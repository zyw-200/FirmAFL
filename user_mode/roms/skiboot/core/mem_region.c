/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <skiboot.h>
#include <mem-map.h>
#include <libfdt_env.h>
#include <lock.h>
#include <device.h>
#include <cpu.h>
#include <affinity.h>
#include <types.h>
#include <mem_region.h>
#include <mem_region-malloc.h>

int64_t mem_dump_free(void);
void mem_dump_allocs(void);

/* Memory poisoning on free (if POISON_MEM_REGION set to 1) */
#define POISON_MEM_REGION	0
#define POISON_MEM_REGION_WITH	0x99
#define POISON_MEM_REGION_LIMIT 1*1024*1024*1024

/* Locking: The mem_region_lock protects the regions list from concurrent
 * updates. Additions to, or removals from, the region list must be done
 * with this lock held. This is typically done when we're establishing
 * the memory & reserved regions.
 *
 * Each region has a lock (region->free_list_lock) to protect the free list
 * from concurrent modification. This lock is used when we're allocating
 * memory out of a specific region.
 *
 * If both locks are needed (eg, __local_alloc, where we need to find a region,
 * then allocate from it), the mem_region_lock must be acquired before (and
 * released after) the per-region lock.
 */
struct lock mem_region_lock = LOCK_UNLOCKED;

static struct list_head regions = LIST_HEAD_INIT(regions);

static bool mem_regions_finalised = false;

unsigned long top_of_ram = SKIBOOT_BASE + SKIBOOT_SIZE;

static struct mem_region skiboot_os_reserve = {
	.name		= "ibm,os-reserve",
	.start		= 0,
	.len		= SKIBOOT_BASE,
	.type		= REGION_OS,
};

struct mem_region skiboot_heap = {
	.name		= "ibm,firmware-heap",
	.start		= HEAP_BASE,
	.len		= HEAP_SIZE,
	.type		= REGION_SKIBOOT_HEAP,
};

static struct mem_region skiboot_code_and_text = {
	.name		= "ibm,firmware-code",
	.start		= SKIBOOT_BASE,
	.len		= HEAP_BASE - SKIBOOT_BASE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_after_heap = {
	.name		= "ibm,firmware-data",
	.start		= HEAP_BASE + HEAP_SIZE,
	.len		= SKIBOOT_BASE + SKIBOOT_SIZE - (HEAP_BASE + HEAP_SIZE),
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_cpu_stacks = {
	.name		= "ibm,firmware-stacks",
	.start		= CPU_STACKS_BASE,
	.len		= 0, /* TBA */
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct alloc_hdr {
	bool free : 1;
	bool prev_free : 1;
	unsigned long num_longs : BITS_PER_LONG-2; /* Including header. */
	const char *location;
};

struct free_hdr {
	struct alloc_hdr hdr;
	struct list_node list;
	/* ... unsigned long tailer; */
};

#define ALLOC_HDR_LONGS (sizeof(struct alloc_hdr) / sizeof(long))
#define ALLOC_MIN_LONGS (sizeof(struct free_hdr) / sizeof(long) + 1)

/* Avoid ugly casts. */
static void *region_start(const struct mem_region *region)
{
	return (void *)(unsigned long)region->start;
}

/* Each free block has a tailer, so we can walk backwards. */
static unsigned long *tailer(struct free_hdr *f)
{
	return (unsigned long *)f + f->hdr.num_longs - 1;
}

/* This walks forward to the next hdr (or NULL if at the end). */
static struct alloc_hdr *next_hdr(const struct mem_region *region,
				  const struct alloc_hdr *hdr)
{
	void *next;

	next = ((unsigned long *)hdr + hdr->num_longs);
	if (next >= region_start(region) + region->len)
		next = NULL;
	return next;
}

/* Creates free block covering entire region. */
static void init_allocatable_region(struct mem_region *region)
{
	struct free_hdr *f = region_start(region);
	assert(region->type == REGION_SKIBOOT_HEAP ||
	       region->type == REGION_MEMORY);
	f->hdr.num_longs = region->len / sizeof(long);
	f->hdr.free = true;
	f->hdr.prev_free = false;
	*tailer(f) = f->hdr.num_longs;
	list_head_init(&region->free_list);
	list_add(&region->free_list, &f->list);
}

static void make_free(struct mem_region *region, struct free_hdr *f,
		      const char *location)
{
	struct alloc_hdr *next;
#if POISON_MEM_REGION == 1
	size_t poison_size= (void*)tailer(f) - (void*)(f+1);

	/* We only poison up to a limit, as otherwise boot is kinda slow */
	if (poison_size > POISON_MEM_REGION_LIMIT) {
		poison_size = POISON_MEM_REGION_LIMIT;
	}

	memset(f+1, POISON_MEM_REGION_WITH, poison_size);
#endif
	if (f->hdr.prev_free) {
		struct free_hdr *prev;
		unsigned long *prev_tailer = (unsigned long *)f - 1;

		assert(*prev_tailer);
		prev = (void *)((unsigned long *)f - *prev_tailer);
		assert(prev->hdr.free);
		assert(!prev->hdr.prev_free);

		/* Expand to cover the one we just freed. */
		prev->hdr.num_longs += f->hdr.num_longs;
		f = prev;
	} else {
		f->hdr.free = true;
		f->hdr.location = location;
		list_add(&region->free_list, &f->list);
	}

	/* Fix up tailer. */
	*tailer(f) = f->hdr.num_longs;

	/* If next is free, coalesce it */
	next = next_hdr(region, &f->hdr);
	if (next) {
		next->prev_free = true;
		if (next->free) {
			struct free_hdr *next_free = (void *)next;
			list_del_from(&region->free_list, &next_free->list);
			/* Maximum of one level of recursion */
			make_free(region, next_free, location);
		}
	}
}

/* Can we fit this many longs with this alignment in this free block? */
static bool fits(struct free_hdr *f, size_t longs, size_t align, size_t *offset)
{
	*offset = 0;

	while (f->hdr.num_longs >= *offset + longs) {
		size_t addr;

		addr = (unsigned long)f
			+ (*offset + ALLOC_HDR_LONGS) * sizeof(long);
		if ((addr & (align - 1)) == 0)
			return true;

		/* Don't make tiny chunks! */
		if (*offset == 0)
			*offset = ALLOC_MIN_LONGS;
		else
			(*offset)++;
	}
	return false;
}

static void discard_excess(struct mem_region *region,
			   struct alloc_hdr *hdr, size_t alloc_longs,
			   const char *location)
{
	/* Do we have excess? */
	if (hdr->num_longs > alloc_longs + ALLOC_MIN_LONGS) {
		struct free_hdr *post;

		/* Set up post block. */
		post = (void *)hdr + alloc_longs * sizeof(long);
		post->hdr.num_longs = hdr->num_longs - alloc_longs;
		post->hdr.prev_free = false;

		/* Trim our block. */
		hdr->num_longs = alloc_longs;

		/* This coalesces as required. */
		make_free(region, post, location);
	}
}

static const char *hdr_location(const struct alloc_hdr *hdr)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		return hdr->location;
	return "*CORRUPT*";
}

static void bad_header(const struct mem_region *region,
		       const struct alloc_hdr *hdr,
		       const char *during,
		       const char *location)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		prerror("%p (in %s) %s at %s, previously %s\n",
			hdr-1, region->name, during, location, hdr->location);
	else
		prerror("%p (in %s) %s at %s, previously %p\n",
			hdr-1, region->name, during, location, hdr->location);
	abort();
}

static bool region_is_reservable(struct mem_region *region)
{
	return region->type != REGION_OS;
}

static bool region_is_reserved(struct mem_region *region)
{
	return region->type != REGION_OS && region->type != REGION_MEMORY;
}

void mem_dump_allocs(void)
{
	struct mem_region *region;
	struct alloc_hdr *hdr;

	/* Second pass: populate property data */
	printf("Memory regions:\n");
	list_for_each(&regions, region, list) {
		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;
		printf("  0x%012llx..%012llx : %s\n",
		       (long long)region->start,
		       (long long)(region->start + region->len - 1),
		       region->name);
		if (region->free_list.n.next == NULL) {
			printf("    no allocs\n");
			continue;
		}
		for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
			if (hdr->free)
				continue;
			printf("    0x%.8lx %s\n", hdr->num_longs * sizeof(long),
			       hdr_location(hdr));
		}
	}
}

int64_t mem_dump_free(void)
{
	struct mem_region *region;
	struct alloc_hdr *hdr;
	int64_t total_free;
	int64_t region_free;

	total_free = 0;

	printf("Free space in HEAP memory regions:\n");
	list_for_each(&regions, region, list) {
		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;
		region_free = 0;

		if (region->free_list.n.next == NULL) {
			continue;
		}
		for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
			if (!hdr->free)
				continue;

			region_free+= hdr->num_longs * sizeof(long);
		}
		printf("Region %s free: %"PRIx64"\n",
		       region->name, region_free);
		total_free += region_free;
	}

	printf("Total free: %"PRIu64"\n", total_free);

	return total_free;
}

static void *__mem_alloc(struct mem_region *region, size_t size, size_t align,
			 const char *location)
{
	size_t alloc_longs, offset;
	struct free_hdr *f;
	struct alloc_hdr *next;

	/* Align must be power of 2. */
	assert(!((align - 1) & align));

	/* This should be a constant. */
	assert(is_rodata(location));

	/* Unallocatable region? */
	if (!(region->type == REGION_SKIBOOT_HEAP ||
	      region->type == REGION_MEMORY))
		return NULL;

	/* First allocation? */
	if (region->free_list.n.next == NULL)
		init_allocatable_region(region);

	/* Don't do screwy sizes. */
	if (size > region->len)
		return NULL;

	/* Don't do tiny alignments, we deal in long increments. */
	if (align < sizeof(long))
		align = sizeof(long);

	/* Convert size to number of longs, too. */
	alloc_longs = (size + sizeof(long)-1) / sizeof(long) + ALLOC_HDR_LONGS;

	/* Can't be too small for when we free it, either. */
	if (alloc_longs < ALLOC_MIN_LONGS)
		alloc_longs = ALLOC_MIN_LONGS;

	/* Walk free list. */
	list_for_each(&region->free_list, f, list) {
		/* We may have to skip some to meet alignment. */
		if (fits(f, alloc_longs, align, &offset))
			goto found;
	}

	return NULL;

found:
	assert(f->hdr.free);
	assert(!f->hdr.prev_free);

	/* This block is no longer free. */
	list_del_from(&region->free_list, &f->list);
	f->hdr.free = false;
	f->hdr.location = location;

	next = next_hdr(region, &f->hdr);
	if (next) {
		assert(next->prev_free);
		next->prev_free = false;
	}

	if (offset != 0) {
		struct free_hdr *pre = f;

		f = (void *)f + offset * sizeof(long);
		assert(f >= pre + 1);

		/* Set up new header. */
		f->hdr.num_longs = pre->hdr.num_longs - offset;
		/* f->hdr.prev_free will be set by make_free below. */
		f->hdr.free = false;
		f->hdr.location = location;

		/* Fix up old header. */
		pre->hdr.num_longs = offset;
		pre->hdr.prev_free = false;

		/* This coalesces as required. */
		make_free(region, pre, location);
	}

	/* We might be too long; put the rest back. */
	discard_excess(region, &f->hdr, alloc_longs, location);

	/* Clear tailer for debugging */
	*tailer(f) = 0;

	/* Their pointer is immediately after header. */
	return &f->hdr + 1;
}

void *mem_alloc(struct mem_region *region, size_t size, size_t align,
		const char *location)
{
	void *r;

	assert(lock_held_by_me(&region->free_list_lock));

	r = __mem_alloc(region, size, align, location);
	if (r)
		return r;

	prerror("mem_alloc(0x%lx, 0x%lx, \"%s\") failed !\n",
		size, align, location);
	mem_dump_allocs();
	return NULL;
}

void mem_free(struct mem_region *region, void *mem, const char *location)
{
	struct alloc_hdr *hdr;

	/* This should be a constant. */
	assert(is_rodata(location));

	assert(lock_held_by_me(&region->free_list_lock));

	/* Freeing NULL is always a noop. */
	if (!mem)
		return;

	/* Your memory is in the region, right? */
	assert(mem >= region_start(region) + sizeof(*hdr));
	assert(mem < region_start(region) + region->len);

	/* Grab header. */
	hdr = mem - sizeof(*hdr);

	if (hdr->free)
		bad_header(region, hdr, "re-freed", location);

	make_free(region, (struct free_hdr *)hdr, location);
}

size_t mem_allocated_size(const void *ptr)
{
	const struct alloc_hdr *hdr = ptr - sizeof(*hdr);
	return hdr->num_longs * sizeof(long) - sizeof(struct alloc_hdr);
}

bool mem_resize(struct mem_region *region, void *mem, size_t len,
		const char *location)
{
	struct alloc_hdr *hdr, *next;
	struct free_hdr *f;

	/* This should be a constant. */
	assert(is_rodata(location));

	assert(lock_held_by_me(&region->free_list_lock));

	/* Get header. */
	hdr = mem - sizeof(*hdr);
	if (hdr->free)
		bad_header(region, hdr, "resize", location);

	/* Round up size to multiple of longs. */
	len = (sizeof(*hdr) + len + sizeof(long) - 1) / sizeof(long);

	/* Can't be too small for when we free it, either. */
	if (len < ALLOC_MIN_LONGS)
		len = ALLOC_MIN_LONGS;

	/* Shrinking is simple. */
	if (len <= hdr->num_longs) {
		hdr->location = location;
		discard_excess(region, hdr, len, location);
		return true;
	}

	/* Check if we can expand. */
	next = next_hdr(region, hdr);
	if (!next || !next->free || hdr->num_longs + next->num_longs < len)
		return false;

	/* OK, it's free and big enough, absorb it. */
	f = (struct free_hdr *)next;
	list_del_from(&region->free_list, &f->list);
	hdr->num_longs += next->num_longs;
	hdr->location = location;

	/* Update next prev_free */
	next = next_hdr(region, &f->hdr);
	if (next) {
		assert(next->prev_free);
		next->prev_free = false;
	}

	/* Clear tailer for debugging */
	*tailer(f) = 0;

	/* Now we might have *too* much. */
	discard_excess(region, hdr, len, location);
	return true;
}

bool mem_check(const struct mem_region *region)
{
	size_t frees = 0;
	struct alloc_hdr *hdr, *prev_free = NULL;
	struct free_hdr *f;

	/* Check it's sanely aligned. */
	if (region->start % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sanely aligned (%llx)\n",
			region->name, (unsigned long long)region->start);
		return false;
	}
	if ((long)region->len % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sane length (%llu)\n",
			region->name, (unsigned long long)region->len);
		return false;
	}

	/* Not ours to play with, or empty?  Don't do anything. */
	if (!(region->type == REGION_MEMORY ||
	      region->type == REGION_SKIBOOT_HEAP) ||
	    region->free_list.n.next == NULL)
		return true;

	/* Walk linearly. */
	for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
		if (hdr->num_longs < ALLOC_MIN_LONGS) {
			prerror("Region '%s' %s %p (%s) size %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
			return false;
		}
		if ((unsigned long)hdr + hdr->num_longs * sizeof(long) >
		    region->start + region->len) {
			prerror("Region '%s' %s %p (%s) oversize %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
			return false;
		}
		if (hdr->free) {
			if (hdr->prev_free || prev_free) {
				prerror("Region '%s' free %p (%s) has prev_free"
					" %p (%s) %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free,
					prev_free ? hdr_location(prev_free)
					: "NULL",
					hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = hdr;
			frees ^= (unsigned long)hdr - region->start;
		} else {
			if (hdr->prev_free != (bool)prev_free) {
				prerror("Region '%s' alloc %p (%s) has"
					" prev_free %p %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free, hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = NULL;
		}
	}

	/* Now walk free list. */
	list_for_each(&region->free_list, f, list)
		frees ^= (unsigned long)f - region->start;

	if (frees) {
		prerror("Region '%s' free list and walk do not match!\n",
			region->name);
		return false;
	}
	return true;
}

static struct mem_region *new_region(const char *name,
				     uint64_t start, uint64_t len,
				     struct dt_node *node,
				     enum mem_region_type type)
{
	struct mem_region *region;

	region = malloc(sizeof(*region));
	if (!region)
		return NULL;

	region->name = name;
	region->start = start;
	region->len = len;
	region->node = node;
	region->type = type;
	region->free_list.n.next = NULL;
	init_lock(&region->free_list_lock);

	return region;
}

/* We always split regions, so we only have to replace one. */
static struct mem_region *split_region(struct mem_region *head,
				       uint64_t split_at,
				       enum mem_region_type type)
{
	struct mem_region *tail;
	uint64_t end = head->start + head->len;

	tail = new_region(head->name, split_at, end - split_at,
			  head->node, type);
	/* Original region becomes head. */
	if (tail)
		head->len -= tail->len;

	return tail;
}

static bool intersects(const struct mem_region *region, uint64_t addr)
{
	return addr > region->start &&
		addr < region->start + region->len;
}

static bool maybe_split(struct mem_region *r, uint64_t split_at)
{
	struct mem_region *tail;

	if (!intersects(r, split_at))
		return true;

	tail = split_region(r, split_at, r->type);
	if (!tail)
		return false;

	/* Tail add is important: we may need to split again! */
	list_add_tail(&regions, &tail->list);
	return true;
}

static bool overlaps(const struct mem_region *r1, const struct mem_region *r2)
{
	return (r1->start + r1->len > r2->start
		&& r1->start < r2->start + r2->len);
}

static struct mem_region *get_overlap(const struct mem_region *region)
{
	struct mem_region *i;

	list_for_each(&regions, i, list) {
		if (overlaps(region, i))
			return i;
	}
	return NULL;
}

static bool add_region(struct mem_region *region)
{
	struct mem_region *r;

	if (mem_regions_finalised) {
		prerror("MEM: add_region(%s@0x%"PRIx64") called after finalise!\n",
				region->name, region->start);
		return false;
	}

	/* First split any regions which intersect. */
	list_for_each(&regions, r, list)
		if (!maybe_split(r, region->start) ||
		    !maybe_split(r, region->start + region->len))
			return false;

	/* Now we have only whole overlaps, if any. */
	while ((r = get_overlap(region)) != NULL) {
		assert(r->start == region->start);
		assert(r->len == region->len);
		list_del_from(&regions, &r->list);
		free(r);
	}

	/* Finally, add in our own region. */
	list_add(&regions, &region->list);
	return true;
}

void mem_reserve_hw(const char *name, uint64_t start, uint64_t len)
{
	struct mem_region *region;
	bool added;

	lock(&mem_region_lock);
	region = new_region(name, start, len, NULL, REGION_HW_RESERVED);
	assert(region);
	added = add_region(region);
	assert(added);
	unlock(&mem_region_lock);
}

static bool matches_chip_id(const __be32 ids[], size_t num, u32 chip_id)
{
	size_t i;

	for (i = 0; i < num; i++)
		if (be32_to_cpu(ids[i]) == chip_id)
			return true;

	return false;
}

void *__local_alloc(unsigned int chip_id, size_t size, size_t align,
		    const char *location)
{
	struct mem_region *region;
	void *p = NULL;
	bool use_local = true;

	lock(&mem_region_lock);

restart:
	list_for_each(&regions, region, list) {
		const struct dt_property *prop;
		const __be32 *ids;

		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;

		/* Don't allocate from normal heap. */
		if (region == &skiboot_heap)
			continue;

		/* First pass, only match node local regions */
		if (use_local) {
			if (!region->node)
				continue;
			prop = dt_find_property(region->node, "ibm,chip-id");
			ids = (const __be32 *)prop->prop;
			if (!matches_chip_id(ids, prop->len/sizeof(u32),
					     chip_id))
				continue;
		}

		/* Second pass, match anything */
		lock(&region->free_list_lock);
		p = mem_alloc(region, size, align, location);
		unlock(&region->free_list_lock);
		if (p)
			break;
	}

	/*
	 * If we can't allocate the memory block from the expected
	 * node, we bail to any one that can accommodate our request.
	 */
	if (!p && use_local) {
		use_local = false;
		goto restart;
	}

	unlock(&mem_region_lock);

	return p;
}

struct mem_region *find_mem_region(const char *name)
{
	struct mem_region *region;

	list_for_each(&regions, region, list) {
		if (streq(region->name, name))
			return region;
	}
	return NULL;
}

bool mem_range_is_reserved(uint64_t start, uint64_t size)
{
	uint64_t end = start + size;
	struct mem_region *region;

	/* We may have the range covered by a number of regions, which could
	 * appear in any order. So, we look for a region that covers the
	 * start address, and bump start up to the end of that region.
	 *
	 * We repeat until we've either bumped past the end of the range,
	 * or we didn't find a matching region.
	 *
	 * This has a worst-case of O(n^2), but n is well bounded by the
	 * small number of reservations.
	 */
	for (;;) {
		bool found = false;

		list_for_each(&regions, region, list) {
			if (!region_is_reserved(region))
				continue;

			/* does this region overlap the start address, and
			 * have a non-zero size? */
			if (region->start <= start &&
					region->start + region->len > start &&
					region->len) {
				start = region->start + region->len;
				found = true;
			}
		}

		/* 'end' is the first byte outside of the range */
		if (start >= end)
			return true;

		if (!found)
			break;
	}

	return false;
}

void adjust_cpu_stacks_alloc(void)
{
	/* CPU stacks start at 0, then when we know max possible PIR,
	 * we adjust, then when we bring all CPUs online we know the
	 * runtime max PIR, so we adjust this a few times during boot.
	 */
	skiboot_cpu_stacks.len = (cpu_max_pir + 1) * STACK_SIZE;
}

static void mem_region_parse_reserved_properties(void)
{
	const struct dt_property *names, *ranges;
	struct mem_region *region;

	prlog(PR_INFO, "MEM: parsing reserved memory from "
			"reserved-names/-ranges properties\n");

	names = dt_find_property(dt_root, "reserved-names");
	ranges = dt_find_property(dt_root, "reserved-ranges");
	if (names && ranges) {
		const uint64_t *range;
		int n, len;

		range = (const void *)ranges->prop;

		for (n = 0; n < names->len; n += len, range += 2) {
			char *name;

			len = strlen(names->prop + n) + 1;
			name = strdup(names->prop + n);

			region = new_region(name,
					dt_get_number(range, 2),
					dt_get_number(range + 1, 2),
					NULL, REGION_HW_RESERVED);
			list_add(&regions, &region->list);
		}
	} else if (names || ranges) {
		prerror("Invalid properties: reserved-names=%p "
				"with reserved-ranges=%p\n",
				names, ranges);
		abort();
	} else {
		return;
	}
}

static bool mem_region_parse_reserved_nodes(const char *path)
{
	struct dt_node *parent, *node;

	parent = dt_find_by_path(dt_root, path);
	if (!parent)
		return false;

	prlog(PR_INFO, "MEM: parsing reserved memory from node %s\n", path);

	dt_for_each_child(parent, node) {
		const struct dt_property *reg;
		struct mem_region *region;

		reg = dt_find_property(node, "reg");
		if (!reg) {
			char *nodepath = dt_get_path(node);
			prerror("node %s has no reg property, ignoring\n",
					nodepath);
			free(nodepath);
			continue;
		}

		region = new_region(strdup(node->name),
				dt_get_number(reg->prop, 2),
				dt_get_number(reg->prop + sizeof(u64), 2),
				node, REGION_HW_RESERVED);
		list_add(&regions, &region->list);
	}

	return true;
}

/* Trawl through device tree, create memory regions from nodes. */
void mem_region_init(void)
{
	struct mem_region *region;
	struct dt_node *i;
	bool rc;

	/* Ensure we have no collision between skiboot core and our heap */
	extern char _end[];
	BUILD_ASSERT(HEAP_BASE >= (uint64_t)_end);

	/*
	 * Add associativity properties outside of the lock
	 * to avoid recursive locking caused by allocations
	 * done by add_chip_dev_associativity()
	 */
	dt_for_each_node(dt_root, i) {
		if (!dt_has_node_property(i, "device_type", "memory"))
			continue;

		/* Add associativity properties */
		add_chip_dev_associativity(i);
	}

	/* Add each memory node. */
	dt_for_each_node(dt_root, i) {
		uint64_t start, len;
		char *rname;
#define NODE_REGION_PREFIX 	"ibm,firmware-allocs-"

		if (!dt_has_node_property(i, "device_type", "memory"))
			continue;
		rname = zalloc(strlen(i->name) + strlen(NODE_REGION_PREFIX) + 1);
		assert(rname);
		strcat(rname, NODE_REGION_PREFIX);
		strcat(rname, i->name);
		start = dt_get_address(i, 0, &len);
		lock(&mem_region_lock);
		region = new_region(rname, start, len, i, REGION_MEMORY);
		if (!region) {
			prerror("MEM: Could not add mem region %s!\n", i->name);
			abort();
		}
		list_add(&regions, &region->list);
		if ((start + len) > top_of_ram)
			top_of_ram = start + len;
		unlock(&mem_region_lock);
	}

	adjust_cpu_stacks_alloc();

	lock(&mem_region_lock);

	/* Now carve out our own reserved areas. */
	if (!add_region(&skiboot_os_reserve) ||
	    !add_region(&skiboot_code_and_text) ||
	    !add_region(&skiboot_heap) ||
	    !add_region(&skiboot_after_heap) ||
	    !add_region(&skiboot_cpu_stacks)) {
		prerror("Out of memory adding skiboot reserved areas\n");
		abort();
	}

	/* Add reserved ranges from the DT */
	rc = mem_region_parse_reserved_nodes("/reserved-memory");
	if (!rc)
		rc = mem_region_parse_reserved_nodes(
				"/ibm,hostboot/reserved-memory");
	if (!rc)
		mem_region_parse_reserved_properties();

	unlock(&mem_region_lock);

}

static uint64_t allocated_length(const struct mem_region *r)
{
	struct free_hdr *f, *last = NULL;

	/* No allocations at all? */
	if (r->free_list.n.next == NULL)
		return 0;

	/* Find last free block. */
	list_for_each(&r->free_list, f, list)
		if (f > last)
			last = f;

	/* No free blocks? */
	if (!last)
		return r->len;

	/* Last free block isn't at end? */
	if (next_hdr(r, &last->hdr))
		return r->len;
	return (unsigned long)last - r->start;
}

/* Separate out allocated sections into their own region. */
void mem_region_release_unused(void)
{
	struct mem_region *r;

	lock(&mem_region_lock);
	assert(!mem_regions_finalised);

	printf("Releasing unused memory:\n");
	list_for_each(&regions, r, list) {
		uint64_t used_len;

		/* If it's not allocatable, ignore it. */
		if (!(r->type == REGION_SKIBOOT_HEAP ||
		      r->type == REGION_MEMORY))
			continue;

		used_len = allocated_length(r);

		printf("    %s: %llu/%llu used\n",
		       r->name, (long long)used_len, (long long)r->len);

		/* We keep the skiboot heap. */
		if (r == &skiboot_heap)
			continue;

		/* Nothing used?  Whole thing is for Linux. */
		if (used_len == 0)
			r->type = REGION_OS;
		/* Partially used?  Split region. */
		else if (used_len != r->len) {
			struct mem_region *for_linux;
			struct free_hdr *last = region_start(r) + used_len;

			/* Remove the final free block. */
			list_del_from(&r->free_list, &last->list);

			for_linux = split_region(r, r->start + used_len,
						 REGION_OS);
			if (!for_linux) {
				prerror("OOM splitting mem node %s for linux\n",
					r->name);
				abort();
			}
			list_add(&regions, &for_linux->list);
		}
	}
	unlock(&mem_region_lock);
}

static void mem_region_add_dt_reserved_node(struct dt_node *parent,
		struct mem_region *region)
{
	char *name, *p;

	/* If a reserved region was established before skiboot, it may be
	 * referenced by a device-tree node with extra data. In that case,
	 * copy the node to /reserved-memory/, unless it's already there.
	 *
	 * We update region->node to the new copy here, as the prd code may
	 * update regions' device-tree nodes, and we want those updates to
	 * apply to the nodes in /reserved-memory/.
	 */
	if (region->type == REGION_HW_RESERVED && region->node) {
		if (region->node->parent != parent)
			region->node = dt_copy(region->node, parent);
		return;
	}

	name = strdup(region->name);
	assert(name);

	/* remove any cell addresses in the region name; we have our own cell
	 * addresses here */
	p = strchr(name, '@');
	if (p)
		*p = '\0';

	region->node = dt_new_addr(parent, name, region->start);
	assert(region->node);
	dt_add_property_u64s(region->node, "reg", region->start, region->len);
	free(name);
}

void mem_region_add_dt_reserved(void)
{
	int names_len, ranges_len, len;
	const struct dt_property *prop;
	struct mem_region *region;
	void *names, *ranges;
	struct dt_node *node;
	uint64_t *range;
	char *name;

	names_len = 0;
	ranges_len = 0;

	/* Finalise the region list, so we know that the regions list won't be
	 * altered after this point. The regions' free lists may change after
	 * we drop the lock, but we don't access those. */
	lock(&mem_region_lock);
	mem_regions_finalised = true;

	/* establish top-level reservation node */
	node = dt_find_by_path(dt_root, "reserved-memory");
	if (!node) {
		node = dt_new(dt_root, "reserved-memory");
		dt_add_property_cells(node, "#address-cells", 2);
		dt_add_property_cells(node, "#size-cells", 2);
		dt_add_property(node, "ranges", NULL, 0);
	}

	/* First pass: calculate length of property data */
	list_for_each(&regions, region, list) {
		if (!region_is_reservable(region))
			continue;
		names_len += strlen(region->name) + 1;
		ranges_len += 2 * sizeof(uint64_t);
	}

	name = names = malloc(names_len);
	range = ranges = malloc(ranges_len);

	printf("Reserved regions:\n");
	/* Second pass: populate property data */
	list_for_each(&regions, region, list) {
		if (!region_is_reservable(region))
			continue;
		len = strlen(region->name) + 1;
		memcpy(name, region->name, len);
		name += len;

		printf("  0x%012llx..%012llx : %s\n",
		       (long long)region->start,
		       (long long)(region->start + region->len - 1),
		       region->name);

		mem_region_add_dt_reserved_node(node, region);

		range[0] = cpu_to_fdt64(region->start);
		range[1] = cpu_to_fdt64(region->len);
		range += 2;
	}
	unlock(&mem_region_lock);


	prop = dt_find_property(dt_root, "reserved-names");
	if (prop)
		dt_del_property(dt_root, (struct dt_property *)prop);

	prop = dt_find_property(dt_root, "reserved-ranges");
	if (prop)
		dt_del_property(dt_root, (struct dt_property *)prop);

	dt_add_property(dt_root, "reserved-names", names, names_len);
	dt_add_property(dt_root, "reserved-ranges", ranges, ranges_len);

	free(names);
	free(ranges);
}

struct mem_region *mem_region_next(struct mem_region *region)
{
	struct list_node *node;

	assert(lock_held_by_me(&mem_region_lock));

	node = region ? &region->list : &regions.n;

	if (node->next == &regions.n)
		return NULL;

	return list_entry(node->next, struct mem_region, list);
}
