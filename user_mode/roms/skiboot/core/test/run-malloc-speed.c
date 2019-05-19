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

#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)
/* Don't include this, it's PPC-specific */
#define __CPU_H
static unsigned int cpu_max_pir = 1;
struct cpu_thread {
	unsigned int			chip_id;
};

#include <stdlib.h>

/* Use these before we undefine them below. */
static inline void *real_malloc(size_t size)
{
	return malloc(size);
}

static inline void real_free(void *p)
{
	return free(p);
}

#include <skiboot.h>

/* We need mem_region to accept __location__ */
#define is_rodata(p) true
#include "../malloc.c"
#include "../mem_region.c"
#include "../device.c"

#undef malloc
#undef free
#undef realloc

#include <assert.h>
#include <stdio.h>

char __rodata_start[1], __rodata_end[1];
struct dt_node *dt_root;

void lock(struct lock *l)
{
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

bool lock_held_by_me(struct lock *l)
{
	return l->lock_val;
}

#define TEST_HEAP_ORDER 27
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

#define NUM_ALLOCS 4096

int main(void)
{
	uint64_t i, len;
	void **p = real_malloc(sizeof(void*)*NUM_ALLOCS);

	assert(p);

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)real_malloc(skiboot_heap.len);

	len = skiboot_heap.len / NUM_ALLOCS - sizeof(struct alloc_hdr);
	for (i = 0; i < NUM_ALLOCS; i++) {
		p[i] = __malloc(len, __location__);
		assert(p[i] > region_start(&skiboot_heap));
		assert(p[i] + len <= region_start(&skiboot_heap)
		       + skiboot_heap.len);
	}
	assert(mem_check(&skiboot_heap));
	assert(skiboot_heap.free_list_lock.lock_val == 0);
	free(region_start(&skiboot_heap));
	real_free(p);
	return 0;
}
