/* Copyright 2013-2015 IBM Corp.
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
#include <string.h>

/* Use these before we override definitions below. */
static void *real_malloc(size_t size)
{
	return malloc(size);
}

static void real_free(void *p)
{
	return free(p);
}

#undef malloc
#undef free

#include <skiboot.h>

#define is_rodata(p) true

#include "../mem_region.c"
#include "../malloc.c"
#include "../device.c"

#include <assert.h>
#include <stdio.h>

void lock(struct lock *l)
{
	assert(!l->lock_val);
	l->lock_val++;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val--;
}

bool lock_held_by_me(struct lock *l)
{
	return l->lock_val;
}


#define TEST_HEAP_ORDER 12
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

int main(void)
{
	struct mem_region *r;
	char *test_heap;

	/* Use malloc for the heap, so valgrind can find issues. */
	test_heap = real_malloc(TEST_HEAP_SIZE);
	skiboot_heap.start = (unsigned long)test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	lock(&mem_region_lock);

	/* empty regions */
	r = mem_region_next(NULL);
	assert(!r);

	r = new_region("test.1", 0x1000, 0x1000, NULL, REGION_RESERVED);
	assert(add_region(r));
	r = new_region("test.2", 0x2000, 0x1000, NULL, REGION_RESERVED);
	assert(add_region(r));
	mem_regions_finalised = true;

	r = mem_region_next(NULL);
	assert(r);
	assert(r->start == 0x2000);
	assert(r->len == 0x1000);
	assert(r->type == REGION_RESERVED);

	r = mem_region_next(r);
	assert(r);
	assert(r->start == 0x1000);
	assert(r->len == 0x1000);
	assert(r->type == REGION_RESERVED);

	r = mem_region_next(r);
	assert(!r);

	unlock(&mem_region_lock);
	real_free(test_heap);

	return 0;
}
