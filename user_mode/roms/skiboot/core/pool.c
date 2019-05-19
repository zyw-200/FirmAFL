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

/* This file provides some functions to manage a pool of pre-allocated
 * objects. It also provides a method to reserve a pre-defined number
 * of objects for higher priorty requests. The allocations follow the
 * following rules:
 *
 * 1. An allocation will succeed at any priority if there is more than
 *    the reserved number of objects free.
 * 2. Only high priority allocations will succeed when there are less
 *    than the reserved number of objects free.
 * 3. When an allocation is freed it is always added to the high priority
 *    pool if there are less than the reserved number of allocations
 *    available.
 */

#include <pool.h>
#include <string.h>
#include <stdlib.h>
#include <ccan/list/list.h>

void* pool_get(struct pool *pool, enum pool_priority priority)
{
	void *obj;

	if (!pool->free_count ||
	    ((pool->free_count <= pool->reserved) && priority == POOL_NORMAL))
		return NULL;

	pool->free_count--;
	obj = (void *) list_pop_(&pool->free_list, 0);
	assert(obj);
	memset(obj, 0, pool->obj_size);
	return obj;
}

void pool_free_object(struct pool *pool, void *obj)
{
	pool->free_count++;
	list_add_tail(&pool->free_list,
		      (struct list_node *) (obj));
}

int pool_init(struct pool *pool, size_t obj_size, int count, int reserved)
{
	int i;

	if (obj_size < sizeof(struct list_node))
		obj_size = sizeof(struct list_node);

	assert(count >= reserved);
	pool->buf = malloc(obj_size*count);
	if (!pool->buf)
		return -1;

	pool->obj_size = obj_size;
	pool->free_count = count;
	pool->reserved = reserved;
	list_head_init(&pool->free_list);

	for(i = 0; i < count; i++)
		list_add_tail(&pool->free_list,
			      (struct list_node *) (pool->buf + obj_size*i));

	return 0;
}
