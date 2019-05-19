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

#ifndef __LOCK_H
#define __LOCK_H

#include <stdbool.h>

struct lock {
	/* Lock value has bit 63 as lock bit and the PIR of the owner
	 * in the top 32-bit
	 */
	unsigned long lock_val;

	/*
	 * Set to true if lock is involved in the console flush path
	 * in which case taking it will suspend console flushing
	 */
	bool in_con_path;
};

/* Initializer */
#define LOCK_UNLOCKED	{ .lock_val = 0, .in_con_path = 0 }

/* Note vs. libc and locking:
 *
 * The printf() family of
 * functions use stack based t buffers and call into skiboot
 * underlying read() and write() which use a console lock.
 *
 * The underlying FSP console code will thus operate within that
 * console lock.
 *
 * The libc does *NOT* lock stream buffer operations, so don't
 * try to scanf() from the same FILE from two different processors.
 *
 * FSP operations are locked using an FSP lock, so all processors
 * can safely call the FSP API
 *
 * Note about ordering:
 *
 * lock() is a full memory barrier. unlock() is a lwsync
 *
 */

extern bool bust_locks;

static inline void init_lock(struct lock *l)
{
	*l = (struct lock)LOCK_UNLOCKED;
}

extern bool __try_lock(struct lock *l);
extern bool try_lock(struct lock *l);
extern void lock(struct lock *l);
extern void unlock(struct lock *l);

extern bool lock_held_by_me(struct lock *l);

/* The debug output can happen while the FSP lock, so we need some kind
 * of recursive lock support here. I don't want all locks to be recursive
 * though, thus the caller need to explicitly call lock_recursive which
 * returns false if the lock was already held by this cpu. If it returns
 * true, then the caller shall release it when done.
 */
extern bool lock_recursive(struct lock *l);

/* Called after per-cpu data structures are available */
extern void init_locks(void);

#endif /* __LOCK_H */
