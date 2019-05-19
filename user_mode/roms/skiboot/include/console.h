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

#ifndef __CONSOLE_H
#define __CONSOLE_H

#include "unistd.h"
#include <lock.h>

/*
 * Our internal console uses the format of BML new-style in-memory
 * console and supports input for setups without a physical console
 * facility or FSP.
 *
 * (This is v3 of the format, the previous one sucked)
 */
struct memcons {
	uint64_t magic;
#define MEMCONS_MAGIC	0x6630696567726173LL
	uint64_t obuf_phys;
	uint64_t ibuf_phys;
	uint32_t obuf_size;
	uint32_t ibuf_size;
	uint32_t out_pos;
#define MEMCONS_OUT_POS_WRAP	0x80000000u
#define MEMCONS_OUT_POS_MASK	0x00ffffffu
	uint32_t in_prod;
	uint32_t in_cons;
};

extern struct memcons memcons;

#define INMEM_CON_IN_LEN	16
#define INMEM_CON_OUT_LEN	(INMEM_CON_LEN - INMEM_CON_IN_LEN)

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
	size_t (*read)(char *buf, size_t len);
	bool (*poll_read)(void);
	int64_t (*flush)(void);
};

extern struct lock con_lock;

extern bool dummy_console_enabled(void);
extern void force_dummy_console(void);
extern bool flush_console(void);
extern bool __flush_console(bool flush_to_drivers);
extern void set_console(struct con_ops *driver);

extern void console_complete_flush(void);

extern int mambo_read(void);
extern void mambo_write(const char *buf, size_t count);
extern void enable_mambo_console(void);

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count);

extern void clear_console(void);
extern void memcons_add_properties(void);
extern void dummy_console_add_nodes(void);

#endif /* __CONSOLE_H */
