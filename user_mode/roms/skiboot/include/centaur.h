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

#ifndef __CENTAUR_H
#define __CENTAUR_H

#include <stdint.h>
#include <lock.h>

#include <ccan/list/list.h>

struct centaur_chip {
	bool			valid;
	bool			online;
	uint8_t			ec_level;
	uint32_t		part_id;
	uint32_t		fsi_master_chip_id;
	uint32_t		fsi_master_port;
	uint32_t		fsi_master_engine;
	uint32_t		scache_disable_count;
	bool			scache_was_enabled;
	uint32_t		error_count;
	struct lock		lock;

	/* Used by hw/p8-i2c.c */
	struct list_head	i2cms;
};

extern int64_t centaur_disable_sensor_cache(uint32_t part_id);
extern int64_t centaur_enable_sensor_cache(uint32_t part_id);

extern int64_t centaur_xscom_read(uint32_t id, uint64_t pcb_addr, uint64_t *val) __warn_unused_result;
extern int64_t centaur_xscom_write(uint32_t id, uint64_t pcb_addr, uint64_t val) __warn_unused_result;
extern void centaur_init(void);

extern struct centaur_chip *get_centaur(uint32_t part_id);

#endif /* __CENTAUR_H */
