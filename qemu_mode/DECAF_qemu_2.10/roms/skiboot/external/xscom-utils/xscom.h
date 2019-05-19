/* Copyright 2014-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>

extern int xscom_read(uint32_t chip_id, uint64_t addr, uint64_t *val);
extern int xscom_write(uint32_t chip_id, uint64_t addr, uint64_t val);

extern int xscom_read_ex(uint32_t ex_target_id, uint64_t addr, uint64_t *val);
extern int xscom_write_ex(uint32_t ex_target_id, uint64_t addr, uint64_t val);

extern void xscom_for_each_chip(void (*cb)(uint32_t chip_id));

extern uint32_t xscom_init(void);

#endif /* __XSCOM_H */
