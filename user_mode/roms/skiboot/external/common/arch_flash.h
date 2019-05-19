/* Copyright 2015 IBM Corp.
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

#ifndef __EXTERNAL_ARCH_FLASH_H
#define __EXTERNAL_ARCH_FLASH_H

#include <getopt.h>
#include <libflash/blocklevel.h>

enum bmc_access {
	PNOR_DIRECT,
	PNOR_MTD,
	BMC_DIRECT,
	BMC_MTD,
	ACCESS_INVAL
};

int arch_flash_init(struct blocklevel_device **bl, const char *file,
		bool keep_alive);

void arch_flash_close(struct blocklevel_device *bl, const char *file);

/* Low level functions that an architecture may support */

/*
 * If called BEFORE init, then this dictates how the flash will be
 * accessed.
 * If called AFTER init, then this returns how the flash is being accessed.
 */
enum bmc_access arch_flash_bmc(struct blocklevel_device *bl,
		enum bmc_access access);

int arch_flash_erase_chip(struct blocklevel_device *bl);
int arch_flash_4b_mode(struct blocklevel_device *bl, int set_4b);
int arch_flash_set_wrprotect(struct blocklevel_device *bl, int set);

#endif /* __EXTERNAL_ARCH_FLASH_H */
