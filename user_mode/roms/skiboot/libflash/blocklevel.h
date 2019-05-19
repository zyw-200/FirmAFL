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
#ifndef __LIBFLASH_BLOCKLEVEL_H
#define __LIBFLASH_BLOCKLEVEL_H

#include <stdint.h>
#include <stdbool.h>

struct bl_prot_range {
	uint32_t start;
	uint32_t len;
};

struct blocklevel_range {
	struct bl_prot_range *prot;
	int n_prot;
	int total_prot;
};

enum blocklevel_flags {
	WRITE_NEED_ERASE = 1,
};

/*
 * libffs may be used with different backends, all should provide these for
 * libflash to get the information it needs
 */
struct blocklevel_device {
	void *priv;
	int (*reacquire)(struct blocklevel_device *bl);
	int (*release)(struct blocklevel_device *bl);
	int (*read)(struct blocklevel_device *bl, uint32_t pos, void *buf, uint32_t len);
	int (*write)(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len);
	int (*erase)(struct blocklevel_device *bl, uint32_t pos, uint32_t len);
	int (*get_info)(struct blocklevel_device *bl, const char **name, uint32_t *total_size,
			uint32_t *erase_granule);

	/*
	 * Keep the erase mask so that blocklevel_erase() can do sanity checking
	 */
	uint32_t erase_mask;
	bool keep_alive;
	enum blocklevel_flags flags;

	struct blocklevel_range ecc_prot;
};

int blocklevel_read(struct blocklevel_device *bl, uint32_t pos, void *buf, uint32_t len);
int blocklevel_write(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len);
int blocklevel_erase(struct blocklevel_device *bl, uint32_t pos, uint32_t len);
int blocklevel_get_info(struct blocklevel_device *bl, const char **name, uint32_t *total_size,
		uint32_t *erase_granule);

/* Convienience functions */
int blocklevel_smart_write(struct blocklevel_device *bl, uint32_t pos, const void *buf, uint32_t len);

/* Implemented in software at this level */
int blocklevel_ecc_protect(struct blocklevel_device *bl, uint32_t start, uint32_t len);

#endif /* __LIBFLASH_BLOCKLEVEL_H */
