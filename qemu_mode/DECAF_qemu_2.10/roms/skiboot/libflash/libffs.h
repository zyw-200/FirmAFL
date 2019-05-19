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
#ifndef __LIBFFS_H
#define __LIBFFS_H

#include <libflash/libflash.h>
#include <libflash/ffs.h>
#include <libflash/blocklevel.h>

/* FFS handle, opaque */
struct ffs_handle;

/* Error codes:
 *
 * < 0 = flash controller errors
 *   0 = success
 * > 0 = libffs / libflash errors
 */
#define FFS_ERR_BAD_MAGIC	100
#define FFS_ERR_BAD_VERSION	101
#define FFS_ERR_BAD_CKSUM	102
#define FFS_ERR_PART_NOT_FOUND	103
#define FFS_ERR_BAD_ECC		104

/* Init */

int ffs_init(uint32_t offset, uint32_t max_size, struct blocklevel_device *bl,
		struct ffs_handle **ffs, bool mark_ecc);

/*
 * Initialise a new ffs_handle to the "OTHER SIDE".
 * Reuses the underlying blocklevel_device.
 */
int ffs_next_side(struct ffs_handle *ffs, struct ffs_handle **new_ffs,
		bool mark_ecc);

/*
 * There are quite a few ways one might consider two ffs_handles to be the
 * same. For the purposes of this function we are trying to detect a fairly
 * specific scenario:
 * Consecutive calls to ffs_next_side() may succeed but have gone circular.
 * It is possible that the OTHER_SIDE partition in one TOC actually points
 * back to the TOC of the first ffs_handle.
 * This function compares for this case, therefore the requirements are
 * simple, the underlying blocklevel_devices must be the same along with
 * the toc_offset and the max_size.
 */
bool ffs_equal(struct ffs_handle *one, struct ffs_handle *two);

void ffs_close(struct ffs_handle *ffs);

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx);

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size, bool *ecc);

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size);

#endif /* __LIBFFS_H */
