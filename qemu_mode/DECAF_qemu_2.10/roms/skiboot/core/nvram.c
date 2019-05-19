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

#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <lock.h>
#include <device.h>
#include <platform.h>
#include <nvram-format.h>

static void *nvram_image;
static uint32_t nvram_size;
static bool nvram_ready;

static int64_t opal_read_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;
	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;

	memcpy((void *)buffer, nvram_image + offset, size);
	return OPAL_SUCCESS;
}
opal_call(OPAL_READ_NVRAM, opal_read_nvram, 3);

static int64_t opal_write_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;
	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;
	memcpy(nvram_image + offset, (void *)buffer, size);
	if (platform.nvram_write)
		platform.nvram_write(offset, nvram_image + offset, size);
	return OPAL_SUCCESS;
}
opal_call(OPAL_WRITE_NVRAM, opal_write_nvram, 3);

void nvram_read_complete(bool success)
{
	struct dt_node *np;

	/* Read not successful, error out and free the buffer */
	if (!success) {
		free(nvram_image);
		nvram_size = 0;
		return;
	}

	/* Check and maybe format nvram */
	if (nvram_check(nvram_image, nvram_size)) {
		if (nvram_format(nvram_image, nvram_size))
			prerror("NVRAM: Failed to format NVRAM!\n");

		/* Write the whole thing back */
		if (platform.nvram_write)
			platform.nvram_write(0, nvram_image, nvram_size);
	}

	/* Add nvram node */
	np = dt_new(opal_node, "nvram");
	dt_add_property_cells(np, "#bytes", nvram_size);
	dt_add_property_string(np, "compatible", "ibm,opal-nvram");

	/* Mark ready */
	nvram_ready = true;
}

void nvram_init(void)
{
	int rc;

	if (!platform.nvram_info)
		return;
	rc = platform.nvram_info(&nvram_size);
	if (rc) {
		prerror("NVRAM: Error %d retrieving nvram info\n", rc);
		return;
	}
	printf("NVRAM: Size is %d KB\n", nvram_size >> 10);
	if (nvram_size > 0x100000) {
		printf("NVRAM: Cropping to 1MB !\n");
		nvram_size = 0x100000;
	}

	/*
	 * We allocate the nvram image with 4k alignment to make the
	 * FSP backend job's easier
	 */
	nvram_image = memalign(0x1000, nvram_size);
	if (!nvram_image) {
		prerror("NVRAM: Failed to allocate nvram image\n");
		nvram_size = 0;
		return;
	}

	/* Read it in */
	rc = platform.nvram_start_read(nvram_image, 0, nvram_size);
	if (rc) {
		prerror("NVRAM: Failed to read NVRAM from FSP !\n");
		nvram_size = 0;
		free(nvram_image);
		return;
	}

	/*
	 * We'll get called back later (or recursively from
	 * nvram_start_read) in nvram_read_complete()
	 */
}
