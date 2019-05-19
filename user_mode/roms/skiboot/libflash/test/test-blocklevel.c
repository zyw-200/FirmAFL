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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libflash/blocklevel.h>

#include "../ecc.c"
#include "../blocklevel.c"

#define __unused		__attribute__((unused))

#define ERR(fmt...) fprintf(stderr, fmt)

int main(void)
{
	int i;
	struct blocklevel_device bl_mem = { 0 };
	struct blocklevel_device *bl = &bl_mem;

	if (blocklevel_ecc_protect(bl, 0, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect!\n");
		return 1;
	}

	/* 0x1000 -> 0x3000 should remain unprotected */

	if (blocklevel_ecc_protect(bl, 0x3000, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect(0x3000, 0x1000)\n");
		return 1;
	}

	/* Zero length protection */
	if (!blocklevel_ecc_protect(bl, 0x4000, 0)) {
		ERR("Shouldn't have succeeded blocklevel_ecc_protect(0x4000, 0)\n");
		return 1;
	}

	/* Minimum creatable size */
	if (blocklevel_ecc_protect(bl, 0x4000, BYTES_PER_ECC)) {
		ERR("Failed to blocklevel_ecc_protect(0x4000, BYTES_PER_ECC)\n");
		return 1;
	}

	/* Deal with overlapping protections */
	if (!blocklevel_ecc_protect(bl, 0x100, 0x1000)) {
		ERR("Shouldn't have succeeded blocklevel_ecc_protect(0x100, 0x1000)\n");
		return 1;
	}

	/* Deal with protections greater than max size */
	if (!blocklevel_ecc_protect(bl, 0, 0xFFFFFFFF)) {
		ERR("Failed to blocklevel_ecc_protect(0, 0xFFFFFFFF)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 1) != 1) {
		ERR("Invaid result for ecc_protected(0, 1)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 0x1000) != 1) {
		ERR("Invalid result for ecc_protected(0, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x100, 0x100) != 1) {
		ERR("Invalid result for ecc_protected(0x0100, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0) != 0) {
		ERR("Invalid result for ecc_protected(0x1000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x1000) != 0) {
		ERR("Invalid result for ecc_protected(0x1000, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x100) != 0) {
		ERR("Invalid result for ecc_protected(0x1000, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x2000, 0) != 0) {
		ERR("Invalid result for ecc_protected(0x2000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4000, 1) != 1) {
		ERR("Invalid result for ecc_protected(0x4000, 1)\n");
		return 1;
	}

	/* Check for asking for a region with mixed protection */
	if (ecc_protected(bl, 0x100, 0x2000) != -1) {
		ERR("Invalid result for ecc_protected(0x100, 0x2000)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x5000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5100, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5100, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5200, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x5120, 0x10) != 1) {
		ERR("Invalid result for ecc_protected(0x5120, 0x10)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x4900, 0x100)) {
		ERR("Failed to blocklevel_ecc_protected(0x4900, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4920, 0x10) != 1) {
		ERR("Invalid result for ecc_protected(0x4920, 0x10)\n");
		return 1;
	}

	if (!blocklevel_ecc_protect(bl, 0x5290, 0x10)) {
		ERR("Shouldn't have been able to blocklevel_ecc_protect(0x5290, 0x10)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x6000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x6200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6200, 0x100)\n");
		return 1;
	}
	/*This addition should cause this one to merge the other two together*/
	if (blocklevel_ecc_protect(bl, 0x6100, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6100, 0x100)\n");
		return 1;
	}

	/* Check that the region merging works */
	for (i = 0; i < bl->ecc_prot.n_prot - 1; i++) {
		if (bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len == bl->ecc_prot.prot[i + 1].start ||
			  bl->ecc_prot.prot[i + 1].start + bl->ecc_prot.prot[i + 1].len == bl->ecc_prot.prot[i].start) {
			ERR("Problem with protection range merge code, region starting at 0x%08x for 0x%08x appears "
				"to touch region 0x%08x for 0x%08x\n", bl->ecc_prot.prot[i].start, bl->ecc_prot.prot[i].len,
				bl->ecc_prot.prot[i + 1].start, bl->ecc_prot.prot[i + 1].len);
			return 1;
		}
	}


	return 0;
}
