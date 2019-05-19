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
#include <device.h>
#include <console.h>
#include <opal.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <ast.h>

#include "astbmc.h"

int pnor_init(void)
{
	struct spi_flash_ctrl *pnor_ctrl;
	struct blocklevel_device *bl = NULL;
	int rc;

	/* Open controller and flash. If the LPC->AHB doesn't point to
	 * the PNOR flash base we assume we're booting from BMC system
	 * memory (or some other place setup by the BMC to support LPC
	 * FW reads & writes). */
	if (ast_is_ahb_lpc_pnor())
		rc = ast_sf_open(AST_SF_TYPE_PNOR, &pnor_ctrl);
	else {
		printf("PLAT: Memboot detected\n");
		rc = ast_sf_open(AST_SF_TYPE_MEM, &pnor_ctrl);
	}
	if (rc) {
		prerror("PLAT: Failed to open PNOR flash controller\n");
		goto fail;
	}

	rc = flash_init(pnor_ctrl, &bl, NULL);
	if (rc) {
		prerror("PLAT: Failed to open init PNOR driver\n");
		goto fail;
	}

	rc = flash_register(bl, true);
	if (!rc)
		return 0;

 fail:
	if (bl)
		flash_exit(bl);
	if (pnor_ctrl)
		ast_sf_close(pnor_ctrl);

	return rc;
}
