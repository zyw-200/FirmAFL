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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "xscom.h"

#define DBG(fmt...)	do { if (verbose) printf(fmt); } while(0)
#define ERR(fmt...)	do { fprintf(stderr, fmt); } while(0)

#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))


#define OCB_PIB_OCBCSR0_0x0006B011	0x0006B011
#define OCB_PIB_OCBCSR0_ANDx0006B012	0x0006B012
#define OCB_PIB_OCBCSR0_ORx0006B013	0x0006B013
#define   OCB_STREAM_MODE			PPC_BIT(4)
#define   OCB_STREAM_TYPE			PPC_BIT(5)
#define OCB_PIB_OCBAR0_0x0006B010	0x0006B010
#define OCB_PIB_OCBDR0_0x0006B015	0x0006B015

int sram_read(uint32_t chip_id, int chan, uint32_t addr, uint64_t *val)
{
	uint32_t coff = chan * 0x20;
	uint64_t sdat;
	int rc;

	/* Read for debug purposes */
	rc = xscom_read(chip_id, OCB_PIB_OCBCSR0_0x0006B011 + coff, &sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBCSR0_0x0006B011 read error %d\n", rc);
		return -1;
	}

	/* Create an AND mask to clear bit 4 and 5 and poke the AND register */
	sdat = ~(OCB_STREAM_MODE | OCB_STREAM_TYPE);
	rc = xscom_write(chip_id, OCB_PIB_OCBCSR0_ANDx0006B012 + coff, sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBCSR0_ANDx0006B012 write error %d\n", rc);
		return -1;
	}

	sdat = ((uint64_t)addr) << 32;
	rc = xscom_write(chip_id, OCB_PIB_OCBAR0_0x0006B010 + coff, sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBAR0_0x0006B010 write error %d\n", rc);
		return -1;
	}

	rc = xscom_read(chip_id, OCB_PIB_OCBDR0_0x0006B015 + coff, val);
	if (rc) {
		ERR("xscom OCB_PIB_OCBAR0_0x0006B010 read error %d\n", rc);
		return -1;
	}
	return 0;
}

int sram_write(uint32_t chip_id, int chan, uint32_t addr, uint64_t val)
{
	uint32_t coff = chan * 0x20;
	uint64_t sdat;
	int rc;

#if 0
	if (dummy) {
		printf("[dummy] write chip %d OCC sram 0x%08x = %016lx\n",
		       chip_id, addr, val);
		return 0;
	}
#endif

	/* Read for debug purposes */
	rc = xscom_read(chip_id, OCB_PIB_OCBCSR0_0x0006B011 + coff, &sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBCSR0_0x0006B011 read error %d\n", rc);
		return -1;
	}

	/* Create an AND mask to clear bit 4 and 5 and poke the AND register */
	sdat = ~(OCB_STREAM_MODE | OCB_STREAM_TYPE);
	rc = xscom_write(chip_id, OCB_PIB_OCBCSR0_ANDx0006B012 + coff, sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBCSR0_ANDx0006B012 write error %d\n", rc);
		return -1;
	}

	sdat = ((uint64_t)addr) << 32;
	rc = xscom_write(chip_id, OCB_PIB_OCBAR0_0x0006B010 + coff, sdat);
	if (rc) {
		ERR("xscom OCB_PIB_OCBAR0_0x0006B010 write error %d\n", rc);
		return -1;
	}

	rc = xscom_write(chip_id, OCB_PIB_OCBDR0_0x0006B015 + coff, val);
	if (rc) {
		ERR("xscom OCB_PIB_OCBAR0_0x0006B010 write error %d\n", rc);
		return -1;
	}
	return 0;
}
