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
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <hostservices.h>

#define PBA_BAR0	0x2013f00
#define PBA_BARMASK0	0x2013f04

static bool read_pba_bar(struct proc_chip *chip, unsigned int bar_no,
			 uint64_t *base, uint64_t *size)
{
	uint64_t bar, mask;
	int rc;

	rc = xscom_read(chip->id, PBA_BAR0 + bar_no, &bar);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	rc = xscom_read(chip->id, PBA_BARMASK0 + bar_no, &mask);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR MASK%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	prlog(PR_DEBUG, "  PBA BAR%d : 0x%016llx\n", bar_no, bar);
	prlog(PR_DEBUG, "  PBA MASK%d: 0x%016llx\n", bar_no, mask);

	*base = bar & 0x0ffffffffffffffful;
	*size = (mask | 0xfffff) + 1;

	return (*base) != 0;
}

static void homer_init_chip(struct proc_chip *chip)
{
	uint64_t hbase = 0, hsize = 0;
	uint64_t sbase, ssize, obase, osize;

	/*
	 * PBA BARs assigned by HB:
	 *
	 *   0 : Entire HOMER
	 *   1 : OCC to Centaur path (we don't care)
	 *   2 : SLW image
	 *   3 : OCC Common area
	 *
	 * We need to reserve the memory covered by BAR 0 and BAR 3, however
	 * on earlier HBs, BAR0 isn't set so we need BAR 2 instead in that
	 * case to cover SLW (OCC not running).
	 */
	if (read_pba_bar(chip, 0, &hbase, &hsize)) {
		prlog(PR_DEBUG, "  HOMER Image at 0x%llx size %lldMB\n",
		      hbase, hsize / 0x100000);

		if (!mem_range_is_reserved(hbase, hsize)) {
			prlog(PR_WARNING,
				"HOMER image is not reserved! Reserving\n");
			mem_reserve_hw("ibm,homer-image", hbase, hsize);
		}

		chip->homer_base = hbase;
		chip->homer_size = hsize;
	}

	/*
	 * We always read the SLW BAR since we need to grab info about the
	 * SLW image in the struct proc_chip for use by the slw.c code
	 */
	if (read_pba_bar(chip, 2, &sbase, &ssize)) {
		prlog(PR_DEBUG, "  SLW Image at 0x%llx size %lldMB\n",
		      sbase, ssize / 0x100000);

		/*
		 * Only reserve it if we have no homer image or if it
		 * doesn't fit in it (only check the base).
		 */
		if ((sbase < hbase || sbase > (hbase + hsize) ||
				(hbase == 0 && sbase > 0)) &&
				!mem_range_is_reserved(sbase, ssize)) {
			prlog(PR_WARNING,
				"SLW image is not reserved! Reserving\n");
			mem_reserve_hw("ibm,slw-image", sbase, ssize);
		}

		chip->slw_base = sbase;
		chip->slw_bar_size = ssize;
		chip->slw_image_size = ssize; /* will be adjusted later */
	}

	if (read_pba_bar(chip, 3, &obase, &osize)) {
		prlog(PR_DEBUG, "  OCC Common Area at 0x%llx size %lldMB\n",
		      obase, osize / 0x100000);
		chip->occ_common_base = obase;
		chip->occ_common_size = osize;
	}
}

void homer_init(void)
{
	struct proc_chip *chip;

	if (proc_gen != proc_gen_p8 || chip_quirk(QUIRK_NO_PBA))
		return;

	/*
	 * XXX This is temporary, on P8 we look for any configured
	 * SLW/OCC BAR and reserve the memory. Eventually, this will be
	 * done via HostBoot using the device-tree "reserved-ranges"
	 * or we'll load the SLW & OCC images ourselves using Host Services.
	 */
	for_each_chip(chip) {
		prlog(PR_DEBUG, "HOMER: Init chip %d\n", chip->id);
		homer_init_chip(chip);
	}

	/*
	 * Check is PBA BARs are already loaded with HOMER and
	 * skip host services.
	 */

	chip = next_chip(NULL);
	if (chip->homer_base && chip->occ_common_base) {
		/* Reserve OCC common area from BAR */
		if (!mem_range_is_reserved(chip->occ_common_base,
					chip->occ_common_size)) {
			prlog(PR_WARNING,
				"OCC common area is not reserved! Reserving\n");
			mem_reserve_hw("ibm,occ-common-area",
						chip->occ_common_base,
						chip->occ_common_size);
		}
	} else {
		/* Allocate memory for HOMER and OCC common area */
		host_services_occ_base_setup();
	}
}

