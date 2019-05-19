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

#include <device.h>
#include "spira.h"
#include <cpu.h>
#include <vpd.h>
#include <ccan/str/str.h>
#include <interrupts.h>

#include "hdata.h"

static struct dt_node *fsp_create_node(const void *spss, int i,
				       struct dt_node *parent)
{
	const struct spss_sp_impl *sp_impl;
	struct dt_node *node;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!CHECK_SPPTR(sp_impl)) {
		prerror("FSP #%d: SPSS/SP_Implementation not found !\n", i);
		return NULL;
	}

	prlog(PR_INFO, "FSP #%d: FSP HW version %d, SW version %d,"
	      " chip DD%d.%d\n", i,
	      be16_to_cpu(sp_impl->hw_version),
	      be16_to_cpu(sp_impl->sw_version),
	      sp_impl->chip_version >> 4, sp_impl->chip_version & 0xf);
	mask = SPSS_SP_IMPL_FLAGS_INSTALLED | SPSS_SP_IMPL_FLAGS_FUNCTIONAL;
	if ((be16_to_cpu(sp_impl->func_flags) & mask) != mask) {
		prerror("FSP #%d: FSP not installed or not functional\n", i);
		return NULL;
	}

	node = dt_new_addr(parent, "fsp", i);
	assert(node);
	dt_add_property_cells(node, "reg", i);

	if (be16_to_cpu(sp_impl->hw_version) == 1) {
		dt_add_property_strings(node, "compatible", "ibm,fsp",
				"ibm,fsp1");
		/* Offset into the FSP MMIO space where the mailbox
		 * registers are */
		/* seen in the FSP1 spec */
		dt_add_property_cells(node, "reg-offset", 0xb0016000);
	} else if (be16_to_cpu(sp_impl->hw_version) == 2) {
		dt_add_property_strings(node, "compatible", "ibm,fsp",
				"ibm,fsp2");
		dt_add_property_cells(node, "reg-offset", 0xb0011000);
	}
	dt_add_property_cells(node, "hw-version", be16_to_cpu(sp_impl->hw_version));
	dt_add_property_cells(node, "sw-version", be16_to_cpu(sp_impl->sw_version));

	if (be16_to_cpu(sp_impl->func_flags) & SPSS_SP_IMPL_FLAGS_PRIMARY)
		dt_add_property(node, "primary", NULL, 0);

	return node;
}

static uint32_t fsp_create_link(const struct spss_iopath *iopath, int index,
				int fsp_index)
{
	struct dt_node *node;
	const char *ststr;
	bool current = false;
	bool working = false;
	uint32_t chip_id;

	switch(be16_to_cpu(iopath->psi.link_status)) {
	case SPSS_IO_PATH_PSI_LINK_BAD_FRU:
		ststr = "Broken";
		break;
	case SPSS_IO_PATH_PSI_LINK_CURRENT:
		ststr = "Active";
		current = working = true;
		break;
	case SPSS_IO_PATH_PSI_LINK_BACKUP:
		ststr = "Backup";
		working = true;
		break;
	default:
		ststr = "Unknown";
	}
	prlog(PR_DEBUG, "FSP #%d: IO PATH %d is %s PSI Link, GXHB at %llx\n",
	      fsp_index, index, ststr, (long long)be64_to_cpu(iopath->psi.gxhb_base));

	chip_id = pcid_to_chip_id(be32_to_cpu(iopath->psi.proc_chip_id));
	node = dt_find_compatible_node_on_chip(dt_root, NULL, "ibm,psihb-x",
					       chip_id);
	if (!node) {
		prerror("FSP #%d: Can't find psihb node for link %d\n",
			fsp_index, index);
	} else {
		if (current)
			dt_add_property(node, "boot-link", NULL, 0);
		dt_add_property_strings(node, "status", working ? "ok" : "bad");
	}

	return chip_id;
}

static void fsp_create_links(const void *spss, int index,
			     struct dt_node *fsp_node)
{
	uint32_t *links = NULL;
	unsigned int i, lp, lcount = 0;
	int count;

	count = HDIF_get_iarray_size(spss, SPSS_IDATA_SP_IOPATH);
	if (count < 0) {
		prerror("FSP #%d: Can't find IO PATH array size !\n", index);
		return;
	}
	prlog(PR_DEBUG, "FSP #%d: Found %d IO PATH\n", index, count);

	/* Iterate all links */
	for (i = 0; i < count; i++) {
		const struct spss_iopath *iopath;
		unsigned int iopath_sz;
		uint32_t chip;

		iopath = HDIF_get_iarray_item(spss, SPSS_IDATA_SP_IOPATH,
					      i, &iopath_sz);
		if (!CHECK_SPPTR(iopath)) {
			prerror("FSP #%d: Can't find IO PATH %d\n", index, i);
			break;
		}
		if (be16_to_cpu(iopath->iopath_type) != SPSS_IOPATH_TYPE_PSI) {
			prerror("FSP #%d: Unsupported IO PATH %d type 0x%04x\n",
				index, i, iopath->iopath_type);
			continue;
		}

		chip = fsp_create_link(iopath, i, index);
		lp = lcount++;
		links = realloc(links, 4 * lcount);
		links[lp] = chip;
	}
	if (links)
		dt_add_property(fsp_node, "ibm,psi-links", links, lcount * 4);

	free(links);
}

void fsp_parse(void)
{
	const void *base_spss, *spss;
	struct dt_node *fsp_root, *fsp_node;
	int i;

	/*
	 * Note on DT representation of the PSI links and FSPs:
	 *
	 * We create a XSCOM node for each PSI host bridge(one per chip),
	 *
	 * This is done in spira.c
	 *
	 * We do not create the /psi MMIO variant at this stage, it will
	 * be added by the psi driver in skiboot.
	 *
	 * We do not put the FSP(s) as children of these. Instead, we create
	 * a top-level /fsps node with the FSPs as children.
	 *
	 * Each FSP then has a "links" property which is an array of chip IDs
	 */

	/* Find SPSS in SPIRA */
	base_spss = get_hdif(&spira.ntuples.sp_subsys, SPSS_HDIF_SIG);
	if (!base_spss) {
		prlog(PR_WARNING, "FSP: No SPSS in SPIRA !\n");
		return;
	}

	fsp_root = dt_new(dt_root, "fsps");
	assert(fsp_root);
	dt_add_property_cells(fsp_root, "#address-cells", 1);
	dt_add_property_cells(fsp_root, "#size-cells", 0);

	/* Iterate FSPs in SPIRA */
	for_each_ntuple_idx(&spira.ntuples.sp_subsys, spss, i, SPSS_HDIF_SIG) {
		fsp_node = fsp_create_node(spss, i, fsp_root);
		if (fsp_node)
			fsp_create_links(spss, i, fsp_node);
	}
}

