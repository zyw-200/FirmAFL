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
#include "spira.h"
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <device.h>
#include <p7ioc.h>
#include <vpd.h>
#include <inttypes.h>

#include "hdata.h"

static void io_add_common(struct dt_node *hn, const struct cechub_io_hub *hub)
{
	dt_add_property_cells(hn, "#address-cells", 2);
	dt_add_property_cells(hn, "#size-cells", 2);
	dt_add_property_cells(hn, "ibm,buid-ext", be32_to_cpu(hub->buid_ext));
	dt_add_property_cells(hn, "ibm,chip-id",
			      pcid_to_chip_id(be32_to_cpu(hub->proc_chip_id)));
	dt_add_property_cells(hn, "ibm,gx-index", be32_to_cpu(hub->gx_index));
	dt_add_property_cells(hn, "revision", be32_to_cpu(hub->ec_level));

	/* Instead of exposing the GX BARs as separate ranges as we *should*
	 * do in an ideal world, we just create a pass-through ranges and
	 * we use separate properties for the BARs.
	 *
	 * This is hackish but will do for now and avoids us having to
	 * do too complex ranges property parsing
	 */
	dt_add_property(hn, "ranges", NULL, 0);
	dt_add_property_cells(hn, "ibm,gx-bar-1",
			      hi32(be64_to_cpu(hub->gx_ctrl_bar1)), lo32(be64_to_cpu(hub->gx_ctrl_bar1)));
	dt_add_property_cells(hn, "ibm,gx-bar-2",
			      hi32(be64_to_cpu(hub->gx_ctrl_bar2)), lo32(be64_to_cpu(hub->gx_ctrl_bar2)));

	/* Add presence detect if valid */
	if (hub->flags & CECHUB_HUB_FLAG_FAB_BR0_PDT)
		dt_add_property_cells(hn, "ibm,br0-presence-detect",
				      hub->fab_br0_pdt);
	if (hub->flags & CECHUB_HUB_FLAG_FAB_BR1_PDT)
		dt_add_property_cells(hn, "ibm,br1-presence-detect",
				      hub->fab_br1_pdt);
}

static bool io_get_lx_info(const void *kwvpd, unsigned int kwvpd_sz,
			   int lx_idx, struct dt_node *hn)
{
	const void *lxr;
	char recname[5];

	/* Find LXRn, where n is the index passed in*/
	strcpy(recname, "LXR0");
	recname[3] += lx_idx;
	lxr = vpd_find(kwvpd, kwvpd_sz, recname, "LX", NULL);
	if (!lxr) {
		/* Not found, try VINI */
		lxr = vpd_find(kwvpd, kwvpd_sz, "VINI",
			       "LX",  NULL);
		if (lxr)
			lx_idx = VPD_LOAD_LXRN_VINI;
	}
	if (!lxr) {
		prlog(PR_DEBUG, "CEC:     LXR%x not found !\n", lx_idx);
		return false;
	}

	prlog(PR_DEBUG, "CEC:     LXRn=%d LXR=%016lx\n", lx_idx,
	      lxr ? *(unsigned long *)lxr : 0);
	prlog(PR_DEBUG, "CEC:     LX Info added to %llx\n", (long long)hn);

	/* Add the LX info */
	if (!dt_has_node_property(hn, "ibm,vpd-lx-info", NULL)) {
		dt_add_property_cells(hn, "ibm,vpd-lx-info",
				      lx_idx,
				      ((uint32_t *)lxr)[0],
				      ((uint32_t *)lxr)[1]);
	}

	return true;
}


static void io_get_loc_code(const void *sp_iohubs, struct dt_node *hn, const char *prop_name)
{
	const struct spira_fru_id *fru_id;
	unsigned int fru_id_sz;
	char loc_code[LOC_CODE_SIZE + 1];
	const char *slca_loc_code;

	/* Find SLCA Index */
	fru_id = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA, &fru_id_sz);
	if (fru_id) {
		memset(loc_code, 0, sizeof(loc_code));

		/* Find LOC Code from SLCA Index */
		slca_loc_code = slca_get_loc_code_index(be16_to_cpu(fru_id->slca_index));
		if (slca_loc_code) {
			strncpy(loc_code, slca_loc_code, LOC_CODE_SIZE);
			if (!dt_has_node_property(hn, prop_name, NULL)) {
				dt_add_property(hn, prop_name, loc_code,
						strlen(loc_code) + 1);
			}
			prlog(PR_DEBUG, "CEC:     %s: %s (SLCA rsrc 0x%x)\n",
			      prop_name, loc_code,
			      be16_to_cpu(fru_id->rsrc_id));
		} else {
			prlog(PR_DEBUG, "CEC:     SLCA Loc not found: "
			      "index %d\n", fru_id->slca_index);
		}
	} else {
		prlog(PR_DEBUG, "CEC:     Hub FRU ID not found...\n");
	}
}

static struct dt_node *io_add_p7ioc(const struct cechub_io_hub *hub,
				    const void *sp_iohubs)
{
	struct dt_node *hn;
	uint64_t reg[2];

	const void *kwvpd;
	unsigned int kwvpd_sz;

	prlog(PR_DEBUG, "    GX#%d BUID_Ext = 0x%x\n",
	      be32_to_cpu(hub->gx_index),
	      be32_to_cpu(hub->buid_ext));
	prlog(PR_DEBUG, "    GX BAR 0 = 0x%016"PRIx64"\n",
	      be64_to_cpu(hub->gx_ctrl_bar0));
	prlog(PR_DEBUG, "    GX BAR 1 = 0x%016"PRIx64"\n",
	      be64_to_cpu(hub->gx_ctrl_bar1));
	prlog(PR_DEBUG, "    GX BAR 2 = 0x%016"PRIx64"\n",
	      be64_to_cpu(hub->gx_ctrl_bar2));
	prlog(PR_DEBUG, "    GX BAR 3 = 0x%016"PRIx64"\n",
	      be64_to_cpu(hub->gx_ctrl_bar3));
	prlog(PR_DEBUG, "    GX BAR 4 = 0x%016"PRIx64"\n",
	      be64_to_cpu(hub->gx_ctrl_bar4));

	/* We only know about memory map 1 */
	if (be32_to_cpu(hub->mem_map_vers) != 1) {
		prerror("P7IOC: Unknown memory map %d\n", be32_to_cpu(hub->mem_map_vers));
		/* We try to continue anyway ... */
	}

	reg[0] = cleanup_addr(be64_to_cpu(hub->gx_ctrl_bar1));
	reg[1] = 0x2000000;

	hn = dt_new_addr(dt_root, "io-hub", reg[0]);
	if (!hn)
		return NULL;

	dt_add_property(hn, "reg", reg, sizeof(reg));
	dt_add_property_strings(hn, "compatible", "ibm,p7ioc", "ibm,ioda-hub");

	kwvpd = HDIF_get_idata(sp_iohubs, CECHUB_ASCII_KEYWORD_VPD, &kwvpd_sz);
	if (kwvpd && kwvpd != sp_iohubs) {
		/*
		 * XX We don't know how to properly find the LXRn
		 * record so for now we'll just try LXR0 and if not
		 * found, we try LXR1
		 */
		if (!io_get_lx_info(kwvpd, kwvpd_sz, 0, hn))
			io_get_lx_info(kwvpd, kwvpd_sz, 1, hn);
	} else {
		prlog(PR_DEBUG, "CEC:     P7IOC Keywords not found.\n");
	}

	io_get_loc_code(sp_iohubs, hn, "ibm,io-base-loc-code");

	return hn;
}

static struct dt_node *io_add_phb3(const struct cechub_io_hub *hub,
				   const struct HDIF_common_hdr *sp_iohubs,
				   unsigned int index, struct dt_node *xcom,
				   unsigned int pe_xscom,
				   unsigned int pci_xscom,
				   unsigned int spci_xscom)
{
	struct dt_node *pbcq;
	uint32_t reg[6];
	unsigned int hdif_vers;

	/* Get HDIF version */
	hdif_vers = be16_to_cpu(sp_iohubs->version);

	/* Create PBCQ node under xscom */
	pbcq = dt_new_addr(xcom, "pbcq", pe_xscom);
	if (!pbcq)
		return NULL;

	/* "reg" property contains in order the PE, PCI and SPCI XSCOM
	 * addresses
	 */
	reg[0] = pe_xscom;
	reg[1] = 0x20;
	reg[2] = pci_xscom;
	reg[3] = 0x05;
	reg[4] = spci_xscom;
	reg[5] = 0x15;
	dt_add_property(pbcq, "reg", reg, sizeof(reg));

	/* A couple more things ... */
	dt_add_property_strings(pbcq, "compatible", "ibm,power8-pbcq");
	dt_add_property_cells(pbcq, "ibm,phb-index", index);
	dt_add_property_cells(pbcq, "ibm,hub-id", be16_to_cpu(hub->hub_num));

	/* The loc code of the PHB itself is different from the base
	 * loc code of the slots (It's actually the DCM's loc code).
	 */
	io_get_loc_code(sp_iohubs, pbcq, "ibm,loc-code");

	/* We indicate that this is an IBM setup, which means that
	 * the presence detect A/B bits are meaningful. So far we
	 * don't know whether they make any sense on customer setups
	 * so we only set that when booting with HDAT
	 */
	dt_add_property(pbcq, "ibm,use-ab-detect", NULL, 0);

	/* HDAT spec has these in version 0x6A and later */
	if (hdif_vers >= 0x6a) {
		u64 eq0 = be64_to_cpu(hub->phb_lane_eq[index][0]);
		u64 eq1 = be64_to_cpu(hub->phb_lane_eq[index][1]);
		u64 eq2 = be64_to_cpu(hub->phb_lane_eq[index][2]);
		u64 eq3 = be64_to_cpu(hub->phb_lane_eq[index][3]);
		dt_add_property_cells(pbcq, "ibm,lane-eq",
				      hi32(eq0), lo32(eq0),
				      hi32(eq1), lo32(eq1),
				      hi32(eq2), lo32(eq2),
				      hi32(eq3), lo32(eq3));
	}

	/* Currently we only create a PBCQ node, the actual PHB nodes
	 * will be added by sapphire later on.
	 */
	return pbcq;
}

static struct dt_node *io_add_p8(const struct cechub_io_hub *hub,
				 const struct HDIF_common_hdr *sp_iohubs)
{
	struct dt_node *xscom;
	unsigned int i, chip_id;

	chip_id = pcid_to_chip_id(be32_to_cpu(hub->proc_chip_id));

	prlog(PR_INFO, "CEC:     HW CHIP=0x%x, HW TOPO=0x%04x\n", chip_id,
	      be16_to_cpu(hub->hw_topology));

	xscom = find_xscom_for_chip(chip_id);
	if (!xscom) {
		prerror("P8: Can't find XSCOM for chip %d\n", chip_id);
		return NULL;
	}

	/* Create PHBs, max 3 */
	for (i = 0; i < 3; i++) {
		if (hub->fab_br0_pdt & (0x80 >> i))
			/* XSCOM addresses are the same on Murano and Venice */
			io_add_phb3(hub, sp_iohubs, i, xscom,
				    0x02012000 + (i * 0x400),
				    0x09012000 + (i * 0x400),
				    0x09013c00 + (i * 0x40));
	}

	/* HACK: We return the XSCOM device for the VPD info */
	return xscom;
}

static void io_add_p8_cec_vpd(const struct HDIF_common_hdr *sp_iohubs)
{
	const struct HDIF_child_ptr *iokids;
	const void *iokid;	
	const void *kwvpd;
	unsigned int kwvpd_sz;

	/* P8 LXR0 kept in IO KID Keyword VPD */
	iokids = HDIF_child_arr(sp_iohubs, CECHUB_CHILD_IO_KIDS);
	if (!CHECK_SPPTR(iokids)) {
		prlog(PR_WARNING, "CEC:     No IOKID child array !\n");
		return;
	}
	if (!iokids->count) {
		prlog(PR_WARNING, "CEC:     IOKID count is 0 !\n");
		return;
	}
	if (be32_to_cpu(iokids->count) > 1) {
		prlog(PR_WARNING, "CEC:     WARNING ! More than 1 IO KID !!! (%d)\n",
		      iokids->count);
		/* Ignoring the additional ones */
	}

	iokid = HDIF_child(sp_iohubs, iokids, 0, "IO KID");
	if (!iokid) {
		prlog(PR_WARNING, "CEC:     No IO KID structure in child array !\n");
		return;
	}

	/* Grab base location code for slots */
	io_get_loc_code(iokid, dt_root, "ibm,io-base-loc-code");

	kwvpd = HDIF_get_idata(iokid, CECHUB_ASCII_KEYWORD_VPD, &kwvpd_sz);
	if (!kwvpd) {
		prlog(PR_WARNING, "CEC:     No VPD entry in IO KID !\n");
		return;
	}

	/* Grab LX load info */
	io_get_lx_info(kwvpd, kwvpd_sz, 0, dt_root);
}

static void io_parse_fru(const void *sp_iohubs)
{
	unsigned int i;
	struct dt_node *hn;
	int count;

	count = HDIF_get_iarray_size(sp_iohubs, CECHUB_FRU_IO_HUBS);
	if (count < 1) {
		prerror("CEC: IO FRU with no chips !\n");
		return;
	}

	prlog(PR_INFO, "CEC:   %d chips in FRU\n", count);

	/* Iterate IO hub array */
	for (i = 0; i < count; i++) {
		const struct cechub_io_hub *hub;
		unsigned int size, hub_id;

		hub = HDIF_get_iarray_item(sp_iohubs, CECHUB_FRU_IO_HUBS,
					   i, &size);
		if (!hub || size < CECHUB_IOHUB_MIN_SIZE) {
			prerror("CEC:     IO-HUB Chip %d bad idata\n", i);
			continue;
		}

		switch (hub->flags & CECHUB_HUB_FLAG_STATE_MASK) {
		case CECHUB_HUB_FLAG_STATE_OK:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d OK\n", i);
			break;
		case CECHUB_HUB_FLAG_STATE_FAILURES:
			prlog(PR_WARNING, "CEC:   IO Hub Chip #%d OK"
			      " with failures\n", i);
			break;
		case CECHUB_HUB_FLAG_STATE_NOT_INST:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d"
			      " Not installed\n", i);
			continue;
		case CECHUB_HUB_FLAG_STATE_UNUSABLE:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d Unusable", i);
			continue;
		}

		hub_id = be16_to_cpu(hub->iohub_id);

		/* GX BAR assignment */
		prlog(PR_DEBUG, "CEC:   PChip: %d HUB ID: %04x [EC=0x%x]"
		      " Hub#=%d)\n",
		      be32_to_cpu(hub->proc_chip_id), hub_id,
		      be32_to_cpu(hub->ec_level), be16_to_cpu(hub->hub_num));

		switch(hub_id) {
		case CECHUB_HUB_P7IOC:
			prlog(PR_INFO, "CEC:     P7IOC !\n");
			hn = io_add_p7ioc(hub, sp_iohubs);
			io_add_common(hn, hub);
			break;
		case CECHUB_HUB_MURANO:
		case CECHUB_HUB_MURANO_SEGU:
			prlog(PR_INFO, "CEC:     Murano !\n");
			hn = io_add_p8(hub, sp_iohubs);
			break;
		case CECHUB_HUB_VENICE_WYATT:
			prlog(PR_INFO, "CEC:     Venice !\n");
			hn = io_add_p8(hub, sp_iohubs);
			break;
		default:
			prlog(PR_ERR, "CEC:     Hub ID 0x%04x unsupported !\n",
			      hub_id);
			hn = NULL;
		}
	}

	/* On P8, grab the CEC VPD */
	if (proc_gen == proc_gen_p8)
		io_add_p8_cec_vpd(sp_iohubs);
}

void io_parse(void)
{
	const struct HDIF_common_hdr *sp_iohubs;
	unsigned int i, size;

	/* Look for IO Hubs */
	if (!get_hdif(&spira.ntuples.cec_iohub_fru, "IO HUB")) {
		prerror("CEC: Cannot locate IO Hub FRU data !\n");
		return;
	}

	/*
	 * Note about LXRn numbering ...
	 *
	 * I can't completely make sense of what that is supposed to be, so
	 * for now, what we do is look for the first one we can find and
	 * increment it for each chip. Works for the machines I have here
	 */

	for_each_ntuple_idx(&spira.ntuples.cec_iohub_fru, sp_iohubs, i,
			    CECHUB_FRU_HDIF_SIG) {
		const struct cechub_hub_fru_id *fru_id_data;
		unsigned int type;
		static const char *typestr[] = {
			"Reservation",
			"Card",
			"CPU Card",
			"Backplane",
			"Backplane Extension"
		};
		fru_id_data = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA_AREA,
					     &size);
		if (!fru_id_data || size < sizeof(struct cechub_hub_fru_id)) {
			prerror("CEC: IO-HUB FRU %d, bad ID data\n", i);
			continue;
		}
		type = be32_to_cpu(fru_id_data->card_type);

		prlog(PR_INFO, "CEC: HUB FRU %d is %s\n",
		      i, type > 4 ? "Unknown" : typestr[type]);

		/*
		 * We currently only handle the backplane (Juno) and
		 * processor FRU (P8 machines)
		 */
		if (type != CECHUB_FRU_TYPE_CEC_BKPLANE &&
		    type != CECHUB_FRU_TYPE_CPU_CARD) {
			prerror("CEC:   Unsupported type\n");
			continue;
		}

		/* We don't support Hubs connected to pass-through ports */
		if (fru_id_data->flags & (CECHUB_FRU_FLAG_HEADLESS |
					  CECHUB_FRU_FLAG_PASSTHROUGH)) {
			prerror("CEC:   Headless or Passthrough unsupported\n");
			continue;
		}

		/* Ok, we have a reasonable candidate */
		io_parse_fru(sp_iohubs);
	}
}

