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
#include <vpd.h>
#include <string.h>
#include "spira.h"
#include "hdata.h"
#include <device.h>
#include "hdata.h"
#include <inttypes.h>

struct card_info {
	const char *ccin; 	/* Customer card identification number */
	const char *description;
};

static const struct card_info card_table[] = {
	{"2B06", "System planar 2S4U"},
	{"2B07", "System planar 1S4U"},
	{"2B2E", "System planar 2S2U"},
	{"2B2F", "System planar 1S2U"},
	{"2CD4", "System planar 2S4U"},
	{"2CD5", "System planar 1S4U"},
	{"2CD6", "System planar 2S2U"},
	{"2CD7", "System planar 1S2U"},
	{"2CD7", "System planar 1S2U"},
	{"2B09", "Base JBOD, RAID and Backplane HD"},
	{"57D7", "Split JBOD, RAID Card"},
	{"2B0B", "Native I/O Card"},

	/* Anchor cards */
	{"52FE", "System Anchor Card - IBM Power 824"},
	{"52F2", "System Anchor Card - IBM Power 814"},
	{"52F5", "System Anchor Card - IBM Power 822"},
	{"561A", "System Anchor Card - IBM Power 824L"},
	{"524D", "System Anchor Card - IBM Power 822L"},
	{"560F", "System Anchor Card - IBM Power 812L"},
	{"561C", "System Anchor Card - DS8870"},

	/* Memory DIMMs */
	{"31E0", "16GB CDIMM"},
	{"31E8", "16GB CDIMM"},
	{"31E1", "32GB CDIMM"},
	{"31E9", "32GB CDIMM"},
	{"31E2", "64GB CDIMM"},
	{"31EA", "64GB CDIMM"},

	/* Power supplies */
	{"2B1D", "Power Supply 900W AC"},
	{"2B1E", "Power Supply 1400W AC"},
	{"2B75", "Power Supply 1400W HVDC"},

	/* Fans */
	{"2B1F", "Fan 4U (A1, A2, A3, A4)"},
	{"2B29", "Fan 2U (A1, A2, A3, A4, A5, A6)"},

	/* Other cards */
};

static struct dt_node *dt_create_vpd_node(struct dt_node *parent,
					  const struct slca_entry *entry);

static const struct card_info *card_info_lookup(char *ccin)
{
	int i;
	for(i = 0; i < ARRAY_SIZE(card_table); i++)
		if (!strcmp(card_table[i].ccin, ccin))
			return &card_table[i];
	return NULL;
}

static void vpd_vini_parse(struct dt_node *node,
			   const void *fruvpd, unsigned int fruvpd_sz)
{
	const void *kw;
	char *str;
	uint8_t kwsz;
	const struct card_info *cinfo;

	/* FRU Stocking Part Number */
	kw = vpd_find(fruvpd, fruvpd_sz, "VINI", "FN", &kwsz);
	if (kw) {
		str = zalloc(kwsz + 1);
		if (!str)
			goto no_memory;
		memcpy(str, kw, kwsz);
		dt_add_property_string(node, "fru-number", str);
		free(str);
	}

	/* Serial Number */
	kw = vpd_find(fruvpd, fruvpd_sz, "VINI", "SN", &kwsz);
	if (kw) {
		str = zalloc(kwsz + 1);
		if (!str)
			goto no_memory;
		memcpy(str, kw, kwsz);
		dt_add_property_string(node, "serial-number", str);
		free(str);
	}

	/* Part Number */
	kw = vpd_find(fruvpd, fruvpd_sz, "VINI", "PN", &kwsz);
	if (kw) {
		str = zalloc(kwsz + 1);
		if (!str)
			goto no_memory;
		memcpy(str, kw, kwsz);
		dt_add_property_string(node, "part-number", str);
		free(str);
	}

	/* Customer Card Identification Number (CCIN) */
	kw = vpd_find(fruvpd, fruvpd_sz, "VINI", "CC", &kwsz);
	if (kw) {
		str = zalloc(kwsz + 1);
		if (!str)
			goto no_memory;
		memcpy(str, kw, kwsz);
		dt_add_property_string(node, "ccin", str);
		cinfo = card_info_lookup(str);
		if (cinfo) {
			dt_add_property_string(node,
				       "description", cinfo->description);
		} else {
			dt_add_property_string(node, "description", "Unknown");
			prlog(PR_WARNING,
			      "VPD: CCIN desc not available for : %s\n", str);
		}
		free(str);
	}
	return;
no_memory:
	prerror("VPD: memory allocation failure in VINI parsing\n");
}

static const char *vpd_map_name(const char *vpd_name)
{
	/* vpd_name is a 2 char array */
	switch (vpd_name[0]) {
	case 'A':
		switch (vpd_name[1]) {
		case 'A':
			return "ac-power-supply";
		case 'M':
			return "air-mover";
		case 'V':
			return "anchor-card";
		}
		break;
	case 'B':
		switch (vpd_name[1]) {
		case 'A':
			return "bus-adapter-card";
		case 'C':
			return "battery-charger";
		case 'D':
			return "bus-daughter-card";
		case 'E':
			return "bus-expansion-card";
		case 'P':
			return "backplane";
		case 'R':
			return "backplane-riser";
		case 'X':
			return "backplane-extender";
		}
		break;
	case 'C':
		switch (vpd_name[1]) {
		case 'A':
			return "calgary-bridge";
		case 'B':
			return "infiniband-connector";
		case 'C':
			return "clock-card";
		case 'D':
			return "card-connector";
		case 'E':
			return "ethernet-connector";
		case 'L':
			return "calgary-phb";
		case 'I':
			return "capacity-card";
		case 'O':
			return "sma-connector";
		case 'P':
			return "processor-capacity-card";
		case 'R':
			return "rio-connector";
		case 'S':
			return "serial-connector";
		case 'U':
			return "usb-connector";
		}
		break;
	case 'D':
		switch (vpd_name[1]) {
		case 'B':
			return "dasd-backplane";
		case 'C':
			return "drawer-card";
		case 'E':
			return "drawer-extension";
		case 'I':
			return "drawer-interposer";
		case 'L':
			return "p7ih-dlink-connector";
		case 'T':
			return "legacy-pci-card";
		case 'V':
			return "media-drawer-led";
		}
		break;
	case 'E':
		switch (vpd_name[1]) {
		case 'I':
			return "enclosure-led";
		case 'F':
			return "enclosure-fault-led";
		case 'S':
			return "embedded-sas";
		case 'T':
			return "ethernet-riser";
		case 'V':
			return "enclosure";
		}
		break;
	case 'F':
		switch (vpd_name[1]) {
		case 'M':
			return "frame";
		}
		break;
	case 'H':
		switch (vpd_name[1]) {
		case 'B':
			return "host-rio-pci-card";
		case 'D':
			return "high-speed-card";
		case 'M':
			return "hmc-connector";
		}
		break;
	case 'I':
		switch (vpd_name[1]) {
		case 'B':
			return "io-backplane";
		case 'C':
			return "io-card";
		case 'D':
			return "ide-connector";
		case 'I':
			return "io-drawer-led";
		case 'P':
			return "interplane-card";
		case 'S':
			return "smp-vbus-cable";
		case 'T':
			return "enclosure-cable";
		case 'V':
			return "io-enclosure";
		}
		break;
	case 'K':
		switch (vpd_name[1]) {
		case 'V':
			return "keyboard-led";
		}
		break;
	case 'L':
		switch (vpd_name[1]) {
		case '2':
			return "l2-cache-module";
		case '3':
			return "l3-cache-module";
		case 'C':
			return "squadrons-light-connector";
		case 'R':
			return "p7ih-connector";
		case 'O':
			return "system-locate-led";
		case 'T':
			return "squadrons-light-strip";
		}
		break;
	case 'M':
		switch (vpd_name[1]) {
		case 'B':
			return "media-backplane";
		case 'E':
			return "map-extension";
		case 'M':
			return "mip-meter";
		case 'S':
			return "ms-dimm";
		}
		break;
	case 'N':
		switch (vpd_name[1]) {
		case 'B':
			return "nvram-battery";
		case 'C':
			return "sp-node-controller";
		case 'D':
			return "numa-dimm";
		}
		break;
	case 'O':
		switch (vpd_name[1]) {
		case 'D':
			return "cuod-card";
		case 'P':
			return "op-panel";
		case 'S':
			return "oscillator";
		}
		break;
	case 'P':
		switch (vpd_name[1]) {
		case '2':
			return "ioc";
		case '5':
			return "ioc-bridge";
		case 'B':
			return "io-drawer-backplane";
		case 'C':
			return "power-capacitor";
		case 'D':
			return "processor-card";
		case 'F':
			return "processor";
		case 'I':
			return "ioc-phb";
		case 'O':
			return "spcn";
		case 'N':
			return "spcn-connector";
		case 'R':
			return "pci-riser-card";
		case 'S':
			return "power-supply";
		case 'T':
			return "pass-through-card";
		case 'X':
			return "psc-sync-card";
		case 'W':
			return "power-connector";
		}
		break;
	case 'R':
		switch (vpd_name[1]) {
		case 'G':
			return "regulator";
		case 'I':
			return "riser";
		case 'K':
			return "rack-indicator";
		case 'W':
			return "riscwatch-connector";
		}
		break;
	case 'S':
		switch (vpd_name[1]) {
		case 'A':
			return "sys-attn-led";
		case 'B':
			return "backup-sysvpd";
		case 'C':
			return "scsi-connector";
		case 'D':
			return "sas-connector";
		case 'I':
			return "scsi-ide-converter";
		case 'L':
			return "phb-slot";
		case 'P':
			return "service-processor";
		case 'R':
			return "service-card";
		case 'S':
			return "soft-switch";
		case 'V':
			return "system-vpd";
		case 'Y':
			return "legacy-sysvpd";
		}
		break;
	case 'T':
		switch (vpd_name[1]) {
		case 'D':
			return "tod-clock";
		case 'I':
			return "torrent-pcie-phb";
		case 'L':
			return "torrent-riser";
		case 'M':
			return "thermal-sensor";
		case 'P':
			return "tpmd-adapter";
		case 'R':
			return "torrent-bridge";
		}
		break;
	case 'V':
		switch (vpd_name[1]) {
		case 'V':
			return "root-node-vpd";
		}
		break;
	case 'W':
		switch (vpd_name[1]) {
		case 'D':
			return "water_device";
		}
		break;
	}

	prlog(PR_WARNING,
	      "VPD: Could not map FRU ID %s to a known name\n", vpd_name);
	return "Unknown";
}

static bool valid_child_entry(const struct slca_entry *entry)
{
	if ((entry->install_indic == SLCA_INSTALL_INSTALLED) &&
		(entry->vpd_collected == SLCA_VPD_COLLECTED))
		return true;

	return false;
}

static void vpd_add_children(struct dt_node *parent, uint16_t slca_index)
{
	const struct slca_entry *s_entry, *child;
	uint16_t current_child_index, max_index;

	s_entry = slca_get_entry(slca_index);
	if (!s_entry || (s_entry->nr_child == 0))
		return;

	/*
	 * This slca_entry has children. Parse the children array
	 * and add nodes for valid entries.
	 *
	 * A child entry is valid if all of the following criteria is met
	 *	a. SLCA_INSTALL_INSTALLED is set in s_entry->install_indic
	 *	b. SLCA_VPD_COLLECTED is set in s_entry->vpd_collected
	 *	c. The SLCA is not a duplicate entry.
	 */

	/* current_index tracks where we are right now in the array */
	current_child_index = be16_to_cpu(s_entry->child_index);

	/* max_index tracks how far down the array we must traverse */
	max_index = be16_to_cpu(s_entry->child_index)
				+ be16_to_cpu(s_entry->nr_child);

	while (current_child_index < max_index) {
		child = slca_get_entry(current_child_index);
		if (!child)
			return;

		if (valid_child_entry(child)) {
			struct dt_node *node;

			node = dt_create_vpd_node(parent, child);
			if (!node)
				return;
		}

		/* Skip dups -- currently we presume dups are contiguous */
		if (child->nr_dups > 0)
			current_child_index += child->nr_dups;
		current_child_index++;
	}
	return;
}

/* Create the vpd node and add its children */
static struct dt_node *dt_create_vpd_node(struct dt_node *parent,
					  const struct slca_entry *entry)
{
	struct dt_node *node;
	const char *name;
	uint64_t addr;

	name = vpd_map_name(entry->fru_id);
	addr = (uint64_t)be16_to_cpu(entry->rsrc_id);
	node = dt_new_addr(parent, name, addr);
	if (!node) {
		prerror("VPD: Creating node at %s@%"PRIx64" failed\n", name, addr);
		return NULL;
	}

	/* Add location code */
	slca_vpd_add_loc_code(node, be16_to_cpu(entry->my_index));
	/* Add FRU label */
	dt_add_property(node, "fru-type", entry->fru_id, 2);
	/* Recursively add children */
	vpd_add_children(node, be16_to_cpu(entry->my_index));

	return node;
}

struct dt_node *dt_add_vpd_node(const struct HDIF_common_hdr *hdr,
				int indx_fru, int indx_vpd)
{
	const struct spira_fru_id *fru_id;
	unsigned int fruvpd_sz, fru_id_sz;
	const struct slca_entry *entry;
	struct dt_node *dt_vpd, *node;
	static bool first = true;
	const void *fruvpd;
	const char *name;
	uint64_t addr;
	char *lname;
	int len;

	fru_id = HDIF_get_idata(hdr, indx_fru, &fru_id_sz);
	if (!fru_id)
		return NULL;

	fruvpd = HDIF_get_idata(hdr, indx_vpd, &fruvpd_sz);
	if (!CHECK_SPPTR(fruvpd))
		return NULL;

	dt_vpd = dt_find_by_path(dt_root, "/vpd");
	if (!dt_vpd)
		return NULL;

	if (first) {
		entry = slca_get_entry(SLCA_ROOT_INDEX);
		if (!entry) {
			prerror("VPD: Could not find the slca root entry\n");
			return NULL;
		}

		node = dt_create_vpd_node(dt_vpd, entry);
		if (!node)
			return NULL;

		first = false;
	}

	entry = slca_get_entry(be16_to_cpu(fru_id->slca_index));
	if (!entry)
		return NULL;

	name = vpd_map_name(entry->fru_id);
	addr = (uint64_t)be16_to_cpu(entry->rsrc_id);
	len = strlen(name) + STR_MAX_CHARS(addr) + 2;
	lname = zalloc(len);
	if (!lname) {
		prerror("VPD: Failed to allocate memory\n");
		return NULL;
	}

	snprintf(lname, len, "%s@%llx", name, (long long)addr);

	/* Get the node already created */
	node = dt_find_by_name(dt_vpd, lname);
	free(lname);
	/*
	 * It is unlikely that node not found because vpd nodes have the
	 * corresponding slca entry which we would have used to populate the vpd
	 * tree during the 'first' pass above so that we just need to perform
	 * VINI parse and add the vpd data..
	 * Still, we consider this case and create fresh node under '/vpd' if
	 * 'node' not found.
	 */
	if (!node) {
		node = dt_create_vpd_node(dt_vpd, entry);
		if (!node)
			return NULL;
	}

	/* Parse VPD fields, ensure that it has not been added already */
	if (!dt_find_property(node, "ibm,vpd")) {
		dt_add_property(node, "ibm,vpd", fruvpd, fruvpd_sz);
		vpd_vini_parse(node, fruvpd, fruvpd_sz);
	}

	return node;
}

static void sysvpd_parse(void)
{
	const char *model;
	const char *system_id;
	const char *brand;
	char *str;
	uint8_t sz;
	const void *sysvpd;
	unsigned int sysvpd_sz;
	unsigned int fru_id_sz;
	struct dt_node *dt_vpd;
	const struct spira_fru_id *fru_id;
	struct HDIF_common_hdr *sysvpd_hdr;
	const struct machine_info *mi;

	sysvpd_hdr = get_hdif(&spira.ntuples.system_vpd, SYSVPD_HDIF_SIG);
	if (!sysvpd_hdr)
		goto no_sysvpd;

	fru_id = HDIF_get_idata(sysvpd_hdr, SYSVPD_IDATA_FRU_ID, &fru_id_sz);
	if (!fru_id)
		goto no_sysvpd;;

	sysvpd = HDIF_get_idata(sysvpd_hdr, SYSVPD_IDATA_KW_VPD, &sysvpd_sz);
	if (!CHECK_SPPTR(sysvpd))
		goto no_sysvpd;

	/* Add system VPD */
	dt_vpd = dt_find_by_path(dt_root, "/vpd");
	if (dt_vpd) {
		dt_add_property(dt_vpd, "ibm,vpd", sysvpd, sysvpd_sz);
		slca_vpd_add_loc_code(dt_vpd, be16_to_cpu(fru_id->slca_index));
	}

	model = vpd_find(sysvpd, sysvpd_sz, "VSYS", "TM", &sz);
	if (!model)
		goto no_sysvpd;
	str = zalloc(sz + 1);
	if (!str)
		goto no_sysvpd;
	memcpy(str, model, sz);
	dt_add_property_string(dt_root, "model", str);
	mi = machine_info_lookup(str);
	if (mi) {
		dt_add_property_string(dt_root, "model-name", mi->name);
	} else {
		dt_add_property_string(dt_root, "model-name", "Unknown");
		prlog(PR_WARNING, "VPD: Model name %s not known\n", str);
	}

	free(str);
	dt_add_property_string(dt_root, "vendor", "IBM");

	system_id = vpd_find(sysvpd, sysvpd_sz, "VSYS", "SE", &sz);
	if (!system_id)
		goto no_sysid;
	str = zalloc(sz + 1);
	if (!str)
		goto no_sysid;
	memcpy(str, system_id, sz);
	dt_add_property_string(dt_root, "system-id", str);
	free(str);

	brand = vpd_find(sysvpd, sysvpd_sz, "VSYS", "BR", &sz);
	if (!brand)
		goto no_brand;
	str = zalloc(sz + 1);
	if (!str)
		goto no_brand;
	memcpy(str, brand, sz);
	dt_add_property_string(dt_root, "system-brand", str);
	free(str);

	return;

no_brand:
	dt_add_property_string(dt_root, "system-brand", "Unknown");
	return;

no_sysid:
	dt_add_property_string(dt_root, "system-id", "Unknown");
	return;

 no_sysvpd:
	dt_add_property_string(dt_root, "model", "Unknown");
}

static void iokid_vpd_parse(const struct HDIF_common_hdr *iohub_hdr)
{
	const struct HDIF_child_ptr *iokids;
	const struct HDIF_common_hdr *iokid;
	unsigned int i;

	iokids = HDIF_child_arr(iohub_hdr, CECHUB_CHILD_IO_KIDS);
	if (!CHECK_SPPTR(iokids)) {
		prerror("VPD: No IOKID child array\n");
		return;
	}

	for (i = 0; i < be32_to_cpu(iokids->count); i++) {
		iokid = HDIF_child(iohub_hdr, iokids, i,
					IOKID_FRU_HDIF_SIG);
		/* IO KID VPD structure layout is similar to FRUVPD */
		if (iokid)
			dt_add_vpd_node(iokid,
				FRUVPD_IDATA_FRU_ID, FRUVPD_IDATA_KW_VPD);
	}
}

static void iohub_vpd_parse(void)
{
	const struct HDIF_common_hdr *iohub_hdr;
	const struct cechub_hub_fru_id *fru_id_data;
	unsigned int i, vpd_sz, fru_id_sz;

	if (!get_hdif(&spira.ntuples.cec_iohub_fru, CECHUB_FRU_HDIF_SIG)) {
		prerror("VPD: Could not find IO HUB FRU data\n");
		return;
	}

	for_each_ntuple_idx(&spira.ntuples.cec_iohub_fru, iohub_hdr,
					i, CECHUB_FRU_HDIF_SIG) {

		fru_id_data = HDIF_get_idata(iohub_hdr,
					     CECHUB_FRU_ID_DATA_AREA,
					     &fru_id_sz);

		/* P8, IO HUB is on processor card and we have a
		 * daughter card array
		 */
		if (fru_id_data &&
		    be32_to_cpu(fru_id_data->card_type) == CECHUB_FRU_TYPE_CPU_CARD) {
			iokid_vpd_parse(iohub_hdr);
			continue;
		}

		/* On P7, the keyword VPD will not be NULL */
		if (HDIF_get_idata(iohub_hdr,
				   CECHUB_ASCII_KEYWORD_VPD, &vpd_sz))
			dt_add_vpd_node(iohub_hdr, CECHUB_FRU_ID_DATA,
					CECHUB_ASCII_KEYWORD_VPD);
	}
}

static void _vpd_parse(struct spira_ntuple tuple)
{
	const struct HDIF_common_hdr *fruvpd_hdr;
	unsigned int i;

	if (!get_hdif(&tuple, FRUVPD_HDIF_SIG))
		return;

	for_each_ntuple_idx(&tuple, fruvpd_hdr, i, FRUVPD_HDIF_SIG)
		dt_add_vpd_node(fruvpd_hdr,
				FRUVPD_IDATA_FRU_ID, FRUVPD_IDATA_KW_VPD);
}

void vpd_parse(void)
{
	const struct HDIF_common_hdr *fruvpd_hdr;

	/* Enclosure */
	_vpd_parse(spira.ntuples.nt_enclosure_vpd);

	/* Backplane */
	_vpd_parse(spira.ntuples.backplane_vpd);

	/* System VPD uses the VSYS record, so its special */
	sysvpd_parse();

	/* clock card -- does this use the FRUVPD sig? */
	_vpd_parse(spira.ntuples.clock_vpd);

	/* Anchor card */
	_vpd_parse(spira.ntuples.anchor_vpd);

	/* Op panel -- does this use the FRUVPD sig? */
	_vpd_parse(spira.ntuples.op_panel_vpd);

	/* External cache FRU vpd -- does this use the FRUVPD sig? */
	_vpd_parse(spira.ntuples.ext_cache_fru_vpd);

	/* Misc CEC FRU */
	_vpd_parse(spira.ntuples.misc_cec_fru_vpd);

	/* CEC IO HUB FRU */
	iohub_vpd_parse();

	/*
	 * SP subsystem -- while the rest of the SPINFO structure is
	 * different, the FRU ID data and pointer pair to keyword VPD
	 * are the same offset as a FRUVPD entry. So reuse it
	 */
	fruvpd_hdr = get_hdif(&spira.ntuples.sp_subsys, SPSS_HDIF_SIG);
	if (fruvpd_hdr)
		dt_add_vpd_node(fruvpd_hdr,
				FRUVPD_IDATA_FRU_ID, FRUVPD_IDATA_KW_VPD);
}
