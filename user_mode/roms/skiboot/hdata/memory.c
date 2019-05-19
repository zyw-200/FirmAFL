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

#include <cpu.h>
#include <device.h>
#include <vpd.h>
#include <ccan/str/str.h>
#include <libfdt/libfdt.h>
#include <types.h>

#include "spira.h"
#include "hdata.h"

struct HDIF_ram_area_id {
	__be16 id;
#define RAM_AREA_INSTALLED	0x8000
#define RAM_AREA_FUNCTIONAL	0x4000
	__be16 flags;
};

struct HDIF_ram_area_size {
	__be64 mb;
};

struct ram_area {
	const struct HDIF_ram_area_id *raid;
	const struct HDIF_ram_area_size *rasize;
};

struct HDIF_ms_area_address_range {
	__be64 start;
	__be64 end;
	__be32 chip;
	__be32 mirror_attr;
	__be64 mirror_start;
};

struct HDIF_ms_area_id {
	__be16 id;
#define MS_PTYPE_RISER_CARD	0x8000
#define MS_PTYPE_MEM_CARD	0x4000
#define MS_PTYPE_CEC_FRU	0x2000
#define MS_PTYPE_HYBRID_CARD	0x1000
	__be16 parent_type;
#define MS_AREA_INSTALLED	0x8000
#define MS_AREA_FUNCTIONAL	0x4000
#define MS_AREA_SHARED		0x2000
	__be16 flags;
	__be16 share_id;
};

static struct dt_node *find_shared(struct dt_node *root, u16 id, u64 start, u64 len)
{
	struct dt_node *i;

	for (i = dt_first(root); i; i = dt_next(root, i)) {
		__be64 reg[2];
		const struct dt_property *shared, *type, *region;

		type = dt_find_property(i, "device_type");
		if (!type || strcmp(type->prop, "memory") != 0)
			continue;

		shared = dt_find_property(i, DT_PRIVATE "share-id");
		if (!shared || fdt32_to_cpu(*(u32 *)shared->prop) != id)
			continue;

		region = dt_find_property(i, "reg");
		if (!region)
			continue;
		memcpy(reg, region->prop, sizeof(reg));
		if (be64_to_cpu(reg[0]) == start && be64_to_cpu(reg[1]) == len)
			break;
	}
	return i;
}

static void append_chip_id(struct dt_node *mem, u32 id)
{
	struct dt_property *prop;
	size_t len, i;
	be32 *p;

	prop = __dt_find_property(mem, "ibm,chip-id");
	if (!prop)
		return;
	len = prop->len >> 2;
	p = (be32*)prop->prop;

	/* Check if it exists already */
	for (i = 0; i < len; i++) {
		if (be32_to_cpu(p[i]) == id)
			return;
	}

	/* Add it to the list */
	dt_resize_property(&prop, (len + 1) << 2);
	p = (be32 *)prop->prop;
	p[len] = cpu_to_be32(id);
}

static bool add_address_range(struct dt_node *root,
			      const struct HDIF_ms_area_id *id,
			      const struct HDIF_ms_area_address_range *arange)
{
	struct dt_node *mem;
	u64 reg[2];
	char *name;
	u32 chip_id;
	size_t namesz = sizeof("memory@") + STR_MAX_CHARS(reg[0]);

	name = (char*)malloc(namesz);
	assert(name);

	chip_id = pcid_to_chip_id(be32_to_cpu(arange->chip));

	prlog(PR_DEBUG, "  Range: 0x%016llx..0x%016llx "
	      "on Chip 0x%x mattr: 0x%x\n",
	      (long long)be64_to_cpu(arange->start),
	      (long long)be64_to_cpu(arange->end),
	      chip_id, arange->mirror_attr);

	/* reg contains start and length */
	reg[0] = cleanup_addr(be64_to_cpu(arange->start));
	reg[1] = cleanup_addr(be64_to_cpu(arange->end)) - reg[0];

	if (be16_to_cpu(id->flags) & MS_AREA_SHARED) {
		/* Only enter shared nodes once. */ 
		mem = find_shared(root, be16_to_cpu(id->share_id),
				  reg[0], reg[1]);
		if (mem) {
			append_chip_id(mem, chip_id);
			free(name);
			return true;
		}
	}
	snprintf(name, namesz, "memory@%llx", (long long)reg[0]);

	mem = dt_new(root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property_cells(mem, "ibm,chip-id", chip_id);
	dt_add_property_u64s(mem, "reg", reg[0], reg[1]);
	if (be16_to_cpu(id->flags) & MS_AREA_SHARED)
		dt_add_property_cells(mem, DT_PRIVATE "share-id",
				      be16_to_cpu(id->share_id));

	free(name);

	return true;
}

static u32 add_chip_id_to_ram_area(const struct HDIF_common_hdr *msarea,
				    struct dt_node *ram_area)
{
	const struct HDIF_array_hdr *arr;
	const struct HDIF_ms_area_address_range *arange;
	unsigned int size;
	u32 chip_id;

	/* Safe to assume pointers are valid here. */
	arr = HDIF_get_idata(msarea, 4, &size);
	arange = (void *)arr + be32_to_cpu(arr->offset);
	chip_id = pcid_to_chip_id(be32_to_cpu(arange->chip));
	dt_add_property_cells(ram_area, "ibm,chip-id", chip_id);

	return chip_id;
}

static void add_bus_freq_to_ram_area(struct dt_node *ram_node, u32 chip_id)
{
	const struct sppcia_cpu_timebase *timebase;
	bool got_pcia = false;
	const void *pcia;
	u64 freq;
	u32 size;

	pcia = get_hdif(&spira.ntuples.pcia, SPPCIA_HDIF_SIG);
	if (!pcia) {
		prlog(PR_WARNING, "HDAT: Failed to add memory bus frequency "
		      "as PCIA does not exist\n");
		return;
	}

	for_each_pcia(pcia) {
		const struct sppcia_core_unique *id;

		id = HDIF_get_idata(pcia, SPPCIA_IDATA_CORE_UNIQUE, &size);
		if (!id || size < sizeof(*id)) {
			prlog(PR_WARNING, "HDAT: Bad id size %u @ %p\n", size, id);
			return;
		}

		if (chip_id == pcid_to_chip_id(be32_to_cpu(id->proc_chip_id))) {
			got_pcia = true;
			break;
		}
	}

	if (got_pcia == false)
		return;

	timebase = HDIF_get_idata(pcia, SPPCIA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		/**
		 * @fwts-label HDATBadTimebaseSize
		 * @fwts-advice HDAT described an invalid size for timebase,
		 * which means there's a disagreement between HDAT and OPAL.
		 * This is most certainly a firmware bug.
		 */
		prlog(PR_ERR, "HDAT: Bad timebase size %u @ %p\n", size,
		      timebase);
		return;
	}

	freq = ((u64)be32_to_cpu(timebase->memory_bus_frequency)) *1000000ul;
	dt_add_property_cells(ram_node, "ibm,memory-bus-frequency", hi32(freq),
			      lo32(freq));
}

static void add_size_to_ram_area(struct dt_node *ram_node,
				 const struct HDIF_common_hdr *hdr,
				 int indx_vpd)
{
	const void	*fruvpd;
	unsigned int	fruvpd_sz;
	const void	*kw;
	char		*str;
	uint8_t		kwsz;

	fruvpd = HDIF_get_idata(hdr, indx_vpd, &fruvpd_sz);
	if (!CHECK_SPPTR(fruvpd))
		return;

	/* DIMM Size */
	kw = vpd_find(fruvpd, fruvpd_sz, "VINI", "SZ", &kwsz);
	if (!kw)
		return;

	str = zalloc(kwsz + 1);
	if (!str){
		prerror("Allocation failed\n");
		return;
	}
	memcpy(str, kw, kwsz);
	dt_add_property_string(ram_node, "size", str);
	free(str);
}

static void vpd_add_ram_area(const struct HDIF_common_hdr *msarea)
{
	unsigned int i;
	unsigned int ram_sz;
	const struct HDIF_common_hdr *ramarea;
	const struct HDIF_child_ptr *ramptr;
	const struct HDIF_ram_area_id *ram_id;
	struct dt_node *ram_node;
	u32 chip_id;

	ramptr = HDIF_child_arr(msarea, 0);
	if (!CHECK_SPPTR(ramptr)) {
		prerror("MS AREA: No RAM area at %p\n", msarea);
		return;
	}

	for (i = 0; i < be32_to_cpu(ramptr->count); i++) {
		ramarea = HDIF_child(msarea, ramptr, i, "RAM   ");
		if (!CHECK_SPPTR(ramarea))
			continue;

		ram_id = HDIF_get_idata(ramarea, 2, &ram_sz);
		if (!CHECK_SPPTR(ram_id))
			continue;

		if ((be16_to_cpu(ram_id->flags) & RAM_AREA_INSTALLED) &&
		    (be16_to_cpu(ram_id->flags) & RAM_AREA_FUNCTIONAL)) {
			ram_node = dt_add_vpd_node(ramarea, 0, 1);
			if (ram_node) {
				chip_id = add_chip_id_to_ram_area(msarea,
								  ram_node);
				add_bus_freq_to_ram_area(ram_node, chip_id);
				add_size_to_ram_area(ram_node, ramarea, 1);
			}
		}
	}
}

static void get_msareas(struct dt_node *root,
			const struct HDIF_common_hdr *ms_vpd)
{
	unsigned int i;
	const struct HDIF_child_ptr *msptr;

	/* First childptr refers to msareas. */
	msptr = HDIF_child_arr(ms_vpd, MSVPD_CHILD_MS_AREAS);
	if (!CHECK_SPPTR(msptr)) {
		prerror("MS VPD: no children at %p\n", ms_vpd);
		return;
	}

	for (i = 0; i < be32_to_cpu(msptr->count); i++) {
		const struct HDIF_common_hdr *msarea;
		const struct HDIF_array_hdr *arr;
		const struct HDIF_ms_area_address_range *arange;
		const struct HDIF_ms_area_id *id;
		const void *fruid;
		unsigned int size, j;
		u16 flags;

		msarea = HDIF_child(ms_vpd, msptr, i, "MSAREA");
		if (!CHECK_SPPTR(msarea))
			return;

		id = HDIF_get_idata(msarea, 2, &size);
		if (!CHECK_SPPTR(id))
			return;
		if (size < sizeof(*id)) {
			prerror("MS VPD: %p msarea #%i id size too small!\n",
				ms_vpd, i);
			return;
		}

		flags = be16_to_cpu(id->flags);
		prlog(PR_DEBUG, "MS VPD: %p, area %i: %s %s %s\n",
		       ms_vpd, i,
		       flags & MS_AREA_INSTALLED ?
		       "installed" : "not installed",
		       flags & MS_AREA_FUNCTIONAL ?
		       "functional" : "not functional",
		       flags & MS_AREA_SHARED ?
		       "shared" : "not shared");

		if ((flags & (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
		    != (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
			continue;

		arr = HDIF_get_idata(msarea, 4, &size);
		if (!CHECK_SPPTR(arr))
			continue;

		if (size < sizeof(*arr)) {
			prerror("MS VPD: %p msarea #%i arr size too small!\n",
				ms_vpd, i);
			return;
		}

		if (be32_to_cpu(arr->eactsz) < sizeof(*arange)) {
			prerror("MS VPD: %p msarea #%i arange size too small!\n",
				ms_vpd, i);
			return;
		}

		fruid = HDIF_get_idata(msarea, 0, &size);
		if (!CHECK_SPPTR(fruid))
			return;

		/* Add Raiser card VPD */
		if (be16_to_cpu(id->parent_type) & MS_PTYPE_RISER_CARD)
			dt_add_vpd_node(msarea, 0, 1);

		/* Add RAM Area VPD */
		vpd_add_ram_area(msarea);

		/* This offset is from the arr, not the header! */
		arange = (void *)arr + be32_to_cpu(arr->offset);
		for (j = 0; j < be32_to_cpu(arr->ecnt); j++) {
			if (!add_address_range(root, id, arange))
				return;
			arange = (void *)arange + be32_to_cpu(arr->esize);
		}
	}
}

static bool __memory_parse(struct dt_node *root)
{
	struct HDIF_common_hdr *ms_vpd;
	const struct msvpd_ms_addr_config *msac;
	const struct msvpd_total_config_ms *tcms;
	unsigned int size;

	ms_vpd = get_hdif(&spira.ntuples.ms_vpd, MSVPD_HDIF_SIG);
	if (!ms_vpd) {
		prerror("MS VPD: invalid\n");
		op_display(OP_FATAL, OP_MOD_MEM, 0x0000);
		return false;
	}
	if (be32_to_cpu(spira.ntuples.ms_vpd.act_len) < sizeof(*ms_vpd)) {
		prerror("MS VPD: invalid size %u\n",
			be32_to_cpu(spira.ntuples.ms_vpd.act_len));
		op_display(OP_FATAL, OP_MOD_MEM, 0x0001);
		return false;
	}

	prlog(PR_DEBUG, "MS VPD: is at %p\n", ms_vpd);

	msac = HDIF_get_idata(ms_vpd, MSVPD_IDATA_MS_ADDR_CONFIG, &size);
	if (!CHECK_SPPTR(msac) || size < sizeof(*msac)) {
		prerror("MS VPD: bad msac size %u @ %p\n", size, msac);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0002);
		return false;
	}
	prlog(PR_DEBUG, "MS VPD: MSAC is at %p\n", msac);

	dt_add_property_u64(dt_root, DT_PRIVATE "maxmem",
			    be64_to_cpu(msac->max_configured_ms_address));

	tcms = HDIF_get_idata(ms_vpd, MSVPD_IDATA_TOTAL_CONFIG_MS, &size);
	if (!CHECK_SPPTR(tcms) || size < sizeof(*tcms)) {
		prerror("MS VPD: Bad tcms size %u @ %p\n", size, tcms);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0003);
		return false;
	}
	prlog(PR_DEBUG, "MS VPD: TCMS is at %p\n", tcms);

	prlog(PR_DEBUG, "MS VPD: Maximum configured address: 0x%llx\n",
	      (long long)be64_to_cpu(msac->max_configured_ms_address));
	prlog(PR_DEBUG, "MS VPD: Maximum possible address: 0x%llx\n",
	      (long long)be64_to_cpu(msac->max_possible_ms_address));

	get_msareas(root, ms_vpd);

	prlog(PR_INFO, "MS VPD: Total MB of RAM: 0x%llx\n",
	       (long long)be64_to_cpu(tcms->total_in_mb));

	return true;
}

void memory_parse(void)
{
	if (!__memory_parse(dt_root)) {
		prerror("MS VPD: Failed memory init !\n");
		abort();
	}
}

