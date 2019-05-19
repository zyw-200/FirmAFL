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
#include <device.h>
#include <types.h>

#include "hdata.h"

#define PACA_MAX_THREADS 4

static unsigned int paca_index(const struct HDIF_common_hdr *paca)
{
	void *start = get_hdif(&spira.ntuples.paca, PACA_HDIF_SIG);
	return ((void *)paca - start)
		/ be32_to_cpu(spira.ntuples.paca.alloc_len);
}

static struct dt_node *add_cpu_node(struct dt_node *cpus,
				    const struct HDIF_common_hdr *paca,
				    const struct sppaca_cpu_id *id,
				    bool okay)
{
	const struct sppaca_cpu_timebase *timebase;
	const struct sppaca_cpu_cache *cache;
	const struct sppaca_cpu_attr *attr;
	struct dt_node *cpu;
	u32 no, size, ve_flags, l2_phandle, chip_id;

	/* We use the process_interrupt_line as the res id */
	no = be32_to_cpu(id->process_interrupt_line);

	ve_flags = be32_to_cpu(id->verify_exists_flags);
	printf("CPU[%i]: PIR=%i RES=%i %s %s(%u threads)\n",
	       paca_index(paca), be32_to_cpu(id->pir), no,
	       ve_flags & CPU_ID_PACA_RESERVED
	       ? "**RESERVED**" : cpu_state(ve_flags),
	       ve_flags & CPU_ID_SECONDARY_THREAD
	       ? "[secondary] " : 
	       (be32_to_cpu(id->pir) == boot_cpu->pir ? "[boot] " : ""),
	       ((ve_flags & CPU_ID_NUM_SECONDARY_THREAD_MASK)
		>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);

	timebase = HDIF_get_idata(paca, SPPACA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		prerror("CPU[%i]: bad timebase size %u @ %p\n",
			paca_index(paca), size, timebase);
		return NULL;
	}

	cache = HDIF_get_idata(paca, SPPACA_IDATA_CACHE_SIZE, &size);
	if (!cache || size < sizeof(*cache)) {
		prerror("CPU[%i]: bad cache size %u @ %p\n",
			paca_index(paca), size, cache);
		return NULL;
	}

	cpu = add_core_common(cpus, cache, timebase, no, okay);

	/* Core attributes */
	attr = HDIF_get_idata(paca, SPPACA_IDATA_CPU_ATTR, &size);
	if (attr)
		add_core_attr(cpu, be32_to_cpu(attr->attr));

	/* Add cache info */
	l2_phandle = add_core_cache_info(cpus, cache, no, okay);
	dt_add_property_cells(cpu, "l2-cache", l2_phandle);

	/* We append the secondary cpus in __cpu_parse */
	dt_add_property_cells(cpu, "ibm,ppc-interrupt-server#s", no);

	dt_add_property_cells(cpu, DT_PRIVATE "hw_proc_id",
			      be32_to_cpu(id->hardware_proc_id));
	dt_add_property_cells(cpu, "ibm,pir", be32_to_cpu(id->pir));

	chip_id = pcid_to_chip_id(be32_to_cpu(id->processor_chip_id));
	dt_add_property_cells(cpu, "ibm,chip-id", chip_id);

	return cpu;
}

static struct dt_node *find_cpu_by_hardware_proc_id(struct dt_node *root,
						    u32 hw_proc_id)
{
	struct dt_node *i;

	dt_for_each_node(root, i) {
		const struct dt_property *prop;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;

		prop = dt_find_property(i, DT_PRIVATE "hw_proc_id");
		if (!prop)
			return NULL;

		if (be32_to_cpu(*(be32 *)prop->prop) == hw_proc_id)
			return i;
	}
	return NULL;
}

/* Note that numbers are small. */
static void add_be32_sorted(__be32 arr[], __be32 new, unsigned num)
{
	unsigned int i;

	/* Walk until we find where we belong (insertion sort). */
	for (i = 0; i < num; i++) {
		if (be32_to_cpu(new) < be32_to_cpu(arr[i])) {
			__be32 tmp = arr[i];
			arr[i] = new;
			new = tmp;
		}
	}
	arr[i] = new;
}

static void add_icps(void)
{
	struct dt_node *cpu;
	unsigned int i;
	u64 reg[PACA_MAX_THREADS * 2];
	struct dt_node *icp;

	dt_for_each_node(dt_root, cpu) {
		u32 irange[2], size, pir;
		const struct dt_property *intsrv;
		const struct HDIF_common_hdr *paca;
		u64 ibase;
		unsigned int num_threads;
		bool found = false;

		if (!dt_has_node_property(cpu, "device_type", "cpu"))
			continue;

		intsrv = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		pir = dt_prop_get_u32(cpu, "ibm,pir");

		/* Get ibase address */
		paca = get_hdif(&spira.ntuples.paca, PACA_HDIF_SIG);
		for_each_paca(paca) {
			const struct sppaca_cpu_id *id;
			id = HDIF_get_idata(paca, SPPACA_IDATA_CPU_ID, &size);

			if (!CHECK_SPPTR(id))
				continue;

			if (pir != be32_to_cpu(id->pir))
				continue;
			ibase = cleanup_addr(be64_to_cpu(id->ibase));
			found = true;
			break;
		}
		if (!found)
			return;

		num_threads = intsrv->len / sizeof(u32);
		assert(num_threads <= PACA_MAX_THREADS);

		icp = dt_new_addr(dt_root, "interrupt-controller", ibase);
		if (!icp)
			continue;

		dt_add_property_strings(icp, "compatible",
					"IBM,ppc-xicp",
					"IBM,power7-xicp");

		irange[0] = dt_property_get_cell(intsrv, 0); /* Index */
		irange[1] = num_threads;		     /* num servers */
		dt_add_property(icp, "ibm,interrupt-server-ranges",
				irange, sizeof(irange));
		dt_add_property(icp, "interrupt-controller", NULL, 0);
		dt_add_property_cells(icp, "#address-cells", 0);
		dt_add_property_string(icp, "device_type",
				   "PowerPC-External-Interrupt-Presentation");
		for (i = 0; i < num_threads*2; i += 2) {
			reg[i] = ibase;
			/* One page is enough for a handful of regs. */
			reg[i+1] = 4096;
			ibase += reg[i+1];
		}
		dt_add_property(icp, "reg", reg, sizeof(reg));	
	}
}

static bool __paca_parse(void)
{
	const struct HDIF_common_hdr *paca;
	struct dt_node *cpus;

	paca = get_hdif(&spira.ntuples.paca, PACA_HDIF_SIG);
	if (!paca) {
		prerror("Invalid PACA (PCIA = %p)\n",
			ntuple_addr(&spira.ntuples.pcia));
		return false;
	}

	if (be32_to_cpu(spira.ntuples.paca.act_len) < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			be32_to_cpu(spira.ntuples.paca.act_len));
		return false;
	}

	cpus = dt_new(dt_root, "cpus");
	dt_add_property_cells(cpus, "#address-cells", 1);
	dt_add_property_cells(cpus, "#size-cells", 0);

	for_each_paca(paca) {
		const struct sppaca_cpu_id *id;
		u32 size, ve_flags;
		bool okay;

		id = HDIF_get_idata(paca, SPPACA_IDATA_CPU_ID, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				paca_index(paca), size, id);
			return false;
		}

		ve_flags = be32_to_cpu(id->verify_exists_flags);
		switch ((ve_flags&CPU_ID_VERIFY_MASK) >> CPU_ID_VERIFY_SHIFT) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			okay = true;
			break;
		default:
			okay = false;
		}

		printf("CPU[%i]: PIR=%i RES=%i %s\n",
		       paca_index(paca), be32_to_cpu(id->pir),
		       be32_to_cpu(id->process_interrupt_line),
		       okay ? "OK" : "UNAVAILABLE");

		/* Secondary threads don't get their own node. */
		if (ve_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		if (!add_cpu_node(cpus, paca, id, okay))
			return false;
	}

	/* Now account for secondaries. */
	for_each_paca(paca) {
		const struct dt_property *prop;
		const struct sppaca_cpu_id *id;
		u32 size, state, num, ve_flags;
		struct dt_node *cpu;
		__be32 *new_prop;

		id = HDIF_get_idata(paca, 2, &size);
		if (!CHECK_SPPTR(id))
			continue;

		ve_flags = be32_to_cpu(id->verify_exists_flags);
		state = (ve_flags & CPU_ID_VERIFY_MASK) >> CPU_ID_VERIFY_SHIFT;
		switch (state) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			break;
		default:
			continue;
		}

		/* Only interested in secondary threads. */
		if (!(ve_flags & CPU_ID_SECONDARY_THREAD))
			continue;

		cpu = find_cpu_by_hardware_proc_id(cpus,
				   be32_to_cpu(id->hardware_proc_id));
		if (!cpu) {
			prerror("CPU[%i]: could not find primary hwid %i\n",
				paca_index(paca),
				be32_to_cpu(id->hardware_proc_id));
			return false;
		}

		/* Add the cpu #. */
		prop = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		if (!prop) {
			prerror("CPU[%i]: could not find mapping information\n",
				paca_index(paca));
			return false;
		}
		num = prop->len / sizeof(u32);
		new_prop = malloc((num + 1) * sizeof(u32));
		if (!new_prop) {
			prerror("Property allocation length %zu failed\n",
				(num + 1) * sizeof(u32));
			return false;
		}
		memcpy(new_prop, prop->prop, prop->len);
		add_be32_sorted(new_prop, id->process_interrupt_line, num);
		dt_del_property(cpu, (struct dt_property *)prop);
		dt_add_property(cpu, "ibm,ppc-interrupt-server#s",
				new_prop, (num + 1) * sizeof(__be32));
		free(new_prop);
	}

	add_icps();

	return true;
}

int paca_parse(void)
{
	if (!__paca_parse()) {
		prerror("CPU: Initial CPU parsing failed\n");
		return -1;
	}
	return 0;
}
