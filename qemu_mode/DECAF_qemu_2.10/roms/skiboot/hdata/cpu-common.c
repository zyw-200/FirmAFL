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
#include <ccan/str/str.h>
#include <device.h>

#include "hdata.h"

struct dt_node * add_core_common(struct dt_node *cpus,
				 const struct sppcia_cpu_cache *cache,
				 const struct sppaca_cpu_timebase *tb,
				 uint32_t int_server, bool okay)
{
	const char *name;
	struct dt_node *cpu;
	uint32_t version;
	uint64_t freq;
	const uint8_t pa_features[] = {
		6, 0, 0xf6, 0x3f, 0xc7, 0x00, 0x80, 0xc0 };

	prlog(PR_INFO, "    Cache: I=%u D=%u/%u/%u/%u\n",
	      be32_to_cpu(cache->icache_size_kb),
	      be32_to_cpu(cache->l1_dcache_size_kb),
	      be32_to_cpu(cache->l2_dcache_size_kb),
	      be32_to_cpu(cache->l3_dcache_size_kb),
	      be32_to_cpu(cache->l35_dcache_size_kb));

	/* Use the boot CPU PVR to make up a CPU name in the device-tree
	 * since the HDAT doesn't seem to tell....
	 */
	version = mfspr(SPR_PVR);
	switch(PVR_TYPE(version)) {
	case PVR_TYPE_P7:
		name = "PowerPC,POWER7";
		break;
	case PVR_TYPE_P7P:
		name = "PowerPC,POWER7+";
		break;
	case PVR_TYPE_P8E:
	case PVR_TYPE_P8:
	case PVR_TYPE_P8NVL:
		name = "PowerPC,POWER8";
		break;
	case PVR_TYPE_P9:
		name = "PowerPC,POWER9";
		break;
	default:
		name = "PowerPC,Unknown";
	}

	cpu = dt_new_addr(cpus, name, int_server);
	assert(cpu);
	dt_add_property_string(cpu, "device_type", "cpu");
	dt_add_property_string(cpu, "status", okay ? "okay" : "bad");
	dt_add_property_cells(cpu, "reg", int_server);
	dt_add_property_cells(cpu, "cpu-version", version);
	dt_add_property(cpu, "64-bit", NULL, 0);
	dt_add_property(cpu, "32-64-bridge", NULL, 0);
	dt_add_property(cpu, "graphics", NULL, 0);
	dt_add_property(cpu, "general-purpose", NULL, 0);
	dt_add_property_cells(cpu, "ibm,processor-segment-sizes",
			      0x1c, 0x28, 0xffffffff, 0xffffffff);
	dt_add_property_cells(cpu, "ibm,processor-page-sizes",
			      0xc, 0x10, 0x18, 0x22);

	/* Page size encodings appear to be the same for P7 and P8 */
	dt_add_property_cells(cpu, "ibm,segment-page-sizes",
		0x0c, 0x000, 3, 0x0c, 0x0000,  /*  4K seg  4k pages */
		                0x10, 0x0007,  /*  4K seg 64k pages */
		                0x18, 0x0038,  /*  4K seg 16M pages */
		0x10, 0x110, 2, 0x10, 0x0001,  /* 64K seg 64k pages */
		                0x18, 0x0008,  /* 64K seg 16M pages */
		0x18, 0x100, 1,	0x18, 0x0000,  /* 16M seg 16M pages */
		0x22, 0x120, 1, 0x22, 0x0003); /* 16G seg 16G pages */
			      
	dt_add_property(cpu, "ibm,pa-features",
			pa_features, sizeof(pa_features));
	dt_add_property_cells(cpu, "ibm,slb-size", 0x20);

	dt_add_property_cells(cpu, "ibm,vmx", 0x2);
	dt_add_property_cells(cpu, "ibm,dfp", 0x2);
	dt_add_property_cells(cpu, "ibm,purr", 0x1);
	dt_add_property_cells(cpu, "ibm,spurr", 0x1);

	/*
	 * Do not create "clock-frequency" if the frequency doesn't
	 * fit in a single cell
	 */
	freq = ((uint64_t)be32_to_cpu(tb->actual_clock_speed)) * 1000000ul;
	if (freq <= 0xfffffffful)
		dt_add_property_cells(cpu, "clock-frequency", freq);
	dt_add_property_cells(cpu, "ibm,extended-clock-frequency",
			      hi32(freq), lo32(freq));

	/* FIXME: Hardcoding is bad. */
	dt_add_property_cells(cpu, "timebase-frequency", 512000000);
	dt_add_property_cells(cpu, "ibm,extended-timebase-frequency",
			      0, 512000000);

	dt_add_property_cells(cpu, "reservation-granule-size",
			      be32_to_cpu(cache->reservation_size));

	dt_add_property_cells(cpu, "d-tlb-size",
			      be32_to_cpu(cache->dtlb_entries));
	dt_add_property_cells(cpu, "i-tlb-size",
			      be32_to_cpu(cache->itlb_entries));
	/* Assume unified TLB */
	dt_add_property_cells(cpu, "tlb-size",
			      be32_to_cpu(cache->dtlb_entries));
	dt_add_property_cells(cpu, "d-tlb-sets",
			      be32_to_cpu(cache->dtlb_assoc_sets));
	dt_add_property_cells(cpu, "i-tlb-sets",
			      be32_to_cpu(cache->itlb_assoc_sets));
	dt_add_property_cells(cpu, "tlb-sets",
			      be32_to_cpu(cache->dtlb_assoc_sets));

	dt_add_property_cells(cpu, "d-cache-block-size",
			      be32_to_cpu(cache->dcache_block_size));
	dt_add_property_cells(cpu, "i-cache-block-size",
			      be32_to_cpu(cache->icache_block_size));
	dt_add_property_cells(cpu, "d-cache-size",
			      be32_to_cpu(cache->l1_dcache_size_kb)*1024);
	dt_add_property_cells(cpu, "i-cache-size",
			      be32_to_cpu(cache->icache_size_kb)*1024);
	dt_add_property_cells(cpu, "i-cache-sets",
			      be32_to_cpu(cache->icache_assoc_sets));
	dt_add_property_cells(cpu, "d-cache-sets",
			      be32_to_cpu(cache->dcache_assoc_sets));

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cells(cpu, "i-cache-line-size",
				      be32_to_cpu(cache->icache_line_size));
	if (cache->l1_dcache_line_size != cache->dcache_block_size)
		dt_add_property_cells(cpu, "d-cache-line-size",
				      be32_to_cpu(cache->l1_dcache_line_size));
	return cpu;
}

void add_core_attr(struct dt_node *cpu, uint32_t attr)
{
	if (attr & CPU_ATTR_UNIFIED_PL1)
		dt_add_property(cpu, "cache-unified", NULL, 0);
	if (attr & CPU_ATTR_SPLIT_TLB)
		dt_add_property(cpu, "tlb-split", NULL, 0);
	if (attr & CPU_ATTR_TLBIA)
		dt_add_property(cpu, "tlbia", NULL, 0);
	if (attr & CPU_ATTR_PERF_MONITOR)
		dt_add_property_cells(cpu, "performance-monitor", 0, 1);
	if (attr & CPU_ATTR_EXTERN_CONT)
		dt_add_property(cpu, "external-control", NULL, 0);
}

static struct dt_node *create_cache_node(struct dt_node *cpus,
					 const struct sppcia_cpu_cache *cache,
					 const char *name, uint32_t unit_addr,
					 int okay)
{
	struct dt_node *node;

	node = dt_new_addr(cpus, name, unit_addr);
	assert(node);

	dt_add_property_string(node, "device_type", "cache");
	dt_add_property_cells(node, "reg", unit_addr);
	dt_add_property_string(node, "status", okay ? "okay" : "bad");
	dt_add_property(node, "cache-unified", NULL, 0);

	/* Assume cache associavitity sets is same for L2, L3 and L3.5 */
	dt_add_property_cells(node, "d-cache-sets",
			      be32_to_cpu(cache->l2_cache_assoc_sets));
	dt_add_property_cells(node, "i-cache-sets",
			      be32_to_cpu(cache->l2_cache_assoc_sets));

	return node;
}

static struct dt_node *l35_cache_node(struct dt_node *cpus,
				      const struct sppcia_cpu_cache *cache,
				      uint32_t unit_addr, int okay)
{
	struct dt_node *node;

	node = create_cache_node(cpus, cache, "l35-cache", unit_addr, okay);

	dt_add_property_cells(node, "d-cache-size",
			      be32_to_cpu(cache->l35_dcache_size_kb) * 1024);
	dt_add_property_cells(node, "i-cache-size",
			      be32_to_cpu(cache->l35_dcache_size_kb) * 1024);

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cells(node, "i-cache-line-size",
				      be32_to_cpu(cache->icache_line_size));
	if (cache->l35_cache_line_size != cache->dcache_block_size)
		dt_add_property_cells(node, "d-cache-line-size",
				      be32_to_cpu(cache->l35_cache_line_size));

	return node;
}

static struct dt_node *l3_cache_node(struct dt_node *cpus,
				     const struct sppcia_cpu_cache *cache,
				     uint32_t unit_addr, int okay)
{
	struct dt_node *node;

	node = create_cache_node(cpus, cache, "l3-cache", unit_addr, okay);

	dt_add_property_cells(node, "d-cache-size",
			      be32_to_cpu(cache->l3_dcache_size_kb) * 1024);
	dt_add_property_cells(node, "i-cache-size",
			      be32_to_cpu(cache->l3_dcache_size_kb) * 1024);

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cells(node, "i-cache-line-size",
				      be32_to_cpu(cache->icache_line_size));
	if (cache->l3_line_size != cache->dcache_block_size)
		dt_add_property_cells(node, "d-cache-line-size",
				      be32_to_cpu(cache->l3_line_size));

	return node;
}

static struct dt_node *l2_cache_node(struct dt_node *cpus,
				     const struct sppcia_cpu_cache *cache,
				     uint32_t unit_addr, int okay)
{
	struct dt_node *node;

	node = create_cache_node(cpus, cache, "l2-cache", unit_addr, okay);

	dt_add_property_cells(node, "d-cache-size",
			      be32_to_cpu(cache->l2_dcache_size_kb) * 1024);
	dt_add_property_cells(node, "i-cache-size",
			      be32_to_cpu(cache->l2_dcache_size_kb) * 1024);

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cells(node, "i-cache-line-size",
				      be32_to_cpu(cache->icache_line_size));
	if (cache->l2_line_size != cache->dcache_block_size)
		dt_add_property_cells(node, "d-cache-line-size",
				      be32_to_cpu(cache->l2_line_size));

	return node;
}

uint32_t add_core_cache_info(struct dt_node *cpus,
			     const struct sppcia_cpu_cache *cache,
			     uint32_t int_server, int okay)
{
	struct dt_node *l2_node, *l3_node, *l35_node;
	uint32_t unit_addr;

	/* Use Processor Interrupt Line to genarate cache unit address */
	unit_addr = 0x20 << 24 | int_server;
	l2_node = l2_cache_node(cpus, cache, unit_addr, okay);

	unit_addr = 0x30 << 24 | int_server;
	l3_node = l3_cache_node(cpus, cache, unit_addr, okay);
	/* Represents the next level of cache in the memory hierarchy */
	dt_add_property_cells(l2_node, "l2-cache", l3_node->phandle);

	if (be32_to_cpu(cache->l35_dcache_size_kb)) {
		unit_addr = 0x35 << 24 | int_server;
		l35_node = l35_cache_node(cpus, cache, unit_addr, okay);
		dt_add_property_cells(l3_node, "l2-cache", l35_node->phandle);
	}

	return l2_node->phandle;
}
