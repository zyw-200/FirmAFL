/* Copyright 2013-2015 IBM Corp.
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
#include <nx.h>

void nx_create_rng_node(struct dt_node *node)
{
	u64 bar, cfg;
	u64 xbar, xcfg;
	u32 pb_base;
	u32 gcid;
	u64 rng_addr, rng_len, len, addr_mask;
	struct dt_node *rng;
	int rc;

	gcid = dt_get_chip_id(node);
	pb_base = dt_get_address(node, 0, NULL);

	if (dt_node_is_compatible(node, "ibm,power7-nx")) {
		xbar = pb_base + NX_P7_RNG_BAR;
		xcfg = pb_base + NX_P7_RNG_CFG;
		addr_mask = NX_P7_RNG_BAR_ADDR;
	} else if (dt_node_is_compatible(node, "ibm,power8-nx")) {
		xbar = pb_base + NX_P8_RNG_BAR;
		xcfg = pb_base + NX_P8_RNG_CFG;
		addr_mask = NX_P8_RNG_BAR_ADDR;
	} else {
		prerror("NX%d: Unknown NX type!\n", gcid);
		return;
	}

	rc = xscom_read(gcid, xbar, &bar); /* Get RNG BAR */
	if (rc)
		return;	/* Hope xscom always prints error message */

	rc = xscom_read(gcid, xcfg, &cfg); /* Get RNG CFG */
	if (rc)
		return;

	/*
	 * We mask in-place rather than using GETFIELD for the base address
	 * as we happen to *know* that it's properly aligned in the register.
	 *
	 * FIXME? Always assusme BAR gets a valid address from FSP
	 */
	rng_addr = bar & addr_mask;
	len  = GETFIELD(NX_RNG_BAR_SIZE, bar);
	if (len > 4) {
		prerror("NX%d: Corrupted bar size %lld\n", gcid, len);
		return;
	}
	rng_len = (u64[]){  0x1000,         /* 4K */
			    0x10000,        /* 64K */
			    0x400000000UL,    /* 16G*/
			    0x100000,       /* 1M */
			    0x1000000       /* 16M */} [len];


	prlog(PR_INFO, "NX%d: RNG BAR set to 0x%016llx..0x%016llx\n",
	      gcid, rng_addr, rng_addr + rng_len - 1);

	/* RNG must be enabled before MMIO is enabled */
	rc = xscom_write(gcid, xcfg, cfg | NX_RNG_CFG_ENABLE);
	if (rc)
		return;

	/* The BAR needs to be enabled too */
	rc = xscom_write(gcid, xbar, bar | NX_RNG_BAR_ENABLE);
	if (rc)
		return;
	rng = dt_new_addr(dt_root, "hwrng", rng_addr);
	if (!rng)
		return;

	dt_add_property_strings(rng, "compatible", "ibm,power-rng");
	dt_add_property_cells(rng, "reg", hi32(rng_addr), lo32(rng_addr),
			      hi32(rng_len), lo32(rng_len));
	dt_add_property_cells(rng, "ibm,chip-id", gcid);
}
