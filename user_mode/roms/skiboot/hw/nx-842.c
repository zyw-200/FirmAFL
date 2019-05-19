/* Copyright 2015 IBM Corp.
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
#include <chip.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>

/* Configuration settings */
#define CFG_842_FC_ENABLE	(0x1f) /* enable all 842 functions */
#define CFG_842_ENABLE		(1) /* enable 842 engines */
#define DMA_COMPRESS_PREFETCH	(1) /* enable prefetching (on P8) */
#define DMA_DECOMPRESS_PREFETCH	(1) /* enable prefetching (on P8) */
#define DMA_COMPRESS_MAX_RR	(15) /* range 1-15 */
#define DMA_DECOMPRESS_MAX_RR	(15) /* range 1-15 */
#define DMA_SPBC		(1) /* write SPBC in CPB */
#define DMA_CSB_WR		NX_DMA_CSB_WR_CI
#define DMA_COMPLETION_MODE	NX_DMA_COMPLETION_MODE_CI
#define DMA_CPB_WR		NX_DMA_CPB_WR_CI_PAD
#define DMA_OUTPUT_DATA_WR	NX_DMA_OUTPUT_DATA_WR_CI
#define EE_1			(1) /* enable engine 842 1 */
#define EE_0			(1) /* enable engine 842 0 */

static int nx_cfg_842(u32 gcid, u64 xcfg)
{
	u64 cfg, ci, ct;
	int rc, instance = gcid + 1;

	BUILD_ASSERT(MAX_CHIPS < NX_842_CFG_CI_MAX);

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc)
		return rc;

	ct = GETFIELD(NX_842_CFG_CT, cfg);
	if (!ct)
		prlog(PR_INFO, "NX%d:   842 CT set to %u\n", gcid, NX_CT_842);
	else if (ct == NX_CT_842)
		prlog(PR_INFO, "NX%d:   842 CT already set to %u\n",
		      gcid, NX_CT_842);
	else
		prlog(PR_INFO, "NX%d:   842 CT already set to %u, "
		      "changing to %u\n", gcid, (unsigned int)ct, NX_CT_842);
	ct = NX_CT_842;
	cfg = SETFIELD(NX_842_CFG_CT, cfg, ct);

	/* Coprocessor Instance must be shifted left.
	 * See hw doc Section 5.5.1.
	 */
	ci = GETFIELD(NX_842_CFG_CI, cfg) >> NX_842_CFG_CI_LSHIFT;
	if (!ci)
		prlog(PR_INFO, "NX%d:   842 CI set to %d\n", gcid, instance);
	else if (ci == instance)
		prlog(PR_INFO, "NX%d:   842 CI already set to %u\n", gcid,
		      (unsigned int)ci);
	else
		prlog(PR_INFO, "NX%d:   842 CI already set to %u, "
		      "changing to %d\n", gcid, (unsigned int)ci, instance);
	ci = instance;
	cfg = SETFIELD(NX_842_CFG_CI, cfg, ci << NX_842_CFG_CI_LSHIFT);

	/* Enable all functions */
	cfg = SETFIELD(NX_842_CFG_FC_ENABLE, cfg, CFG_842_FC_ENABLE);

	cfg = SETFIELD(NX_842_CFG_ENABLE, cfg, CFG_842_ENABLE);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: 842 CT %u CI %u config failure %d\n",
			gcid, (unsigned int)ct, (unsigned int)ci, rc);
	else
		prlog(PR_DEBUG, "NX%d:   842 Config 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

static int nx_cfg_dma(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc)
		return rc;

	if (proc_gen == proc_gen_p8) {
		cfg = SETFIELD(NX_P8_DMA_CFG_842_COMPRESS_PREFETCH, cfg,
			       DMA_COMPRESS_PREFETCH);
		cfg = SETFIELD(NX_P8_DMA_CFG_842_DECOMPRESS_PREFETCH, cfg,
			       DMA_DECOMPRESS_PREFETCH);
	}

	cfg = SETFIELD(NX_DMA_CFG_842_COMPRESS_MAX_RR, cfg,
		       DMA_COMPRESS_MAX_RR);
	cfg = SETFIELD(NX_DMA_CFG_842_DECOMPRESS_MAX_RR, cfg,
		       DMA_DECOMPRESS_MAX_RR);
	cfg = SETFIELD(NX_DMA_CFG_842_SPBC, cfg,
		       DMA_SPBC);
	cfg = SETFIELD(NX_DMA_CFG_842_CSB_WR, cfg,
		       DMA_CSB_WR);
	cfg = SETFIELD(NX_DMA_CFG_842_COMPLETION_MODE, cfg,
		       DMA_COMPLETION_MODE);
	cfg = SETFIELD(NX_DMA_CFG_842_CPB_WR, cfg,
		       DMA_CPB_WR);
	cfg = SETFIELD(NX_DMA_CFG_842_OUTPUT_DATA_WR, cfg,
		       DMA_OUTPUT_DATA_WR);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: DMA config failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   DMA 0x%016lx\n", gcid,
		      (unsigned long)cfg);

	return rc;
}

static int nx_cfg_ee(u32 gcid, u64 xcfg)
{
	u64 cfg;
	int rc;

	rc = xscom_read(gcid, xcfg, &cfg);
	if (rc)
		return rc;

	cfg = SETFIELD(NX_EE_CFG_CH1, cfg, EE_1);
	cfg = SETFIELD(NX_EE_CFG_CH0, cfg, EE_0);

	rc = xscom_write(gcid, xcfg, cfg);
	if (rc)
		prerror("NX%d: ERROR: Engine Enable failure %d\n", gcid, rc);
	else
		prlog(PR_DEBUG, "NX%d:   Engine Enable 0x%016lx\n",
		      gcid, (unsigned long)cfg);

	return rc;
}

void nx_create_842_node(struct dt_node *node)
{
	u32 gcid;
	u32 pb_base;
	u64 cfg_dma, cfg_842, cfg_ee;
	int rc;

	gcid = dt_get_chip_id(node);
	pb_base = dt_get_address(node, 0, NULL);

	prlog(PR_INFO, "NX%d: 842 at 0x%x\n", gcid, pb_base);

	if (dt_node_is_compatible(node, "ibm,power7-nx")) {
		cfg_dma = pb_base + NX_P7_DMA_CFG;
		cfg_842 = pb_base + NX_P7_842_CFG;
		cfg_ee = pb_base + NX_P7_EE_CFG;
	} else if (dt_node_is_compatible(node, "ibm,power8-nx")) {
		cfg_dma = pb_base + NX_P8_DMA_CFG;
		cfg_842 = pb_base + NX_P8_842_CFG;
		cfg_ee = pb_base + NX_P8_EE_CFG;
	} else {
		prerror("NX%d: ERROR: Unknown NX type!\n", gcid);
		return;
	}

	rc = nx_cfg_dma(gcid, cfg_dma);
	if (rc)
		return;

	rc = nx_cfg_842(gcid, cfg_842);
	if (rc)
		return;

	rc = nx_cfg_ee(gcid, cfg_ee);
	if (rc)
		return;

	prlog(PR_INFO, "NX%d: 842 Coprocessor Enabled\n", gcid);

	dt_add_property_cells(node, "ibm,842-coprocessor-type", NX_CT_842);
	dt_add_property_cells(node, "ibm,842-coprocessor-instance", gcid + 1);
}
