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

#ifndef __P7IOC_H
#define __P7IOC_H

#include <cec.h>
#include <pci.h>

#include <ccan/container_of/container_of.h>

/*
 * Memory windows and BUID assignment
 *
 * - GX BAR assignment
 *
 *   I don't know of any spec here, so we're going to mimmic what
 *   OPAL seems to be doing:
 *
 *     - BAR 0 :   32M, disabled. We just leave it alone.
 *     - BAR 1 :    8G, enabled. Appears to correspond to the MMIO
 *                      space of the IOC itself and the PCI IO space
 *     - BAR 2:   128G,
 *     - BAR 3:   128G,
 *     - BAR 4:   128G, all 3 contiguous, forming a single 368G region
 *                      and is used for M32 and M64 PHB windows.
 *
 * - Memory map
 *
 *    MWIN1 = BAR1 (8G)
 *    MWIN2 = BAR2,3,4 (384G)
 *
 *    MWIN2 is divided into 6 * 4G regions for use by M32's (*) and
 *    6 * 32G regions for use by M64's.
 *
 * (*) The M32 will typically be configured to only 2G or so, however
 *     the OS is in control of that setting, and since we have to reserve
 *     a power of two, we reserve the whole 4G.
 *
 *    - RGC registers: MWIN1 + 0x00000000
 *    - PHBn IO space: MWIN1 + 0x01000000 + n * 0x00800000 (8M each)
 *    - PHBn M32     : MWIN2 + n * 0x1_00000000 (4G each)
 *    - PHBn M64     : MWIN2 + (n + 1) * 0x8_00000000 (32G each)
 *
 * - BUID map. The RGC has interrupts, each PHB has then its own
 *             interrupts (errors etc...), 4 LSIs and 256 LSIs so
 *             respectively 1 BUID for self, 1 for LSIs and 16 for LSIs
 *
 *   We keep all BUIDs below 0x10 reserved. They will be used for things
 *   like the PSI controller, the NX unit, etc.. in the P7 chip.
 *
 *    RGC	: 0x010
 *    PHBn LSI	: 0x040 + n * 0x40 (   1 BUID)
 *    PHBn MSI  : 0x060 + n * 0x40 (0x10 BUIDs)
 *
 * -> For routing, each PHB gets a block of 0x40 BUIDs:
 *
 *	from 0x40 * (n + 1) to 0x7f * (n + 1)
 */

/* Some definitions resulting from the above description
 *
 * Note: A better approach might be to read the GX BAR content
 *       and isolate the biggest contiguous windows. From there
 *       we could divide things algorithmically and thus be
 *       less sensitive to a change in the memory map by the FSP
 */
#define MWIN1_SIZE	0x200000000ul	/* MWIN1 is 8G */
#define MWIN2_SIZE     0x6000000000ul	/* MWIN2 is 384G */
#define PHB_IO_OFFSET	 0x01000000ul	/* Offset of PHB IO space in MWIN1 */
#define PHB_IO_SIZE	 0x00800000ul
#define PHB_M32_OFFSET	        0x0ul	/* Offset of PHB M32 space in MWIN2 */
#define PHB_M32_SIZE	0x100000000ul
#define PHB_M64_OFFSET	0x800000000ul	/* Offset of PHB M64 space in MWIN2 */
#define PHB_M64_SIZE	0x800000000ul
#define RGC_BUID_OFFSET		0x10	/* Offset of RGC BUID */
#define PHB_BUID_OFFSET		0x40	/* Offset of PHB BUID blocks */
#define PHB_BUID_SIZE		0x40	/* Size of PHB BUID blocks */
#define PHB_BUID_LSI_OFFSET	0x00	/* Offset of LSI in PHB BUID block */
#define PHB_BUID_MSI_OFFSET	0x20	/* Offset of MSI in PHB BUID block */
#define PHB_BUID_MSI_SIZE	0x10	/* Size of PHB MSI BUID block */

#define PHBn_IO_BASE(n)		(PHB_IO_OFFSET + (n) * PHB_IO_SIZE)
#define PHBn_M32_BASE(n)	(PHB_M32_OFFSET + (n) * PHB_M32_SIZE)
#define PHBn_M64_BASE(n)	(PHB_M64_OFFSET + (n) * PHB_M64_SIZE)
#define PHBn_BUID_BASE(n)	(PHB_BUID_OFFSET + (n) * PHB_BUID_SIZE)

#define BUID_TO_PHB(buid)	(((buid) - PHB_BUID_OFFSET) / PHB_BUID_SIZE)

/* p7ioc has 6 PHBs */
#define P7IOC_NUM_PHBS		6

/* M32 window setting at boot:
 *
 * To allow for DMA, we need to split the 32-bit PCI address space between
 * MMIO and DMA. For now, we use a 2G/2G split with MMIO at the top.
 *
 * Note: The top 64K of the M32 space are used by MSIs. This is not
 * visible here but need to be conveyed to the OS one way or another
 *
 * Note2: The space reserved in the system address space for M32 is always
 * 4G. That we chose to use a smaller portion of it is not relevant to
 * the upper levels. To keep things consistent, the offset we apply to
 * the window start is also applied on the host side.
 */
#define M32_PCI_START	0x80000000
#define M32_PCI_SIZE	0x80000000

/* PHB registers exist in both a hard coded space and a programmable
 * AIB space. We program the latter to the values recommended in the
 * documentation:
 *
 *	0x80000 + n * 0x10000
 */
#define PHBn_ASB_BASE(n)	(((n) << 16))
#define PHBn_ASB_SIZE		0x10000ul
#define PHBn_AIB_BASE(n)	(0x80000ul + ((n) << 16))
#define PHBn_AIB_SIZE		0x10000ul

/*
 * LSI interrupts
 *
 * The LSI interrupt block supports 8 interrupts. 4 of them are the
 * standard PCIe INTA..INTB. The rest is for additional functions
 * of the PHB
 */
#define PHB_LSI_PCIE_INTA		0
#define PHB_LSI_PCIE_INTB		1
#define PHB_LSI_PCIE_INTC		2
#define PHB_LSI_PCIE_INTD		3
#define PHB_LSI_PCIE_HOTPLUG		4
#define PHB_LSI_PCIE_PERFCTR		5
#define PHB_LSI_PCIE_UNUSED		6
#define PHB_LSI_PCIE_ERROR		7

/*
 * State structure for a PHB on P7IOC
 */

/*
 * The PHB State structure is essentially used during PHB reset
 * or recovery operations to indicate that the PHB cannot currently
 * be used for normal operations.
 *
 * Some states involve waiting for the timebase to reach a certain
 * value. In which case the field "delay_tgt_tb" is set and the
 * state machine will be run from the "state_poll" callback.
 *
 * At IPL time, we call this repeatedly during the various sequences
 * however under OS control, this will require a change in API.
 *
 * Fortunately, the OPAL API for slot power & reset are not currently
 * used by Linux, so changing them isn't going to be an issue. The idea
 * here is that some of these APIs will return a positive integer when
 * needing such a delay to proceed. The OS will then be required to
 * call a new function opal_poll_phb() after that delay. That function
 * will potentially return a new delay, or OPAL_SUCCESS when the original
 * operation has completed successfully. If the operation has completed
 * with an error, then opal_poll_phb() will return that error.
 *
 * Note: Should we consider also returning optionally some indication
 * of what operation is in progress for OS debug/diag purposes ?
 *
 * Any attempt at starting a new "asynchronous" operation while one is
 * already in progress will result in an error.
 *
 * Internally, this is represented by the state being P7IOC_PHB_STATE_FUNCTIONAL
 * when no operation is in progress, which it reaches at the end of the
 * boot time initializations. Any attempt at performing a slot operation
 * on a PHB in that state will change the state to the corresponding
 * operation state machine. Any attempt while not in that state will
 * return an error.
 *
 * Some operations allow for a certain amount of retries, this is
 * provided for by the "retries" structure member for use by the state
 * machine as it sees fit.
 */
enum p7ioc_phb_state {
	/* First init state */
	P7IOC_PHB_STATE_UNINITIALIZED,

	/* During PHB HW inits */
	P7IOC_PHB_STATE_INITIALIZING,

	/* Set if the PHB is for some reason unusable */
	P7IOC_PHB_STATE_BROKEN,

	/* Set if the PHB is fenced due to an error */
	P7IOC_PHB_STATE_FENCED,

	/* PHB turned off by FSP (no clocks) */
	P7IOC_PHB_STATE_OFF,

	/* Normal PHB functional state */
	P7IOC_PHB_STATE_FUNCTIONAL,
};

/* P7IOC PHB slot states */
#define P7IOC_SLOT_NORMAL		0x00000000
#define P7IOC_SLOT_LINK			0x00000100
#define   P7IOC_SLOT_LINK_START		0x00000101
#define   P7IOC_SLOT_LINK_WAIT		0x00000102
#define P7IOC_SLOT_HRESET		0x00000200
#define   P7IOC_SLOT_HRESET_START	0x00000201
#define   P7IOC_SLOT_HRESET_TRAINING	0x00000202
#define   P7IOC_SLOT_HRESET_DELAY	0x00000203
#define   P7IOC_SLOT_HRESET_DELAY2	0x00000204
#define P7IOC_SLOT_FRESET		0x00000300
#define   P7IOC_SLOT_FRESET_START	0x00000301
#define   P7IOC_SLOT_FRESET_TRAINING	0x00000302
#define   P7IOC_SLOT_FRESET_POWER_OFF	0x00000303
#define   P7IOC_SLOT_FRESET_POWER_ON	0x00000304
#define   P7IOC_SLOT_FRESET_ASSERT	0x00000305
#define   P7IOC_SLOT_FRESET_DEASSERT	0x00000306
#define P7IOC_SLOT_PFRESET		0x00000400
#define   P7IOC_SLOT_PFRESET_START	0x00000401
#define P7IOC_SLOT_CRESET		0x00000500
#define   P7IOC_SLOT_CRESET_START	0x00000501

/*
 * In order to support error detection and recovery on different
 * types of IOCs (e.g. P5IOC, P7IOC, P8IOC), the best bet would
 * be make the implementation to be 2 layers: OPAL layer and IOC
 * layer. The OPAL layer just handles the general information and
 * IOC layer should process much more detailed information, which
 * is sensitive to itself.
 */
#define P7IOC_ERR_SRC_NONE	0
#define P7IOC_ERR_SRC_EI	1
#define P7IOC_ERR_SRC_RGC	2
#define P7IOC_ERR_SRC_BI_UP	3
#define P7IOC_ERR_SRC_BI_DOWN	4
#define P7IOC_ERR_SRC_CI_P0	5
#define P7IOC_ERR_SRC_CI_P1	6
#define P7IOC_ERR_SRC_CI_P2	7
#define P7IOC_ERR_SRC_CI_P3	8
#define P7IOC_ERR_SRC_CI_P4	9
#define P7IOC_ERR_SRC_CI_P5	10
#define P7IOC_ERR_SRC_CI_P6	11
#define P7IOC_ERR_SRC_CI_P7	12
#define P7IOC_ERR_SRC_PHB0	13
#define P7IOC_ERR_SRC_PHB1	14
#define P7IOC_ERR_SRC_PHB2	15
#define P7IOC_ERR_SRC_PHB3	16
#define P7IOC_ERR_SRC_PHB4	17
#define P7IOC_ERR_SRC_PHB5	18
#define P7IOC_ERR_SRC_MISC	19
#define P7IOC_ERR_SRC_I2C	20
#define P7IOC_ERR_SRC_LAST	21

#define P7IOC_ERR_CLASS_NONE	0
#define P7IOC_ERR_CLASS_GXE	1
#define P7IOC_ERR_CLASS_PLL	2
#define P7IOC_ERR_CLASS_RGA	3
#define P7IOC_ERR_CLASS_PHB	4
#define P7IOC_ERR_CLASS_ER	5
#define P7IOC_ERR_CLASS_INF	6
#define P7IOC_ERR_CLASS_MAL	7
#define P7IOC_ERR_CLASS_LAST	8

/*
 * P7IOC error descriptor. For errors from PHB and PE, they
 * will be cached to the corresponding PHBs. However, the
 * left errors (e.g. EI, CI Port0/1) will be cached to the
 * IOC directly.
 */
struct p7ioc_err {
	uint32_t err_src;
	uint32_t err_class;
	uint32_t err_bit;
};

struct p7ioc;

#define P7IOC_PHB_CFG_USE_ASB	0x00000001 /* ASB to access PCI-CFG     */
#define P7IOC_PHB_CFG_BLOCKED	0x00000002 /* PCI-CFG blocked except 0	*/

struct p7ioc_phb {
	uint8_t				index;	/* 0..5 index inside p7ioc */
	uint8_t				gen;
	uint32_t			flags;
	enum p7ioc_phb_state		state;
#define P7IOC_REV_DD10	0x00a20001
#define P7IOC_REV_DD11	0x00a20002
	uint32_t			rev;	/* Both major and minor have 2 bytes */
	void				*regs_asb;
	void				*regs;	/* AIB regs */
	uint32_t			buid_lsi;
	uint32_t			buid_msi;
	uint64_t			io_base;
	uint64_t			m32_base;
	uint64_t			m64_base;
	int64_t				ecap;	/* cached PCI-E cap offset */
	int64_t				aercap; /* cached AER ecap offset */
	uint64_t			lxive_cache[8];
	uint64_t			mxive_cache[256];
	uint64_t			mve_cache[256];
	uint64_t			peltm_cache[128];
	uint64_t			peltv_lo_cache[128];
	uint64_t			peltv_hi_cache[128];
	uint64_t			tve_lo_cache[128];
	uint64_t			tve_hi_cache[128];
	uint64_t			iod_cache[128];
	uint64_t			m32d_cache[128];
	uint64_t			m64b_cache[16];
	uint64_t			m64d_cache[128];
	bool				err_pending;
	struct p7ioc_err		err;
	struct p7ioc			*ioc;
	struct phb			phb;
};

static inline struct p7ioc_phb *phb_to_p7ioc_phb(struct phb *phb)
{
	return container_of(phb, struct p7ioc_phb, phb);
}

static inline bool p7ioc_phb_err_pending(struct p7ioc_phb *p)
{
	return p->err_pending;
}

static inline void p7ioc_phb_set_err_pending(struct p7ioc_phb *p, bool pending)
{
	if (!pending) {
		p->err.err_src   = P7IOC_ERR_SRC_NONE;
		p->err.err_class = P7IOC_ERR_CLASS_NONE;
		p->err.err_bit   = -1;
	}

	p->err_pending = pending;
}

/*
 * State structure for P7IOC IO HUB
 */
struct p7ioc {
	/* Device node */
	struct dt_node			*dt_node;

	/* MMIO regs */
	void				*regs;

	/* Main MMIO window from GX for registers & PCI IO space */
	uint64_t			mmio1_win_start;
	uint64_t			mmio1_win_size;

	/* Secondary MMIO window for PCI MMIO space */
	uint64_t			mmio2_win_start;
	uint64_t			mmio2_win_size;

	/* BUID base for the PHB. This does include the top bits
	 * (chip, GX bus ID, etc...). This is initialized from the
	 * SPIRA. It does not contain the offset 0x10 for RGC
	 * interrupts.
	 *
	 * The OPAL-defined "interrupt-base" property will contain
	 * the RGC BUID, not this base value, since this is the real
	 * starting point of interrupts for the IOC and we don't want
	 * to cover the BUID 0..f gap which is reserved for P7 on-chip
	 * interrupt sources.
	 */
	uint32_t			buid_base;
	uint32_t			rgc_buid;

	/* XIVT cache for RGC interrupts */
	uint64_t			xive_cache[16];
	bool				err_pending;
	struct p7ioc_err		err;

	/* PHB array & presence detect */
	struct p7ioc_phb		phbs[P7IOC_NUM_PHBS];
	uint8_t				phb_pdt;
	   
	struct io_hub			hub;
};

static inline struct p7ioc *iohub_to_p7ioc(struct io_hub *hub)
{
	return container_of(hub, struct p7ioc, hub);
}

static inline bool p7ioc_err_pending(struct p7ioc *ioc)
{
	return ioc->err_pending;
}

static inline void p7ioc_set_err_pending(struct p7ioc *ioc, bool pending)
{
	if (!pending) {
		ioc->err.err_src   = P7IOC_ERR_SRC_NONE;
		ioc->err.err_class = P7IOC_ERR_CLASS_NONE;
		ioc->err.err_bit   = -1;
	}

	ioc->err_pending = pending;
}

static inline bool p7ioc_phb_enabled(struct p7ioc *ioc, unsigned int phb)
{
	return !!(ioc->phb_pdt & (0x80 >> phb));
}

extern int64_t p7ioc_inits(struct p7ioc *ioc);

extern void p7ioc_phb_setup(struct p7ioc *ioc, uint8_t index);
extern int64_t p7ioc_phb_init(struct p7ioc_phb *p);

extern bool p7ioc_check_LEM(struct p7ioc *ioc, uint16_t *pci_error_type,
			    uint16_t *severity);
extern int64_t p7ioc_phb_get_xive(struct p7ioc_phb *p, uint32_t isn,
				  uint16_t *server, uint8_t *prio);
extern int64_t p7ioc_phb_set_xive(struct p7ioc_phb *p, uint32_t isn,
				  uint16_t server, uint8_t prio);
extern void p7ioc_reset(struct io_hub *hub);
extern void p7ioc_phb_reset(struct phb *phb);

#endif /* __P7IOC_H */
