/* Copyright 2013-2016 IBM Corp.
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

/*
*/
#ifndef __PHB4_H
#define __PHB4_H

#include <interrupts.h>

/*
 * Memory map
 *
 * In addition to the 4K MMIO registers window, the PBCQ will
 * forward down one or two large MMIO regions for use by the
 * PHB.
 *
 * We try to use the largest MMIO window for the M64 space and
 * the smallest for the M32 space, but we require at least 2G
 * of M32, otherwise we carve it out of M64.
 */

#define M32_PCI_START		0x080000000	/* Offset of the actual M32 window in PCI */
#define M32_PCI_SIZE		0x80000000ul	/* Size for M32 */

#if 0
/*
 * Interrupt map.
 *
 * Each PHB supports 2K interrupt sources, which is shared by
 * LSI and MSI. With default configuration, MSI would use range
 * [0, 0x7f7] and LSI would use [0x7f8, 0x7ff]. The interrupt
 * source should be combined with IRSN to form final hardware
 * IRQ.
 */
#define PHB4_MSI_IRQ_MIN		0x000
#define PHB4_MSI_IRQ_COUNT		0x7F8
#define PHB4_MSI_IRQ_MAX		(PHB4_MSI_IRQ_MIN+PHB4_MSI_IRQ_COUNT-1)
#define PHB4_LSI_IRQ_MIN		(PHB4_MSI_IRQ_COUNT)
#define PHB4_LSI_IRQ_COUNT		8
#define PHB4_LSI_IRQ_MAX		(PHB4_LSI_IRQ_MIN+PHB4_LSI_IRQ_COUNT-1)

#define PHB4_MSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB4_MSI_IRQ_MIN)
#define PHB4_LSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB4_LSI_IRQ_MIN)
#define PHB4_IRQ_NUM(irq)		(irq & 0x7FF)

#endif

/*
 * LSI interrupts
 *
 * The LSI interrupt block supports 8 interrupts. 4 of them are the
 * standard PCIe INTA..INTB. The rest is for additional functions
 * of the PHB
 */
#define PHB4_LSI_PCIE_INTA		0
#define PHB4_LSI_PCIE_INTB		1
#define PHB4_LSI_PCIE_INTC		2
#define PHB4_LSI_PCIE_INTD		3
#define PHB4_LSI_PCIE_INF		6
#define PHB4_LSI_PCIE_ER		7

/*
 * In-memory tables
 *
 * PHB4 requires a bunch of tables to be in memory instead of
 * arrays inside the chip (unlike previous versions of the
 * design).
 *
 * Some of them (IVT, etc...) will be provided by the OS via an
 * OPAL call, not only not all of them, we also need to make sure
 * some like PELT-V exist before we do our internal slot probing
 * or bad thing would happen on error (the whole PHB would go into
 * Fatal error state).
 *
 * So we maintain a set of tables internally for those mandatory
 * ones within our core memory. They are fairly small. They can
 * still be replaced by OS provided ones via OPAL APIs (and reset
 * to the internal ones) so the OS can provide node local allocation
 * for better performances.
 *
 * All those tables have to be naturally aligned
 */

/* RTT Table : 128KB - Maps RID to PE# 
 *
 * Entries are 2 bytes indexed by PCIe RID
 */
#define RTT_TABLE_ENTRIES	0x10000
#define RTT_TABLE_SIZE		0x20000
#define PELTV_TABLE_SIZE_MAX	0x20000

#define PHB4_RESERVED_PE_NUM(p)	((p)->num_pes - 1)
/*
 * State structure for a PHB
 */

/*
 * (Comment copied from p7ioc.h, please update both when relevant)
 *
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
 * neededing such a delay to proceed. The OS will then be required to
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
enum phb4_state {
	/* First init state */
	PHB4_STATE_UNINITIALIZED,

	/* During PHB HW inits */
	PHB4_STATE_INITIALIZING,

	/* Set if the PHB is for some reason unusable */
	PHB4_STATE_BROKEN,

	/* PHB fenced */
	PHB4_STATE_FENCED,

	/* Normal PHB functional state */
	PHB4_STATE_FUNCTIONAL,
};

/*
 * PHB4 PCI slot state. When you're going to apply any
 * changes here, please make sure the base state isn't
 * conflicting with those defined in pci-slot.h
 */
#define PHB4_SLOT_NORMAL			0x00000000
#define PHB4_SLOT_LINK				0x00000100
#define   PHB4_SLOT_LINK_START			0x00000101
#define   PHB4_SLOT_LINK_WAIT_ELECTRICAL	0x00000102
#define   PHB4_SLOT_LINK_WAIT			0x00000103
#define PHB4_SLOT_HRESET			0x00000200
#define   PHB4_SLOT_HRESET_START		0x00000201
#define   PHB4_SLOT_HRESET_DELAY		0x00000202
#define   PHB4_SLOT_HRESET_DELAY2		0x00000203
#define PHB4_SLOT_FRESET			0x00000300
#define   PHB4_SLOT_FRESET_START		0x00000301
#define PHB4_SLOT_PFRESET			0x00000400
#define   PHB4_SLOT_PFRESET_START		0x00000401
#define   PHB4_SLOT_PFRESET_ASSERT_DELAY	0x00000402
#define   PHB4_SLOT_PFRESET_DEASSERT_DELAY	0x00000403
#define PHB4_SLOT_CRESET			0x00000500
#define   PHB4_SLOT_CRESET_START		0x00000501
#define   PHB4_SLOT_CRESET_WAIT_CQ		0x00000502
#define   PHB4_SLOT_CRESET_REINIT		0x00000503
#define   PHB4_SLOT_CRESET_FRESET		0x00000504

/*
 * PHB4 error descriptor. Errors from all components (PBCQ, PHB)
 * will be cached to PHB4 instance. However, PBCQ errors would
 * have higher priority than those from PHB
 */
#define PHB4_ERR_SRC_NONE	0
#define PHB4_ERR_SRC_PBCQ	1
#define PHB4_ERR_SRC_PHB	2

#define PHB4_ERR_CLASS_NONE	0
#define PHB4_ERR_CLASS_DEAD	1
#define PHB4_ERR_CLASS_FENCED	2
#define PHB4_ERR_CLASS_ER	3
#define PHB4_ERR_CLASS_INF	4
#define PHB4_ERR_CLASS_LAST	5

struct phb4_err {
	uint32_t err_src;
	uint32_t err_class;
	uint32_t err_bit;
};

/* Link timeouts, increments of 100ms */
#define PHB4_LINK_WAIT_RETRIES		20
#define PHB4_LINK_ELECTRICAL_RETRIES	20

/* PHB4 flags */
#define PHB4_AIB_FENCED		0x00000001
#define PHB4_CFG_USE_ASB	0x00000002
#define PHB4_CFG_BLOCKED	0x00000004
#define PHB4_CAPP_RECOVERY	0x00000008

struct phb4 {
	unsigned int		index;	    /* 0..2 index inside P8 */
	unsigned int		flags;
	unsigned int		chip_id;    /* Chip ID (== GCID on P8) */
	enum phb4_state		state;
	unsigned int		rev;        /* 00MMmmmm */
#define PHB4_REV_MURANO_DD10	0xa30001
#define PHB4_REV_VENICE_DD10	0xa30002
#define PHB4_REV_MURANO_DD20	0xa30003
#define PHB4_REV_MURANO_DD21	0xa30004
#define PHB4_REV_VENICE_DD20	0xa30005
#define PHB4_REV_NAPLES_DD10	0xb30001
	void			*regs;
	void			*int_mmio;
	uint64_t		pe_xscom;   /* XSCOM bases */
	uint64_t		pe_stk_xscom;
	uint64_t		pci_xscom;
	uint64_t		pci_stk_xscom;
	uint64_t		etu_xscom;
	struct lock		lock;
	uint64_t		mm0_base;    /* Full MM window to PHB */
	uint64_t		mm0_size;    /* '' '' '' */
	uint64_t		mm1_base;    /* Full MM window to PHB */
	uint64_t		mm1_size;    /* '' '' '' */
	uint32_t		base_msi;
	uint32_t		base_lsi;
	uint64_t		irq_port;
	uint32_t		num_pes;
	uint32_t		max_num_pes;
	uint32_t		num_irqs;

	/* SkiBoot owned in-memory tables */
	uint64_t		tbl_rtt;
	uint64_t		tbl_peltv;
	uint64_t		tbl_peltv_size;
	uint64_t		tbl_pest;
	uint64_t		tbl_pest_size;

	bool			skip_perst; /* Skip first perst */
	bool			has_link;
	int64_t			ecap;	    /* cached PCI-E cap offset */
	int64_t			aercap;	    /* cached AER ecap offset */
	const __be64		*lane_eq;
	unsigned int		max_link_speed;

	uint64_t		mrt_size;
	uint64_t		mbt_size;
	uint64_t		tvt_size;

	uint16_t		rte_cache[RTT_TABLE_ENTRIES];
	/* FIXME: dynamically allocate only what's needed below */
	uint64_t		tve_cache[1024];
	uint8_t			peltv_cache[PELTV_TABLE_SIZE_MAX];
	uint64_t		mbt_cache[32][2];
	uint64_t		mdt_cache[512]; /* max num of PEs */
	uint64_t		mist_cache[4096/4];/* max num of MSIs */
	uint64_t		nfir_cache;	/* Used by complete reset */
	bool			err_pending;
	struct phb4_err		err;

	/* Cache some RC registers that need to be emulated */
	uint32_t		rc_cache[4];

	struct phb		phb;
};

static inline struct phb4 *phb_to_phb4(struct phb *phb)
{
	return container_of(phb, struct phb4, phb);
}

static inline bool phb4_err_pending(struct phb4 *p)
{
	return p->err_pending;
}

static inline void phb4_set_err_pending(struct phb4 *p, bool pending)
{
	if (!pending) {
		p->err.err_src   = PHB4_ERR_SRC_NONE;
		p->err.err_class = PHB4_ERR_CLASS_NONE;
		p->err.err_bit   = -1;
	}

	p->err_pending = pending;
}

#endif /* __PHB4_H */
