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

#ifndef __PHB3_H
#define __PHB3_H

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

/*
 * Interrupt map.
 *
 * Each PHB supports 2K interrupt sources, which is shared by
 * LSI and MSI. With default configuration, MSI would use range
 * [0, 0x7f7] and LSI would use [0x7f8, 0x7ff]. The interrupt
 * source should be combined with IRSN to form final hardware
 * IRQ.
 */
#define PHB3_MSI_IRQ_MIN		0x000
#define PHB3_MSI_IRQ_COUNT		0x7F8
#define PHB3_MSI_IRQ_MAX		(PHB3_MSI_IRQ_MIN+PHB3_MSI_IRQ_COUNT-1)
#define PHB3_LSI_IRQ_MIN		(PHB3_MSI_IRQ_COUNT)
#define PHB3_LSI_IRQ_COUNT		8
#define PHB3_LSI_IRQ_MAX		(PHB3_LSI_IRQ_MIN+PHB3_LSI_IRQ_COUNT-1)

#define PHB3_MSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB3_MSI_IRQ_MIN)
#define PHB3_LSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB3_LSI_IRQ_MIN)
#define PHB3_IRQ_NUM(irq)		(irq & 0x7FF)

/*
 * LSI interrupts
 *
 * The LSI interrupt block supports 8 interrupts. 4 of them are the
 * standard PCIe INTA..INTB. The rest is for additional functions
 * of the PHB
 */
#define PHB3_LSI_PCIE_INTA		0
#define PHB3_LSI_PCIE_INTB		1
#define PHB3_LSI_PCIE_INTC		2
#define PHB3_LSI_PCIE_INTD		3
#define PHB3_LSI_PCIE_INF		6
#define PHB3_LSI_PCIE_ER		7

/*
 * In-memory tables
 *
 * PHB3 requires a bunch of tables to be in memory instead of
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

/* IVT Table : MSI Interrupt vectors * state.
 *
 * We're sure that simics has 16-bytes IVE, totally 32KB.
 * However the real HW possiblly has 128-bytes IVE, totally 256KB.
 */
#define IVT_TABLE_ENTRIES	0x800

/* Default to 128-bytes IVEs, uncomment that to force it back to 16-bytes */
//#define IVT_TABLE_IVE_16B

#ifdef IVT_TABLE_IVE_16B
#define IVT_TABLE_SIZE		0x8000
#define IVT_TABLE_STRIDE	2		/* double-words */
#else
#define IVT_TABLE_SIZE		0x40000
#define IVT_TABLE_STRIDE	16		/* double-words */
#endif

/* PELT-V Table : 8KB - Maps PE# to PE# dependencies
 *
 * 256 entries of 256 bits (32 bytes) each
 */
#define PELTV_TABLE_SIZE	0x2000

/* PEST Table : 4KB - PE state table
 *
 * 256 entries of 16 bytes each containing state bits for each PE
 *
 * AFAIK: This acts as a backup for an on-chip cache and shall be
 * accessed via the indirect IODA table access registers only
 */
#define PEST_TABLE_SIZE		0x1000

/* RBA Table : 256 bytes - Reject Bit Array
 *
 * 2048 interrupts, 1 bit each, indiates the reject state of interrupts
 */
#define RBA_TABLE_SIZE		0x100

/*
 * Maximal supported PE# in PHB3. We probably probe it from EEH
 * capability register later.
 */
#define PHB3_MAX_PE_NUM		256
#define PHB3_RESERVED_PE_NUM	255

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
enum phb3_state {
	/* First init state */
	PHB3_STATE_UNINITIALIZED,

	/* During PHB HW inits */
	PHB3_STATE_INITIALIZING,

	/* Set if the PHB is for some reason unusable */
	PHB3_STATE_BROKEN,

	/* PHB fenced */
	PHB3_STATE_FENCED,

	/* Normal PHB functional state */
	PHB3_STATE_FUNCTIONAL,
};

/*
 * PHB3 PCI slot state. When you're going to apply any
 * changes here, please make sure the base state isn't
 * conflicting with those defined in pci-slot.h
 */
#define PHB3_SLOT_NORMAL			0x00000000
#define PHB3_SLOT_LINK				0x00000100
#define   PHB3_SLOT_LINK_START			0x00000101
#define   PHB3_SLOT_LINK_WAIT_ELECTRICAL	0x00000102
#define   PHB3_SLOT_LINK_WAIT			0x00000103
#define PHB3_SLOT_HRESET			0x00000200
#define   PHB3_SLOT_HRESET_START		0x00000201
#define   PHB3_SLOT_HRESET_DELAY		0x00000202
#define   PHB3_SLOT_HRESET_DELAY2		0x00000203
#define PHB3_SLOT_FRESET			0x00000300
#define   PHB3_SLOT_FRESET_START		0x00000301
#define PHB3_SLOT_PFRESET			0x00000400
#define   PHB3_SLOT_PFRESET_START		0x00000401
#define   PHB3_SLOT_PFRESET_ASSERT_DELAY	0x00000402
#define   PHB3_SLOT_PFRESET_DEASSERT_DELAY	0x00000403
#define PHB3_SLOT_CRESET			0x00000500
#define   PHB3_SLOT_CRESET_START		0x00000501
#define   PHB3_SLOT_CRESET_WAIT_CQ		0x00000502
#define   PHB3_SLOT_CRESET_REINIT		0x00000503
#define   PHB3_SLOT_CRESET_FRESET		0x00000504

/*
 * PHB3 error descriptor. Errors from all components (PBCQ, PHB)
 * will be cached to PHB3 instance. However, PBCQ errors would
 * have higher priority than those from PHB
 */
#define PHB3_ERR_SRC_NONE	0
#define PHB3_ERR_SRC_PBCQ	1
#define PHB3_ERR_SRC_PHB	2

#define PHB3_ERR_CLASS_NONE	0
#define PHB3_ERR_CLASS_DEAD	1
#define PHB3_ERR_CLASS_FENCED	2
#define PHB3_ERR_CLASS_ER	3
#define PHB3_ERR_CLASS_INF	4
#define PHB3_ERR_CLASS_LAST	5

struct phb3_err {
	uint32_t err_src;
	uint32_t err_class;
	uint32_t err_bit;
};

/* Link timeouts, increments of 100ms */
#define PHB3_LINK_WAIT_RETRIES		20
#define PHB3_LINK_ELECTRICAL_RETRIES	20

/* PHB3 flags */
#define PHB3_AIB_FENCED		0x00000001
#define PHB3_CFG_USE_ASB	0x00000002
#define PHB3_CFG_BLOCKED	0x00000004
#define PHB3_CAPP_RECOVERY	0x00000008

struct phb3 {
	unsigned int		index;	    /* 0..2 index inside P8 */
	unsigned int		flags;
	unsigned int		chip_id;    /* Chip ID (== GCID on P8) */
	enum phb3_state		state;
	unsigned int		rev;        /* 00MMmmmm */
#define PHB3_REV_MURANO_DD10	0xa30001
#define PHB3_REV_VENICE_DD10	0xa30002
#define PHB3_REV_MURANO_DD20	0xa30003
#define PHB3_REV_MURANO_DD21	0xa30004
#define PHB3_REV_VENICE_DD20	0xa30005
#define PHB3_REV_NAPLES_DD10	0xb30001
	void			*regs;
	uint64_t		pe_xscom;   /* XSCOM bases */
	uint64_t		pci_xscom;
	uint64_t		spci_xscom;
	uint64_t		mm0_base;    /* Full MM window to PHB */
	uint64_t		mm0_size;    /* '' '' '' */
	uint64_t		mm1_base;    /* Full MM window to PHB */
	uint64_t		mm1_size;    /* '' '' '' */
	uint32_t		base_msi;
	uint32_t		base_lsi;

	/* SkiBoot owned in-memory tables */
	uint64_t		tbl_rtt;
	uint64_t		tbl_peltv;
	uint64_t		tbl_pest;
	uint64_t		tbl_ivt;
	uint64_t		tbl_rba;

	bool			skip_perst; /* Skip first perst */
	bool			has_link;
	int64_t			ecap;	    /* cached PCI-E cap offset */
	int64_t			aercap;	    /* cached AER ecap offset */
	const __be64		*lane_eq;
	unsigned int		max_link_speed;

	uint16_t		rte_cache[RTT_TABLE_ENTRIES];
	uint8_t			peltv_cache[PELTV_TABLE_SIZE];
	uint64_t		lxive_cache[8];
	uint64_t		ive_cache[IVT_TABLE_ENTRIES];
	uint64_t		tve_cache[512];
	uint64_t		m32d_cache[256];
	uint64_t		m64b_cache[16];
	uint64_t		nfir_cache;	/* Used by complete reset */
	bool			err_pending;
	struct phb3_err		err;

	struct phb		phb;
};

#define PHB3_IS_NAPLES(p) ((p)->rev == PHB3_REV_NAPLES_DD10)

/*
 * Venice/Murano have one CAPP unit, that can be attached to PHB0,1 or 2.
 * Naples has two CAPP units: CAPP0 attached to PHB0, CAPP1 attached to PHB1.
 */
#define PHB3_CAPP_MAX_PHB_INDEX(p) (PHB3_IS_NAPLES(p) ? 1 : 2)

#define PHB3_CAPP_REG_OFFSET(p) \
	((p)->index && PHB3_IS_NAPLES(p) ? CAPP1_REG_OFFSET : 0x0)

static inline struct phb3 *phb_to_phb3(struct phb *phb)
{
	return container_of(phb, struct phb3, phb);
}

static inline uint64_t phb3_read_reg_asb(struct phb3 *p, uint64_t offset)
{
	uint64_t val;

	xscom_write(p->chip_id, p->spci_xscom, offset);
	xscom_read(p->chip_id, p->spci_xscom + 0x2, &val);

	return val;
}

static inline void phb3_write_reg_asb(struct phb3 *p,
				      uint64_t offset, uint64_t val)
{
	xscom_write(p->chip_id, p->spci_xscom, offset);
	xscom_write(p->chip_id, p->spci_xscom + 0x2, val);
}

static inline bool phb3_err_pending(struct phb3 *p)
{
	return p->err_pending;
}

static inline void phb3_set_err_pending(struct phb3 *p, bool pending)
{
	if (!pending) {
		p->err.err_src   = PHB3_ERR_SRC_NONE;
		p->err.err_class = PHB3_ERR_CLASS_NONE;
		p->err.err_bit   = -1;
	}

	p->err_pending = pending;
}

#endif /* __PHB3_H */
