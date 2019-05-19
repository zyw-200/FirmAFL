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
#include <p7ioc.h>
#include <p7ioc-regs.h>
#include <io.h>
#include <timebase.h>
#include <affinity.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <interrupts.h>
#include <opal.h>
#include <ccan/str/str.h>

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB#%04x: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB#%04x: " fmt, \
				      (p)->phb.opal_id, ## a)

/* Helper to select an IODA table entry */
static inline void p7ioc_phb_ioda_sel(struct p7ioc_phb *p, uint32_t table,
				      uint32_t addr, bool autoinc)
{
	out_be64(p->regs + PHB_IODA_ADDR,
		 (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

static bool p7ioc_phb_fenced(struct p7ioc_phb *p)
{
	struct p7ioc *ioc = p->ioc;
	uint64_t fence, fbits;

	fbits = 0x0003000000000000UL >> (p->index * 4);
	fence = in_be64(ioc->regs + P7IOC_CHIP_FENCE_SHADOW);

	return (fence & fbits) != 0;
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t p7ioc_pcicfg_check(struct p7ioc_phb *p, uint32_t bdfn,
				  uint32_t offset, uint32_t size)
{
	uint32_t sm = size - 1;

	if (offset > 0xfff || bdfn > 0xffff)
		return OPAL_PARAMETER;
	if (offset & sm)
		return OPAL_PARAMETER;

	/* The root bus only has a device at 0 and we get into an
	 * error state if we try to probe beyond that, so let's
	 * avoid that and just return an error to Linux
	 */
	if ((bdfn >> 8) == 0 && (bdfn & 0xff))
		return OPAL_HARDWARE;

	/* Check PHB state */
	if (p->state == P7IOC_PHB_STATE_BROKEN)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

#define P7IOC_PCI_CFG_READ(size, type)	\
static int64_t p7ioc_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
				       uint32_t offset, type *data)	\
{									\
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);			\
	uint64_t addr;							\
	void *base = p->regs;						\
	int64_t rc;							\
									\
	/* Initialize data in case of error */				\
	*data = (type)0xffffffff;					\
									\
	rc = p7ioc_pcicfg_check(p, bdfn, offset, sizeof(type));		\
	if (rc)								\
		return rc;						\
									\
	if (p7ioc_phb_fenced(p)) {					\
		if (!(p->flags & P7IOC_PHB_CFG_USE_ASB))		\
			return OPAL_HARDWARE;				\
									\
		base = p->regs_asb;					\
	} else if ((p->flags & P7IOC_PHB_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	addr = PHB_CA_ENABLE;						\
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);			\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	out_be64(base + PHB_CONFIG_ADDRESS, addr);			\
	*data = in_le##size(base + PHB_CONFIG_DATA +			\
		     (offset & (4 - sizeof(type))));			\
									\
	return OPAL_SUCCESS;						\
}

#define P7IOC_PCI_CFG_WRITE(size, type)	\
static int64_t p7ioc_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
					uint32_t offset, type data)	\
{									\
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);			\
	void *base = p->regs;						\
	uint64_t addr;							\
	int64_t rc;							\
									\
	rc = p7ioc_pcicfg_check(p, bdfn, offset, sizeof(type));		\
	if (rc)								\
		return rc;						\
									\
	if (p7ioc_phb_fenced(p)) {					\
		if (!(p->flags & P7IOC_PHB_CFG_USE_ASB))		\
			return OPAL_HARDWARE;				\
									\
		base = p->regs_asb;					\
	} else if ((p->flags & P7IOC_PHB_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	addr = PHB_CA_ENABLE;						\
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);			\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	out_be64(base + PHB_CONFIG_ADDRESS, addr);			\
	out_le##size(base + PHB_CONFIG_DATA +				\
		     (offset & (4 - sizeof(type))), data);		\
									\
	return OPAL_SUCCESS;						\
}

P7IOC_PCI_CFG_READ(8, uint8_t)
P7IOC_PCI_CFG_READ(16, uint16_t)
P7IOC_PCI_CFG_READ(32, uint32_t)
P7IOC_PCI_CFG_WRITE(8, uint8_t)
P7IOC_PCI_CFG_WRITE(16, uint16_t)
P7IOC_PCI_CFG_WRITE(32, uint32_t)

static void p7ioc_eeh_read_phb_status(struct p7ioc_phb *p,
				      struct OpalIoP7IOCPhbErrorData *stat)
{
	uint16_t tmp16;
	unsigned int i;

	memset(stat, 0, sizeof(struct OpalIoP7IOCPhbErrorData));


	/* Error data common part */
	stat->common.version = OPAL_PHB_ERROR_DATA_VERSION_1;
	stat->common.ioType  = OPAL_PHB_ERROR_DATA_TYPE_P7IOC;
	stat->common.len     = sizeof(struct OpalIoP7IOCPhbErrorData);

	/*
	 * We read some registers using config space through AIB.
	 *
	 * Get to other registers using ASB when possible to get to them
	 * through a fence if one is present.
	 *
	 * Note that the OpalIoP7IOCPhbErrorData has oddities, such as the
	 * bridge control being 32-bit and the UTL registers being 32-bit
	 * (which they really are, but they use the top 32-bit of a 64-bit
	 * register so we need to be a bit careful).
	 */

	/* Use ASB to access PCICFG if the PHB has been fenced */
	p->flags |= P7IOC_PHB_CFG_USE_ASB;

	/* Grab RC bridge control, make it 32-bit */
	p7ioc_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &tmp16);
	stat->brdgCtl = tmp16;

	/* Grab UTL status registers */
	stat->portStatusReg = hi32(in_be64(p->regs_asb
					   + UTL_PCIE_PORT_STATUS));
	stat->rootCmplxStatus = hi32(in_be64(p->regs_asb
					   + UTL_RC_STATUS));
	stat->busAgentStatus = hi32(in_be64(p->regs_asb
					   + UTL_SYS_BUS_AGENT_STATUS));

	/*
	 * Grab various RC PCIe capability registers. All device, slot
	 * and link status are 16-bit, so we grab the pair control+status
	 * for each of them
	 */
	p7ioc_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL,
			    &stat->deviceStatus);
	p7ioc_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTCTL,
			    &stat->slotStatus);
	p7ioc_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL,
			    &stat->linkStatus);

	/*
	 * I assume those are the standard config space header, cmd & status
	 * together makes 32-bit. Secondary status is 16-bit so I'll clear
	 * the top on that one
	 */
	p7ioc_pcicfg_read32(&p->phb, 0, PCI_CFG_CMD, &stat->devCmdStatus);
	p7ioc_pcicfg_read16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, &tmp16);
	stat->devSecStatus = tmp16;

	/* Grab a bunch of AER regs */
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA,
			    &stat->rootErrorStatus);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS,
			    &stat->uncorrErrorStatus);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			    &stat->corrErrorStatus);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG0,
			    &stat->tlpHdr1);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG1,
			    &stat->tlpHdr2);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG2,
			    &stat->tlpHdr3);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG3,
			    &stat->tlpHdr4);
	p7ioc_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_SRCID,
			    &stat->sourceId);

	/* Restore to AIB */
	p->flags &= ~P7IOC_PHB_CFG_USE_ASB;

	/*
	 * No idea what that that is supposed to be, opal.h says
	 * "Record data about the call to allocate a buffer."
	 *
	 * Let's leave them alone for now...
	 *
	 * uint64_t errorClass;
	 * uint64_t correlator;
	*/

	/* P7IOC MMIO Error Regs */
	stat->p7iocPlssr = in_be64(p->regs_asb + PHB_CPU_LOADSTORE_STATUS);
	stat->p7iocCsr = in_be64(p->regs_asb + PHB_DMA_CHAN_STATUS);
	stat->lemFir = in_be64(p->regs_asb + PHB_LEM_FIR_ACCUM);
	stat->lemErrorMask = in_be64(p->regs_asb + PHB_LEM_ERROR_MASK);
	stat->lemWOF = in_be64(p->regs_asb + PHB_LEM_WOF);
	stat->phbErrorStatus = in_be64(p->regs_asb + PHB_ERR_STATUS);
	stat->phbFirstErrorStatus = in_be64(p->regs_asb + PHB_ERR1_STATUS);
	stat->phbErrorLog0 = in_be64(p->regs_asb + PHB_ERR_LOG_0);
	stat->phbErrorLog1 = in_be64(p->regs_asb + PHB_ERR_LOG_1);
	stat->mmioErrorStatus = in_be64(p->regs_asb + PHB_OUT_ERR_STATUS);
	stat->mmioFirstErrorStatus = in_be64(p->regs_asb + PHB_OUT_ERR1_STATUS);
	stat->mmioErrorLog0 = in_be64(p->regs_asb + PHB_OUT_ERR_LOG_0);
	stat->mmioErrorLog1 = in_be64(p->regs_asb + PHB_OUT_ERR_LOG_1);
	stat->dma0ErrorStatus = in_be64(p->regs_asb + PHB_INA_ERR_STATUS);
	stat->dma0FirstErrorStatus = in_be64(p->regs_asb + PHB_INA_ERR1_STATUS);
	stat->dma0ErrorLog0 = in_be64(p->regs_asb + PHB_INA_ERR_LOG_0);
	stat->dma0ErrorLog1 = in_be64(p->regs_asb + PHB_INA_ERR_LOG_1);
	stat->dma1ErrorStatus = in_be64(p->regs_asb + PHB_INB_ERR_STATUS);
	stat->dma1FirstErrorStatus = in_be64(p->regs_asb + PHB_INB_ERR1_STATUS);
	stat->dma1ErrorLog0 = in_be64(p->regs_asb + PHB_INB_ERR_LOG_0);
	stat->dma1ErrorLog1 = in_be64(p->regs_asb + PHB_INB_ERR_LOG_1);

	/* Grab PESTA & B content */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PESTA, 0, true);
	for (i = 0; i < OPAL_P7IOC_NUM_PEST_REGS; i++)
		stat->pestA[i] = in_be64(p->regs_asb + PHB_IODA_DATA0);
	p7ioc_phb_ioda_sel(p, IODA_TBL_PESTB, 0, true);
	for (i = 0; i < OPAL_P7IOC_NUM_PEST_REGS; i++)
		stat->pestB[i] = in_be64(p->regs_asb + PHB_IODA_DATA0);
}

static int64_t p7ioc_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				       uint8_t *freeze_state,
				       uint16_t *pci_error_type,
				       uint16_t *severity,
				       uint64_t *phb_status)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t peev_bit = PPC_BIT(pe_number & 0x3f);
	uint64_t peev, pesta, pestb;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	/* Check dead */
	if (p->state == P7IOC_PHB_STATE_BROKEN) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_DEAD;
		goto bail;
	}

	/* Check fence */
	if (p7ioc_phb_fenced(p)) {
		/* Should be OPAL_EEH_STOPPED_TEMP_UNAVAIL ? */
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		p->state = P7IOC_PHB_STATE_FENCED;
		goto bail;
	}

	/* Check the PEEV */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (pe_number > 63)
		peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

	/* Indicate that we have an ER pending */
	p7ioc_phb_set_err_pending(p, true);
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the PESTA & PESTB */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PESTA, pe_number, false);
	pesta = in_be64(p->regs + PHB_IODA_DATA0);
	p7ioc_phb_ioda_sel(p, IODA_TBL_PESTB, pe_number, false);
	pestb = in_be64(p->regs + PHB_IODA_DATA0);

	/* Convert them */
	if (pesta & IODA_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

	/* XXX Handle more causes */
	if (pesta & IODA_PESTA_MMIO_CAUSE)
		*pci_error_type = OPAL_EEH_PE_MMIO_ERROR;
	else
		*pci_error_type = OPAL_EEH_PE_DMA_ERROR;

 bail:
	if (phb_status)
		p7ioc_eeh_read_phb_status(p, (struct OpalIoP7IOCPhbErrorData *)
					  phb_status);
	return OPAL_SUCCESS;
}

static int64_t p7ioc_eeh_next_error(struct phb *phb, uint64_t *first_frozen_pe,
				    uint16_t *pci_error_type, uint16_t *severity)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	struct p7ioc *ioc = p->ioc;
	uint64_t fir, peev0, peev1;
	uint32_t cfg32, i;

	/* Check if there're pending errors on the IOC. */
	if (p7ioc_err_pending(ioc) &&
	    p7ioc_check_LEM(ioc, pci_error_type, severity))
		return OPAL_SUCCESS;

	/* Clear result */
	*pci_error_type	= OPAL_EEH_NO_ERROR;
        *severity	= OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check dead */
	if (p->state == P7IOC_PHB_STATE_BROKEN) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	/* Check fence */
	if (p7ioc_phb_fenced(p)) {
		/* Should be OPAL_EEH_STOPPED_TEMP_UNAVAIL ? */
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		p->state = P7IOC_PHB_STATE_FENCED;
		p7ioc_phb_set_err_pending(p, false);
		return OPAL_SUCCESS;
	}

	/*
	 * If we don't have pending errors, which might be moved
	 * from IOC to the PHB, then check if there has any frozen PEs.
	 */
	if (!p7ioc_phb_err_pending(p)) {
		p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
		peev0 = in_be64(p->regs + PHB_IODA_DATA0);
		peev1 = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev0 || peev1) {
			p->err.err_src   = P7IOC_ERR_SRC_PHB0 + p->index;
			p->err.err_class = P7IOC_ERR_CLASS_ER;
			p->err.err_bit   = 0;
			p7ioc_phb_set_err_pending(p, true);
		}
	}

	/* Check the pending errors, which might come from IOC */
	if (p7ioc_phb_err_pending(p)) {
		/*
		 * If the frozen PE is caused by a malfunctioning TLP, we
		 * need reset the PHB. So convert ER to PHB-fatal error
		 * for the case.
		 */
		if (p->err.err_class == P7IOC_ERR_CLASS_ER) {
			fir = in_be64(p->regs_asb + PHB_LEM_FIR_ACCUM);
			if (fir & PPC_BIT(60)) {
				p7ioc_pcicfg_read32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_STATUS, &cfg32);
				if (cfg32 & PCIECAP_AER_UE_MALFORMED_TLP)
					p->err.err_class = P7IOC_ERR_CLASS_PHB;
                        }
                }

		/*
		 * Map P7IOC internal error class to that one OS can handle.
		 * For P7IOC_ERR_CLASS_ER, we also need figure out the frozen
		 * PE.
		 */
		switch (p->err.err_class) {
		case P7IOC_ERR_CLASS_PHB:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_FENCED;
			p7ioc_phb_set_err_pending(p, false);
			break;
		case P7IOC_ERR_CLASS_MAL:
		case P7IOC_ERR_CLASS_INF:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_INF;
			p7ioc_phb_set_err_pending(p, false);
			break;
		case P7IOC_ERR_CLASS_ER:
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;
			p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
			peev0 = in_be64(p->regs + PHB_IODA_DATA0);
			peev1 = in_be64(p->regs + PHB_IODA_DATA0);

			for (i = 0 ; i < 64; i++) {
				if (PPC_BIT(i) & peev1) {
					*first_frozen_pe = i + 64;
					break;
				}
			}
			for (i = 0 ;
			     *first_frozen_pe == (uint64_t)-1 && i < 64;
			     i++) {
				if (PPC_BIT(i) & peev0) {
					*first_frozen_pe = i;
					break;
				}
			}

			/* No frozen PE? */
			if (*first_frozen_pe == (uint64_t)-1) {
				*pci_error_type = OPAL_EEH_NO_ERROR;
				*severity = OPAL_EEH_SEV_NO_ERROR;
				p7ioc_phb_set_err_pending(p, false);
			}

			break;
		default:
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			p7ioc_phb_set_err_pending(p, false);
		}
	}

	return OPAL_SUCCESS;
}

static void p7ioc_ER_err_clear(struct p7ioc_phb *p)
{
	u64 err, lem;
	u32 val;

	/* Rec 1,2 */
	lem = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 3,4,5 AER registers (could use cfg space accessors) */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 6,7,8 XXX DOC whacks payload & req size ... we don't */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ull);
	val = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val & 0xe0700000) | 0x0f000f00);

	/* Rec 9,10,11 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 12,13,14 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 23,24,25 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 26,27,28 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 29..34 UTL registers */
	err = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, err);
	err = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, err);
	err = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, err);

	/* PHB error traps registers */
	err = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, err);
	out_be64(p->regs + PHB_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, err);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, err);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, err);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0);

	/* Rec 67, 68 LEM */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~lem);
	out_be64(p->regs + PHB_LEM_WOF, 0);
}

static int64_t p7ioc_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				      uint64_t eeh_action_token)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t peev0, peev1;

	/* XXX Now this is a heavy hammer, coming roughly from the P7IOC doc
	 * and my old "pseudopal" code. It will need to be refined. In general
	 * error handling will have to be reviewed and probably done properly
	 * "from scratch" based on the description in the p7IOC spec.
	 *
	 * XXX Additionally, when handling interrupts, we might want to consider
	 * masking while processing and/or ack'ing interrupt bits etc...
	 */
	u64 err;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitly by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err == 0)
		goto clear_pest;

	p7ioc_ER_err_clear(p);

 clear_pest:
	/* XXX We just clear the whole PESTA for MMIO clear and PESTB
	 * for DMA clear. We might want to only clear the frozen bit
	 * as to not clobber the rest of the state. However, we expect
	 * the state to have been harvested before the clear operations
	 * so this might not be an issue
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}

	/* Update ER pending indication */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
	peev0 = in_be64(p->regs + PHB_IODA_DATA0);
	peev1 = in_be64(p->regs + PHB_IODA_DATA0);
	if (peev0 || peev1) {
		p->err.err_src   = P7IOC_ERR_SRC_PHB0 + p->index;
		p->err.err_class = P7IOC_ERR_CLASS_ER;
		p->err.err_bit   = 0;
		p7ioc_phb_set_err_pending(p, true);
	} else
		p7ioc_phb_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t p7ioc_eeh_freeze_set(struct phb *phb, uint64_t pe_number,
				    uint64_t eeh_action_token)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t data;

	if (pe_number > 127)
		return OPAL_PARAMETER;

	if (eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_MMIO &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_DMA &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_ALL)
		return OPAL_PARAMETER;

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_MMIO) {
		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTA, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA_PESTA_MMIO_FROZEN;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_DMA) {
		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTB, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA_PESTB_DMA_STOPPED;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	return OPAL_SUCCESS;
}

static int64_t p7ioc_err_inject_finalize(struct p7ioc_phb *p, uint64_t addr,
					 uint64_t mask, uint64_t ctrl,
					 bool is_write)
{
	if (is_write)
		ctrl |= PHB_PAPR_ERR_INJ_CTL_WR;
	else
		ctrl |= PHB_PAPR_ERR_INJ_CTL_RD;

	/* HW100549: Take read and write for outbound errors
	 * on DD10 chip
	 */
	if (p->rev == P7IOC_REV_DD10)
		ctrl |= (PHB_PAPR_ERR_INJ_CTL_RD | PHB_PAPR_ERR_INJ_CTL_WR);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, addr);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, mask);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, ctrl);

	return OPAL_SUCCESS;
}

static int64_t p7ioc_err_inject_mem32(struct p7ioc_phb *p, uint32_t pe_no,
				      uint64_t addr, uint64_t mask,
				      bool is_write)
{
	uint64_t a, m, prefer, base;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	int32_t index;

	a = 0x0ull;
	prefer = 0x0ull;
	for (index = 0; index < 128; index++) {
		if (GETFIELD(IODA_XXDT_PE, p->m32d_cache[index]) != pe_no)
			continue;

		base = p->m32_base + M32_PCI_START +
		       (M32_PCI_SIZE / 128) * index;

		/* Update preferred address */
		if (!prefer) {
			prefer = GETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO, base);
			prefer = SETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO,
					  0x0ull, prefer);
		}

		/* The input address matches ? */
		if (addr >= base &&
		    addr < base + (M32_PCI_SIZE / 128)) {
			a = addr;
			break;
		}
	}

	/* Invalid PE number */
	if (!prefer)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (!a) {
		a = prefer;
		m = PHB_PAPR_ERR_INJ_MASK_MMIO;
	} else {
		m = mask;
	}

	return p7ioc_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t p7ioc_err_inject_io32(struct p7ioc_phb *p, uint32_t pe_no,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	uint64_t a, m, prefer, base;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	int32_t index;

	a = 0x0ull;
	prefer = 0x0ull;
	for (index = 0; index < 128; index++) {
		if (GETFIELD(IODA_XXDT_PE, p->iod_cache[index]) != pe_no)
                        continue;

		base = p->io_base + (PHB_IO_SIZE / 128) * index;

		/* Update preferred address */
		if (!prefer) {
			prefer = GETFIELD(PHB_PAPR_ERR_INJ_MASK_IO, base);
			prefer = SETFIELD(PHB_PAPR_ERR_INJ_MASK_IO, 0x0ull, prefer);
		}

		/* The input address matches ? */
		if (addr >= base &&
		    addr <  base + (PHB_IO_SIZE / 128)) {
			a = addr;
			break;
		}
	}

	/* Invalid PE number */
	if (!prefer)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (!a) {
		a = prefer;
		m = PHB_PAPR_ERR_INJ_MASK_IO;
	} else {
		m = mask;
	}

	return p7ioc_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t p7ioc_err_inject_cfg(struct p7ioc_phb *p, uint32_t pe_no,
				    uint64_t addr, uint64_t mask,
				    bool is_write)
{
	uint64_t a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_CFG;
	uint8_t v_bits, base, bus_no;

	/* Looking into PELTM to see if the PCI bus# is owned
	 * by the PE#. Otherwise, we have to figure one out.
	 */
	base = GETFIELD(IODA_PELTM_BUS, p->peltm_cache[pe_no]);
	v_bits = GETFIELD(IODA_PELTM_BUS_VALID, p->peltm_cache[pe_no]);
	switch (v_bits) {
	case IODA_BUS_VALID_3_BITS:
	case IODA_BUS_VALID_4_BITS:
	case IODA_BUS_VALID_5_BITS:
	case IODA_BUS_VALID_6_BITS:
	case IODA_BUS_VALID_7_BITS:
	case IODA_BUS_VALID_ALL:
		base = GETFIELD(IODA_PELTM_BUS, p->peltm_cache[pe_no]);
		base &= (0xff - (((1 << (7 - v_bits)) - 1)));
		a = SETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG, 0x0ul, base);
		m = PHB_PAPR_ERR_INJ_MASK_CFG;

		bus_no = GETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG, addr);
		bus_no &= (0xff - (((1 << (7 - v_bits)) - 1)));
		if (base == bus_no) {
			a = addr;
			m = mask;
		}

		break;
	case IODA_BUS_VALID_ANY:
	default:
		return OPAL_PARAMETER;
	}

	return p7ioc_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t p7ioc_err_inject_dma(struct p7ioc_phb *p, uint32_t pe_no,
				    uint64_t addr, uint64_t mask,
				    bool is_write)
{
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_INB;
	int32_t index;

	/* For DMA, we just pick address from TVT */
	for (index = 0; index < 128; index++) {
		if (GETFIELD(IODA_TVT1_PE_NUM, p->tve_hi_cache[index]) != pe_no)
			continue;

		addr = SETFIELD(PHB_PAPR_ERR_INJ_MASK_DMA, 0ul, index);
		mask = PHB_PAPR_ERR_INJ_MASK_DMA;
		break;
	}

	/* Some PE might not have DMA capability */
	if (index >= 128)
		return OPAL_PARAMETER;

	return p7ioc_err_inject_finalize(p, addr, mask, ctrl, is_write);
}

static int64_t p7ioc_err_inject(struct phb *phb, uint32_t pe_no,
				uint32_t type, uint32_t func,
				uint64_t addr, uint64_t mask)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	int64_t (*handler)(struct p7ioc_phb *p, uint32_t pe_no,
			   uint64_t addr, uint64_t mask, bool is_write);
	bool is_write;

	/* To support 64-bits error later */
	if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
		return OPAL_UNSUPPORTED;

	/* We can't inject error to the reserved PE#127 */
	if (pe_no > 126)
		return OPAL_PARAMETER;

	/* Clear the leftover from last time */
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);

	/* Check if PE number is valid one in PELTM cache */
	if (p->peltm_cache[pe_no] == 0x0001f80000000000ull)
		return OPAL_PARAMETER;

	/* Clear the leftover from last time */
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);

	switch (func) {
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_DATA:
		is_write = false;
		handler = p7ioc_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_DATA:
		is_write = true;
		handler = p7ioc_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_LD_IO_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_IO_DATA:
		is_write = false;
		handler = p7ioc_err_inject_io32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_IO_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_IO_DATA:
		is_write = true;
		handler = p7ioc_err_inject_io32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_DATA:
		is_write = false;
		handler = p7ioc_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_DATA:
		is_write = true;
		handler = p7ioc_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_TARGET:
		is_write = false;
		handler = p7ioc_err_inject_dma;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_TARGET:
		is_write = true;
		handler = p7ioc_err_inject_dma;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return handler(p, pe_no, addr, mask, is_write);
}

static int64_t p7ioc_get_diag_data(struct phb *phb, void *diag_buffer,
				   uint64_t diag_buffer_len)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	struct OpalIoP7IOCPhbErrorData *diag = diag_buffer;

	if (diag_buffer_len < sizeof(struct OpalIoP7IOCPhbErrorData))
		return OPAL_PARAMETER;

	/* Specific error data */
	p7ioc_eeh_read_phb_status(p, diag);

	/*
	 * We're running to here probably because of errors (MAL
	 * or INF class) from IOC. For the case, we need clear
	 * the pending errors and mask the error bit for MAL class
	 * error. Fortunately, we shouldn't get MAL class error from
	 * IOC on P7IOC.
	 */
	if (p7ioc_phb_err_pending(p)			&&
	    p->err.err_class == P7IOC_ERR_CLASS_INF	&&
	    p->err.err_src >= P7IOC_ERR_SRC_PHB0	&&
	    p->err.err_src <= P7IOC_ERR_SRC_PHB5) {
		p7ioc_ER_err_clear(p);
		p7ioc_phb_set_err_pending(p, false);
	}

	return OPAL_SUCCESS;
}

/*
 * We don't support address remapping now since all M64
 * BARs are sharing on remapping base address. We might
 * introduce flag to the PHB in order to trace that. The
 * flag allows to be changed for once. It's something to
 * do in future.
 */
static int64_t p7ioc_set_phb_mem_window(struct phb *phb,
                                        uint16_t window_type,
                                        uint16_t window_num,
                                        uint64_t base,
                                        uint64_t __unused pci_base,
                                        uint64_t size)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t data64;

	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;
		/* The base and size should be 16MB aligned */
		if (base & 0xFFFFFF || size & 0xFFFFFF)
			return OPAL_PARAMETER;
		data64 = p->m64b_cache[window_num];
		data64 = SETFIELD(IODA_M64BT_BASE, data64, base >> 24);
		size = (size >> 24);
		data64 = SETFIELD(IODA_M64BT_MASK, data64, 0x1000000 - size);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * If the M64 BAR hasn't enabled yet, we needn't flush
	 * the setting to hardware and just keep it to the cache
	 */
	p->m64b_cache[window_num] = data64;
	if (!(data64 & IODA_M64BT_ENABLE))
		return OPAL_SUCCESS;
	p7ioc_phb_ioda_sel(p, IODA_TBL_M64BT, window_num, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);

	return OPAL_SUCCESS;
}

/*
 * We can't enable or disable I/O and M32 dynamically, even
 * unnecessary. So the function only support M64 BARs.
 */
static int64_t p7ioc_phb_mmio_enable(struct phb *phb,
				     uint16_t window_type,
				     uint16_t window_num,
				     uint16_t enable)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t data64, base, mask;

	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16 ||
		    enable >= OPAL_ENABLE_M64_NON_SPLIT)
			return OPAL_PARAMETER;

		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * While enabling one specific M64 BAR, we should have
	 * the base/size configured correctly. Otherwise, it
	 * probably incurs fenced AIB.
	 */
	data64 = p->m64b_cache[window_num];
	if (enable == OPAL_ENABLE_M64_SPLIT) {
		base = GETFIELD(IODA_M64BT_BASE, data64);
		base = (base << 24);
		mask = GETFIELD(IODA_M64BT_MASK, data64);
		if (base < p->m64_base || mask == 0x0ul)
			return OPAL_PARTIAL;

		data64 |= IODA_M64BT_ENABLE;
	} else if (enable == OPAL_DISABLE_M64) {
		data64 &= ~IODA_M64BT_ENABLE;
	}

	p7ioc_phb_ioda_sel(p, IODA_TBL_M64BT, window_num, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->m64b_cache[window_num] = data64;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_map_pe_mmio_window(struct phb *phb, uint16_t pe_number,
					uint16_t window_type,
					uint16_t window_num,
					uint16_t segment_num)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t tbl, index;
	uint64_t *cache;

	if (pe_number > 127)
		return OPAL_PARAMETER;

	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
		if (window_num != 0 || segment_num > 127)
			return OPAL_PARAMETER;
		tbl = IODA_TBL_IODT;
		index = segment_num;
		cache = &p->iod_cache[index];
		break;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num > 127)
			return OPAL_PARAMETER;
		tbl = IODA_TBL_M32DT;
		index = segment_num;
		cache = &p->m32d_cache[index];
		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num > 15 || segment_num > 7)
			return OPAL_PARAMETER;

		tbl = IODA_TBL_M64DT;
		index = window_num << 3 | segment_num;
		cache = &p->m64d_cache[index];
		break;
	default:
		return OPAL_PARAMETER;
	}

	p7ioc_phb_ioda_sel(p, tbl, index, false);
	out_be64(p->regs + PHB_IODA_DATA0,
		 SETFIELD(IODA_XXDT_PE, 0ull, pe_number));

	/* Update cache */
	*cache = SETFIELD(IODA_XXDT_PE, 0ull, pe_number);

	return OPAL_SUCCESS;
}


static int64_t p7ioc_set_pe(struct phb *phb, uint64_t pe_number,
			    uint64_t bdfn, uint8_t bus_compare,
			    uint8_t dev_compare, uint8_t func_compare,
			    uint8_t pe_action)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t pelt;
	uint64_t *cache = &p->peltm_cache[pe_number];

	if (pe_number > 127 || bdfn > 0xffff)
		return OPAL_PARAMETER;
	if (pe_action != OPAL_MAP_PE && pe_action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (bus_compare > 7)
		return OPAL_PARAMETER;

	if (pe_action == OPAL_MAP_PE) {
		pelt  = SETFIELD(IODA_PELTM_BUS, 0ul, bdfn >> 8);
		pelt |= SETFIELD(IODA_PELTM_DEV, 0ul, (bdfn >> 3) & 0x1f);
		pelt |= SETFIELD(IODA_PELTM_FUNC, 0ul, bdfn & 0x7);
		pelt |= SETFIELD(IODA_PELTM_BUS_VALID, 0ul, bus_compare);
		if (dev_compare)
			pelt |= IODA_PELTM_DEV_VALID;
		if (func_compare)
			pelt |= IODA_PELTM_FUNC_VALID;
	} else
		pelt = 0;

	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTM, pe_number, false);
	out_be64(p->regs + PHB_IODA_DATA0, pelt);

	/* Update cache */
	*cache = pelt;

	return OPAL_SUCCESS;
}


static int64_t p7ioc_set_peltv(struct phb *phb, uint32_t parent_pe,
			       uint32_t child_pe, uint8_t state)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint32_t reg;
	uint64_t mask, peltv;
	uint64_t *cache;
	if (parent_pe > 127 || child_pe > 127)
		return OPAL_PARAMETER;

	cache = (child_pe >> 6) ? &p->peltv_hi_cache[parent_pe] :
		&p->peltv_lo_cache[parent_pe];
	reg = (child_pe >> 6) ? PHB_IODA_DATA1 : PHB_IODA_DATA0;
	child_pe &= 0x2f;
	mask = 1ull << (63 - child_pe);

	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTV, parent_pe, false);
	peltv = in_be64(p->regs + reg);
	if (state)
		peltv |= mask;
	else
		peltv &= ~mask;
	out_be64(p->regs + reg, peltv);

	/* Update cache */
	*cache = peltv;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_map_pe_dma_window(struct phb *phb, uint16_t pe_number,
				       uint16_t window_id, uint16_t tce_levels,
				       uint64_t tce_table_addr,
				       uint64_t tce_table_size,
				       uint64_t tce_page_size)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t tvt0, tvt1, t, pelt;
	uint64_t dma_window_size;
	uint64_t *cache_lo, *cache_hi;

	if (pe_number > 127 || window_id > 127 || tce_levels != 1)
		return OPAL_PARAMETER;
	cache_lo = &p->tve_lo_cache[window_id];
        cache_hi = &p->tve_hi_cache[window_id];

	/* Encode table size */
	dma_window_size = tce_page_size * (tce_table_size >> 3);
	t = ilog2(dma_window_size);
	if (t < 27)
		return OPAL_PARAMETER;
	tvt0 = SETFIELD(IODA_TVT0_TCE_TABLE_SIZE, 0ul, (t - 26));

	/* Encode TCE page size */
	switch(tce_page_size) {
	case 0x1000:		/* 4K */
		tvt1 = SETFIELD(IODA_TVT1_IO_PSIZE, 0ul, 1ul);
		break;
	case 0x10000:		/* 64K */
		tvt1 = SETFIELD(IODA_TVT1_IO_PSIZE, 0ul, 5ul);
		break;
	case 0x1000000:		/* 16M */
		tvt1 = SETFIELD(IODA_TVT1_IO_PSIZE, 0ul, 13ul);
		break;
	case 0x400000000UL:	/* 16G */
		tvt1 = SETFIELD(IODA_TVT1_IO_PSIZE, 0ul, 23ul);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* XXX Hub number ... leave 0 for now */

	/* Shift in the address. The table address is "off by 4 bits"
	 * but since the field is itself shifted by 16, we basically
	 * need to write the address >> 12, which basically boils down
	 * to writing a 4k page address
	 */
	tvt0 = SETFIELD(IODA_TVT0_TABLE_ADDR, tvt0, tce_table_addr >> 12);

	/* Read the PE filter info from the PELT-M */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTM, pe_number, false);
	pelt = in_be64(p->regs + PHB_IODA_DATA0);

	/* Copy in filter bits from PELT */
	tvt0 = SETFIELD(IODA_TVT0_BUS_VALID, tvt0,
			GETFIELD(IODA_PELTM_BUS_VALID, pelt));
	tvt0 = SETFIELD(IODA_TVT0_BUS_NUM, tvt0,
			GETFIELD(IODA_PELTM_BUS, pelt));
	tvt1 = SETFIELD(IODA_TVT1_DEV_NUM, tvt1,
			GETFIELD(IODA_PELTM_DEV, pelt));
	tvt1 = SETFIELD(IODA_TVT1_FUNC_NUM, tvt1,
			GETFIELD(IODA_PELTM_FUNC, pelt));
	if (pelt & IODA_PELTM_DEV_VALID)
		tvt1 |= IODA_TVT1_DEV_VALID;
	if (pelt & IODA_PELTM_FUNC_VALID)
		tvt1 |= IODA_TVT1_FUNC_VALID;
	tvt1 = SETFIELD(IODA_TVT1_PE_NUM, tvt1, pe_number);

	/* Write the TVE */
	p7ioc_phb_ioda_sel(p, IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA1, tvt1);
	out_be64(p->regs + PHB_IODA_DATA0, tvt0);

	/* Update cache */
	*cache_lo = tvt0;
	*cache_hi = tvt1;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_map_pe_dma_window_real(struct phb *phb __unused,
					    uint16_t pe_number __unused,
					    uint16_t dma_window_num __unused,
					    uint64_t pci_start_addr __unused,
					    uint64_t pci_mem_size __unused)
{
	/* XXX Not yet implemented (not yet used by Linux) */
	return OPAL_UNSUPPORTED;
}

static int64_t p7ioc_set_mve(struct phb *phb, uint32_t mve_number,
			     uint32_t pe_number)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t pelt, mve = 0;
	uint64_t *cache = &p->mve_cache[mve_number];

	if (pe_number > 127 || mve_number > 255)
		return OPAL_PARAMETER;

	/* Read the PE filter info from the PELT-M */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTM, pe_number, false);
	pelt = in_be64(p->regs + PHB_IODA_DATA0);

	mve = SETFIELD(IODA_MVT_BUS_VALID, mve,
		       GETFIELD(IODA_PELTM_BUS_VALID, pelt));
	mve = SETFIELD(IODA_MVT_BUS_NUM, mve,
		       GETFIELD(IODA_PELTM_BUS, pelt));
	mve = SETFIELD(IODA_MVT_DEV_NUM, mve,
		       GETFIELD(IODA_PELTM_DEV, pelt));
	mve = SETFIELD(IODA_MVT_FUNC_NUM, mve,
		       GETFIELD(IODA_PELTM_FUNC, pelt));
	if (pelt & IODA_PELTM_DEV_VALID)
		mve |= IODA_MVT_DEV_VALID;
	if (pelt & IODA_PELTM_FUNC_VALID)
		mve |= IODA_MVT_FUNC_VALID;
	mve = SETFIELD(IODA_MVT_PE_NUM, mve, pe_number);

	p7ioc_phb_ioda_sel(p, IODA_TBL_MVT, mve_number, false);
	out_be64(p->regs + PHB_IODA_DATA0, mve);

	/* Update cache */
	*cache = mve;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_set_mve_enable(struct phb *phb, uint32_t mve_number,
				    uint32_t state)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t mve;
	uint64_t *cache = &p->mve_cache[mve_number];

	if (mve_number > 255)
		return OPAL_PARAMETER;

	p7ioc_phb_ioda_sel(p, IODA_TBL_MVT, mve_number, false);
	mve = in_be64(p->regs + PHB_IODA_DATA0);
	if (state)
		mve |= IODA_MVT_VALID;
	else
		mve &= ~IODA_MVT_VALID;
	out_be64(p->regs + PHB_IODA_DATA0, mve);

	/* Update cache */
	*cache = mve;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_set_xive_pe(struct phb *phb, uint32_t pe_number,
				 uint32_t xive_num)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	uint64_t xive;

	if (pe_number > 127 || xive_num > 255)
		return OPAL_PARAMETER;

	/* Update MXIVE cache */
	xive = p->mxive_cache[xive_num];
	xive = SETFIELD(IODA_XIVT_PENUM, xive, pe_number);
	p->mxive_cache[xive_num] = xive;

	/* Update HW */
	p7ioc_phb_ioda_sel(p, IODA_TBL_MXIVT, xive_num, false);	
	xive = in_be64(p->regs + PHB_IODA_DATA0);
	xive = SETFIELD(IODA_XIVT_PENUM, xive, pe_number);
	out_be64(p->regs + PHB_IODA_DATA0, xive);

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_xive_source(struct phb *phb, uint32_t xive_num,
				     int32_t *interrupt_source_number)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);

	if (xive_num > 255 || !interrupt_source_number)
		return OPAL_PARAMETER;

	*interrupt_source_number = (p->buid_msi << 4) | xive_num;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_msi_32(struct phb *phb __unused, uint32_t mve_number,
				uint32_t xive_num, uint8_t msi_range,
				uint32_t *msi_address, uint32_t *message_data)
{
	if (mve_number > 255 || xive_num > 255 || msi_range != 1)
		return OPAL_PARAMETER;

	*msi_address = 0xffff0000 | (mve_number << 4);
	*message_data = xive_num;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_msi_64(struct phb *phb __unused, uint32_t mve_number,
				uint32_t xive_num, uint8_t msi_range,
				uint64_t *msi_address, uint32_t *message_data)
{
	if (mve_number > 255 || xive_num > 255 || msi_range != 1)
		return OPAL_PARAMETER;

	*msi_address = (9ul << 60) | (((u64)mve_number) << 48);
	*message_data = xive_num;

	return OPAL_SUCCESS;
}

static void p7ioc_root_port_init(struct phb *phb, struct pci_device *dev,
				 int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_SERR_EN | PCI_CFG_CMD_PERR_RESP);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

        /* Mask various unrecoverable errors */
	if (!aercap) return;
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, &val32);
	val32 |= (PCIECAP_AER_UE_MASK_POISON_TLP |
		  PCIECAP_AER_UE_MASK_COMPL_TIMEOUT |
		  PCIECAP_AER_UE_MASK_COMPL_ABORT |
		  PCIECAP_AER_UE_MASK_ECRC);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, val32);

	/* Report various unrecoverable errors as fatal errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, &val32);
	val32 |= (PCIECAP_AER_UE_SEVERITY_DLLP |
		  PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
		  PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
		  PCIECAP_AER_UE_SEVERITY_UNEXP_COMPL |
		  PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
		  PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

	/* Mask various recoverable errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, &val32);
	val32 |= PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);

	/* Enable all error reporting */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, &val32);
	val32 |= (PCIECAP_AER_RERR_CMD_FE |
		  PCIECAP_AER_RERR_CMD_NFE |
		  PCIECAP_AER_RERR_CMD_CE);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, val32);
}

static void p7ioc_switch_port_init(struct phb *phb,
				   struct pci_device *dev,
				   int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking and disable INTx */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN |
		  PCI_CFG_CMD_INTx_DIS);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Disable partity error and enable system error */
	pci_cfg_read16(phb, bdfn, PCI_CFG_BRCTL, &val16);
	val16 &= ~PCI_CFG_BRCTL_PERR_RESP_EN;
	val16 |= PCI_CFG_BRCTL_SERR_EN;
	pci_cfg_write16(phb, bdfn, PCI_CFG_BRCTL, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT);
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/* Unmask all unrecoverable errors */
	if (!aercap) return;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, 0x0);

	/* Severity of unrecoverable errors */
	if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT)
		val32 = (PCIECAP_AER_UE_SEVERITY_DLLP |
			 PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
			 PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
			 PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	else
		val32 = (PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

        /* Mask various correctable errors */
	val32 = PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC generation and disable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= PCIECAP_AER_CAPCTL_ECRCG_EN;
	val32 &= ~PCIECAP_AER_CAPCTL_ECRCC_EN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void p7ioc_endpoint_init(struct phb *phb,
				struct pci_device *dev,
				int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	val16 |= (PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/* Enable ECRC generation and check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static int p7ioc_device_init(struct phb *phb,
			     struct pci_device *dev,
			     void *data __unused)
{
	int ecap = 0;
	int aercap = 0;

	/* Figure out AER capability */
	if (pci_has_cap(dev, PCI_CFG_CAP_ID_EXP, false)) {
		ecap = pci_cap(dev, PCI_CFG_CAP_ID_EXP, false);

		if (!pci_has_cap(dev, PCIECAP_ID_AER, true)) {
			aercap = pci_find_ecap(phb, dev->bdfn,
					       PCIECAP_ID_AER, NULL);
			if (aercap > 0)
				pci_set_cap(dev, PCIECAP_ID_AER, aercap, true);
		} else {
			aercap = pci_cap(dev, PCIECAP_ID_AER, true);
		}
	}

	/* Common initialization for the device */
	pci_device_init(phb, dev);

	if (dev->dev_type == PCIE_TYPE_ROOT_PORT)
		p7ioc_root_port_init(phb, dev, ecap, aercap);
	else if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT ||
		dev->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		p7ioc_switch_port_init(phb, dev, ecap, aercap);
	else
		p7ioc_endpoint_init(phb, dev, ecap, aercap);

	return 0;
}

static int64_t p7ioc_pci_reinit(struct phb *phb,
				uint64_t scope, uint64_t data)
{
	struct pci_device *pd;
	uint16_t bdfn = data;
	int ret;

	if (scope != OPAL_REINIT_PCI_DEV)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	ret = p7ioc_device_init(phb, pd, NULL);
	if (ret)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

static uint8_t p7ioc_choose_bus(struct phb *phb __unused,
				struct pci_device *bridge,
				uint8_t candidate, uint8_t *max_bus,
				bool *use_max)
{
	uint8_t m, al;
	int i;	

	/* Bus number selection is nasty on P7IOC. Our EEH HW can only cope
	 * with bus ranges that are naturally aligned powers of two. It also
	 * has "issues" with dealing with more than 32 bus numbers.
	 *
	 * On the other hand we can deal with overlaps to some extent as
	 * the PELT-M entries are ordered.
	 *
	 * We also don't need to bother with the busses between the upstream
	 * and downstream ports of switches.
	 *
	 * For now we apply this simple mechanism which matche what OFW does
	 * under OPAL:
	 *
	 * - Top level bus (PHB to RC) is 0
	 * - RC to first device is 1..ff
	 * - Then going down, a switch gets (N = parent bus, M = parent max)
	 *       * Upstream bridge is N+1, M, use_max = false
	 *       * Downstream bridge is closest power of two from 32 down and
	 *       * use max
	 *
	 * XXX NOTE: If we have access to HW VPDs, we could know whether
	 * this is a bridge with a single device on it such as IPR and
	 * limit ourselves to a single bus number.
	 */

	/* Default use_max is false (legacy) */
	*use_max = false;

	/* If we are the root complex or we are not in PCIe land anymore, just
	 * use legacy algorithm
	 */
	if (!bridge || !pci_has_cap(bridge, PCI_CFG_CAP_ID_EXP, false))
		return candidate;

	/* Figure out the bridge type */
	switch(bridge->dev_type) {
	case PCIE_TYPE_PCIX_TO_PCIE:
		/* PCI-X to PCIE ... hrm, let's not bother too much with that */
		return candidate;
	case PCIE_TYPE_SWITCH_UPPORT:
	case PCIE_TYPE_ROOT_PORT:
		/* Upstream port, we use legacy handling as well */
		return candidate;
	case PCIE_TYPE_SWITCH_DNPORT:
	case PCIE_TYPE_PCIE_TO_PCIX:
		/* That leaves us with the interesting cases that we handle */
		break;
	default:
		/* Should not happen, treat as legacy */
		prerror("PCI: Device %04x has unsupported type %d in choose_bus\n",
			bridge->bdfn, bridge->dev_type);
		return candidate;
	}

	/* Ok, let's find a power of two that fits, fallback to 1 */
	for (i = 5; i >= 0; i--) {
		m = (1 << i) - 1;
		al = (candidate + m) & ~m;
		if (al <= *max_bus && (al + m) <= *max_bus)
			break;
	}
	if (i < 0)
		return 0;
	*use_max = true;
	*max_bus = al + m;
	return al;
}

static int64_t p7ioc_get_reserved_pe_number(struct phb *phb __unused)
{
	return 127;
}

/* p7ioc_phb_init_ioda_cache - Reset the IODA cache values
 */
static void p7ioc_phb_init_ioda_cache(struct p7ioc_phb *p)
{
	unsigned int i;

	for (i = 0; i < 8; i++)
		p->lxive_cache[i] = SETFIELD(IODA_XIVT_PRIORITY, 0ull, 0xff);
	for (i = 0; i < 256; i++) {
		p->mxive_cache[i] = SETFIELD(IODA_XIVT_PRIORITY, 0ull, 0xff);
		p->mve_cache[i]   = 0;
	}
	for (i = 0; i < 16; i++)
		p->m64b_cache[i] = 0;

	/*
	 * Since there is only one root port under the PHB,
	 * We make all PELTM entries except last one to be
	 * invalid by configuring their RID to 00:00.1. The
	 * last entry is to encompass all RIDs.
	 */
	for (i = 0; i < 127; i++)
		p->peltm_cache[i] = 0x0001f80000000000UL;
	p->peltm_cache[127] = 0x0ul;

	for (i = 0; i < 128; i++) {
		p->peltv_lo_cache[i]	= 0;
		p->peltv_hi_cache[i]	= 0;
		p->tve_lo_cache[i]	= 0;
		p->tve_hi_cache[i]	= 0;
		p->iod_cache[i]		= 0;
		p->m32d_cache[i]	= 0;
		p->m64d_cache[i]	= 0;
	}
}

/* p7ioc_phb_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t p7ioc_ioda_reset(struct phb *phb, bool purge)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	unsigned int i;
	uint64_t reg64;
	uint64_t data64, data64_hi;
	uint8_t prio;
	uint16_t server;
	uint64_t m_server, m_prio;

	/* If the "purge" argument is set, we clear the table cache */
	if (purge)
		p7ioc_phb_init_ioda_cache(p);

	/* Init_18..19: Setup the HRT
	 *
	 * XXX NOTE: I still don't completely get that HRT business so
	 * I'll just mimmic BML and put the PHB number + 1 in there
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_HRT, 0, true);
	out_be64(p->regs + PHB_IODA_DATA0, p->index + 1);
	out_be64(p->regs + PHB_IODA_DATA0, p->index + 1);
	out_be64(p->regs + PHB_IODA_DATA0, p->index + 1);
	out_be64(p->regs + PHB_IODA_DATA0, p->index + 1);

	/* Init_20..21: Cleanup the LXIVT
	 *
	 * We set the priority to FF (masked) and clear everything
	 * else. That means we leave the HRT index to 0 which is
	 * going to remain unmodified... for now.
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_LXIVT, 0, true);
	for (i = 0; i < 8; i++) {
		data64 = p->lxive_cache[i];
		server = GETFIELD(IODA_XIVT_SERVER, data64);
		prio = GETFIELD(IODA_XIVT_PRIORITY, data64);

		/* Now we mangle the server and priority */
		if (prio == 0xff) {
			m_server = 0;
			m_prio = 0xff;
		} else {
			m_server = server >> 3;
			m_prio = (prio >> 3) | ((server & 7) << 5);
		}

		data64 = SETFIELD(IODA_XIVT_SERVER,   data64, m_server);
		data64 = SETFIELD(IODA_XIVT_PRIORITY, data64, m_prio);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_22..23: Cleanup the MXIVT
	 *
	 * We set the priority to FF (masked) and clear everything
	 * else. That means we leave the HRT index to 0 which is
	 * going to remain unmodified... for now.
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_MXIVT, 0, true);
	for (i = 0; i < 256; i++) {
		data64 = p->mxive_cache[i];
		server = GETFIELD(IODA_XIVT_SERVER, data64);
		prio = GETFIELD(IODA_XIVT_PRIORITY, data64);

		/* Now we mangle the server and priority */
		if (prio == 0xff) {
			m_server = 0;
			m_prio = 0xff;
		} else {
			m_server = server >> 3;
			m_prio = (prio >> 3) | ((server & 7) << 5);
		}

		data64 = SETFIELD(IODA_XIVT_SERVER,   data64, m_server);
		data64 = SETFIELD(IODA_XIVT_PRIORITY, data64, m_prio);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_24..25: Cleanup the MVT */
	p7ioc_phb_ioda_sel(p, IODA_TBL_MVT, 0, true);
	for (i = 0; i < 256; i++) {
		data64 = p->mve_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_26..27: Cleanup the PELTM
	 *
	 * A completely clear PELTM should make everything match PE 0
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTM, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->peltm_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_28..30: Cleanup the PELTV */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PELTV, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->peltv_lo_cache[i];
		data64_hi = p->peltv_hi_cache[i];
		out_be64(p->regs + PHB_IODA_DATA1, data64_hi);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_31..33: Cleanup the TVT */
	p7ioc_phb_ioda_sel(p, IODA_TBL_TVT, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->tve_lo_cache[i];
		data64_hi = p->tve_hi_cache[i];
		out_be64(p->regs + PHB_IODA_DATA1, data64_hi);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_34..35: Cleanup the M64BT
	 *
	 * We don't enable M64 BARs by default. However,
	 * we shouldn't purge the hw and cache for it in
	 * future.
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_M64BT, 0, true);
	for (i = 0; i < 16; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_36..37: Cleanup the IODT */
	p7ioc_phb_ioda_sel(p, IODA_TBL_IODT, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->iod_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_38..39: Cleanup the M32DT */
	p7ioc_phb_ioda_sel(p, IODA_TBL_M32DT, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->m32d_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_40..41: Cleanup the M64DT */
	p7ioc_phb_ioda_sel(p, IODA_TBL_M64BT, 0, true);
	for (i = 0; i < 16; i++) {
		data64 = p->m64b_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	p7ioc_phb_ioda_sel(p, IODA_TBL_M64DT, 0, true);
	for (i = 0; i < 127; i++) {
		data64 = p->m64d_cache[i];
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Clear up the TCE cache */
	reg64 = in_be64(p->regs + PHB_PHB2_CONFIG);
	reg64 &= ~PHB_PHB2C_64B_TCE_EN;
	out_be64(p->regs + PHB_PHB2_CONFIG, reg64);
	reg64 |= PHB_PHB2C_64B_TCE_EN;
	out_be64(p->regs + PHB_PHB2_CONFIG, reg64);
	in_be64(p->regs + PHB_PHB2_CONFIG);

	/* Clear PEST & PEEV */
	for (i = 0; i < OPAL_P7IOC_NUM_PEST_REGS; i++) {
		uint64_t pesta, pestb;

		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTA, i, false);
		pesta = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		p7ioc_phb_ioda_sel(p, IODA_TBL_PESTB, i, false);
		pestb = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);

		if ((pesta & IODA_PESTA_MMIO_FROZEN) ||
		    (pestb & IODA_PESTB_DMA_STOPPED))
			PHBDBG(p, "Frozen PE#%d (%s - %s)\n",
			       i, (pestb & IODA_PESTB_DMA_STOPPED) ? "DMA" : "",
			       (pesta & IODA_PESTA_MMIO_FROZEN) ? "MMIO" : "");
	}

	p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
	for (i = 0; i < 2; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	return OPAL_SUCCESS;
}

/*
 * Clear anything we have in PAPR Error Injection registers. Though
 * the spec says the PAPR error injection should be one-shot without
 * the "sticky" bit. However, that's false according to the experiments
 * I had. So we have to clear it at appropriate point in kernel to
 * avoid endless frozen PE.
 */
static int64_t p7ioc_papr_errinjct_reset(struct phb *phb)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, 0x0ul);

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_presence_state(struct pci_slot *slot, uint8_t *val)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t reg;

	reg = in_be64(p->regs + PHB_PCIE_SLOTCTL2);
	if (reg & PHB_PCIE_SLOTCTL2_PRSTN_STAT)
		*val = OPAL_PCI_SLOT_PRESENT;
	else
		*val = OPAL_PCI_SLOT_EMPTY;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_link_state(struct pci_slot *slot, uint8_t *val)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t reg64;
	uint16_t state;
	int64_t rc;

	/* Check if the link training is completed */
	reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	if (!(reg64 & PHB_PCIE_DLP_TC_DL_LINKACT)) {
		*val = 0;
		return OPAL_SUCCESS;
	}

	/* Grab link width from PCIe capability */
	rc = p7ioc_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_LSTAT,
				 &state);
	if (rc < 0) {
		PHBERR(p, "%s: Error %lld reading link status\n",
		       __func__, rc);
		return OPAL_HARDWARE;
	}

	if (state & PCICAP_EXP_LSTAT_DLLL_ACT)
		*val = ((state & PCICAP_EXP_LSTAT_WIDTH) >> 4);
	else
		*val = 0;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_get_power_state(struct pci_slot *slot, uint8_t *val)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t reg64;

	reg64 = in_be64(p->regs + PHB_PCIE_SLOTCTL2);
	if (reg64 & PHB_PCIE_SLOTCTL2_PWR_EN_STAT)
		*val = PCI_SLOT_POWER_ON;
	else
		*val = PCI_SLOT_POWER_OFF;

	return OPAL_SUCCESS;
}

static int64_t p7ioc_set_power_state(struct pci_slot *slot, uint8_t val)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t reg64;
	uint8_t state = PCI_SLOT_POWER_OFF;

	if (val != PCI_SLOT_POWER_OFF && val != PCI_SLOT_POWER_ON)
		return OPAL_PARAMETER;

	/* If the power state has been put into the requested one */
	reg64 = in_be64(p->regs + PHB_PCIE_SLOTCTL2);
	if (reg64 & PHB_PCIE_SLOTCTL2_PWR_EN_STAT)
		state = PCI_SLOT_POWER_ON;
	if (state == val)
		return OPAL_SUCCESS;

	/* Power on/off */
	if (val == PCI_SLOT_POWER_ON) {
		reg64 &= ~(0x8c00000000000000ul);
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
		reg64 |= 0x8400000000000000ul;
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
	} else {
		reg64 &= ~(0x8c00000000000000ul);
		reg64 |= 0x8400000000000000ul;
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
		reg64 &= ~(0x8c00000000000000ul);
		reg64 |= 0x0c00000000000000ul;
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
	}

	return OPAL_SUCCESS;
}

static void p7ioc_prepare_link_change(struct pci_slot *slot, bool up)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t ci_idx = p->index + 2;
	uint32_t cfg32;

	if (!up) {
		/* Mask PCIE port interrupts and AER receiver error */
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0x7E00000000000000);
		p7ioc_pcicfg_read32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, &cfg32);
		cfg32 |= PCIECAP_AER_CE_RECVR_ERR;
		p7ioc_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_MASK, cfg32);

		/* Mask CI port error and clear it */
		out_be64(p->ioc->regs + P7IOC_CIn_LEM_ERR_MASK(ci_idx),
			 0xa4f4000000000000ul);
		out_be64(p->regs + PHB_LEM_ERROR_MASK,
			 0xadb650c9808dd051ul);
		out_be64(p->ioc->regs + P7IOC_CIn_LEM_FIR(ci_idx),
			 0x0ul);

		/* Block access to PCI-CFG space */
		p->flags |= P7IOC_PHB_CFG_BLOCKED;
	} else {
		/* Clear spurious errors and enable PCIE port interrupts */
		out_be64(p->regs + UTL_PCIE_PORT_STATUS, 0x00E0000000000000);
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xFE65000000000000);

		/* Clear AER receiver error status */
		p7ioc_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_STATUS,
				     PCIECAP_AER_CE_RECVR_ERR);
		/* Unmask receiver error status in AER */
		p7ioc_pcicfg_read32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, &cfg32);
		cfg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
		p7ioc_pcicfg_write32(&p->phb, 0,
				     p->aercap + PCIECAP_AER_CE_MASK, cfg32);
		/* Clear and Unmask CI port and PHB errors */
		out_be64(p->ioc->regs + P7IOC_CIn_LEM_FIR(ci_idx), 0x0ul);
		out_be64(p->regs + PHB_LEM_FIR_ACCUM, 0x0ul);
		out_be64(p->ioc->regs + P7IOC_CIn_LEM_ERR_MASK_AND(ci_idx),
			 0x0ul);
		out_be64(p->regs + PHB_LEM_ERROR_MASK, 0x1249a1147f500f2cul);

		/* Don't block access to PCI-CFG space */
		p->flags &= ~P7IOC_PHB_CFG_BLOCKED;

		/* Restore slot's state */
		pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);

		/*
		 * We might lose the bus numbers in the reset and we need
		 * restore the bus numbers. Otherwise, some adpaters (e.g.
		 * IPR) can't be probed properly by kernel. We don't need
		 * restore bus numbers for all kinds of resets. However,
		 * it's not harmful to restore the bus numbers, which makes
		 * the logic simplified
		 */
		pci_restore_bridge_buses(slot->phb, slot->pd);
		if (slot->phb->ops->device_init)
			pci_walk_dev(slot->phb, slot->pd,
				     slot->phb->ops->device_init, NULL);
	}
}

static int64_t p7ioc_poll_link(struct pci_slot *slot)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint64_t reg64;

	switch (slot->state) {
	case P7IOC_SLOT_NORMAL:
	case P7IOC_SLOT_LINK_START:
		PHBDBG(p, "LINK: Start polling\n");
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		reg64 &= ~PHB_PCIE_DLP_TCTX_DISABLE;
		out_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL, reg64);
		slot->retries = 100;
		pci_slot_set_state(slot, P7IOC_SLOT_LINK_WAIT);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case P7IOC_SLOT_LINK_WAIT:
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg64 & PHB_PCIE_DLP_TC_DL_LINKACT) {
			PHBDBG(p, "LINK: Up\n");
			slot->ops.prepare_link_change(slot, true);
			return OPAL_SUCCESS;
		}

		if (slot->retries-- == 0) {
			PHBERR(p, "LINK: Timeout waiting for link up\n");
			goto out;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	default:
		PHBERR(p, "LINK: Unexpected slot state %08x\n",
		       slot->state);
	}

out:
	pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t p7ioc_hreset(struct pci_slot *slot)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint8_t presence = 1;
	uint16_t brctl;
	uint64_t reg64;

	switch (slot->state) {
	case P7IOC_SLOT_NORMAL:
		PHBDBG(p, "HRESET: Starts\n");
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "HRESET: No device\n");
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "HRESET: Prepare for link down\n");
		slot->ops.prepare_link_change(slot, false);

		/* Disable link to avoid training issues */
		PHBDBG(p, "HRESET: Disable link training\n");
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		reg64 |= PHB_PCIE_DLP_TCTX_DISABLE;
		out_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL, reg64);
		pci_slot_set_state(slot, P7IOC_SLOT_HRESET_TRAINING);
		slot->retries = 15;
		/* fall through */
	case P7IOC_SLOT_HRESET_TRAINING:
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(reg64 & PHB_PCIE_DLP_TCRX_DISABLED)) {
			if (slot->retries -- == 0) {
				PHBERR(p, "HRESET: Timeout disabling link training\n");
				goto out;
			}

			return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
		}
		/* fall through */
	case P7IOC_SLOT_HRESET_START:
		PHBDBG(p, "HRESET: Assert\n");
		p7ioc_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);

		pci_slot_set_state(slot, P7IOC_SLOT_HRESET_DELAY);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case P7IOC_SLOT_HRESET_DELAY:
		PHBDBG(p, "HRESET: Deassert\n");
		p7ioc_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		pci_slot_set_state(slot, P7IOC_SLOT_HRESET_DELAY2);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(200));
	case P7IOC_SLOT_HRESET_DELAY2:
		pci_slot_set_state(slot, P7IOC_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "HRESET: Unexpected slot state %08x\n",
		       slot->state);
	}

out:
	pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t p7ioc_freset(struct pci_slot *slot)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	uint8_t presence = 1;
	uint64_t reg64;

	switch (slot->state) {
	case P7IOC_SLOT_NORMAL:
	case P7IOC_SLOT_FRESET_START:
		PHBDBG(p, "FRESET: Starts\n");
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "FRESET: No device\n");
			pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "FRESET: Prepare for link down\n");
		slot->ops.prepare_link_change(slot, false);

		/* Check power state */
		reg64 = in_be64(p->regs + PHB_PCIE_SLOTCTL2);
		if (reg64 & PHB_PCIE_SLOTCTL2_PWR_EN_STAT) {
			PHBDBG(p, "FRESET: Power on, turn off\n");
			reg64 = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);
			reg64 &= ~(0x8c00000000000000ul);
			reg64 |= 0x8400000000000000ul;
			out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
			reg64 &= ~(0x8c00000000000000ul);
			reg64 |= 0x0c00000000000000ul;
			out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
			pci_slot_set_state(slot, P7IOC_SLOT_FRESET_POWER_OFF);
			return pci_slot_set_sm_timeout(slot, secs_to_tb(2));
		}
		/* fall through */
	case P7IOC_SLOT_FRESET_POWER_OFF:
		PHBDBG(p, "FRESET: Power off, turn on\n");
		reg64 = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);
		reg64 &= ~(0x8c00000000000000ul);
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
		reg64 |= 0x8400000000000000ul;
		out_be64(p->regs + PHB_HOTPLUG_OVERRIDE, reg64);
		pci_slot_set_state(slot, P7IOC_SLOT_FRESET_POWER_ON);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(2));
	case P7IOC_SLOT_FRESET_POWER_ON:
		PHBDBG(p, "FRESET: Disable link training\n");
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		reg64 |= PHB_PCIE_DLP_TCTX_DISABLE;
		out_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL, reg64);
		pci_slot_set_state(slot, P7IOC_SLOT_HRESET_TRAINING);
		slot->retries = 200;
		/* fall through */
	case P7IOC_SLOT_HRESET_TRAINING:
		reg64 = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(reg64 & PHB_PCIE_DLP_TCRX_DISABLED)) {
			if (slot->retries -- == 0) {
				PHBERR(p, "HRESET: Timeout disabling link training\n");
				goto out;
			}

			return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
		}

		PHBDBG(p, "FRESET: Assert\n");
		reg64 = in_be64(p->regs + PHB_RESET);
		reg64 &= ~0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg64);
		pci_slot_set_state(slot, P7IOC_SLOT_FRESET_ASSERT);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case P7IOC_SLOT_FRESET_ASSERT:
		PHBDBG(p, "FRESET: Deassert\n");
		reg64 = in_be64(p->regs + PHB_RESET);
		reg64 |= 0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg64);
		if (slot->ops.pfreset) {
			pci_slot_set_state(slot,
					   P7IOC_SLOT_PFRESET_START);
			return slot->ops.pfreset(slot);
		}

		pci_slot_set_state(slot, P7IOC_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "FRESET: Unexpected slot state %08x\n",
		       slot->state);
	}

out:
	pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t p7ioc_creset(struct pci_slot *slot)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(slot->phb);
	struct p7ioc *ioc = p->ioc;
	uint64_t reg64;

	switch (slot->state) {
	case P7IOC_SLOT_NORMAL:
		PHBDBG(p, "CRESET: Starts\n");
		p->flags |= P7IOC_PHB_CFG_BLOCKED;
		p7ioc_phb_reset(slot->phb);

		/*
		 * According to the experiment, we probably still have the
		 * fenced state with the corresponding PHB in the Fence WOF
		 * and we need clear that explicitly. Besides, the RGC might
		 * already have informational error and we should clear that
		 * explicitly as well. Otherwise, RGC XIVE#0 won't issue
		 * interrupt any more.
		 */
		reg64 = in_be64(ioc->regs + P7IOC_CHIP_FENCE_WOF);
		reg64 &= ~PPC_BIT(15 + p->index * 4);
		out_be64(ioc->regs + P7IOC_CHIP_FENCE_WOF, reg64);

		/* Clear informational error from RGC */
		reg64 = in_be64(ioc->regs + P7IOC_RGC_LEM_BASE +
				P7IOC_LEM_WOF_OFFSET);
		reg64 &= ~PPC_BIT(18);
		out_be64(ioc->regs + P7IOC_RGC_LEM_BASE +
			 P7IOC_LEM_WOF_OFFSET, reg64);
		reg64 = in_be64(ioc->regs + P7IOC_RGC_LEM_BASE +
				P7IOC_LEM_FIR_OFFSET);
		reg64 &= ~PPC_BIT(18);
		out_be64(ioc->regs + P7IOC_RGC_LEM_BASE +
			 P7IOC_LEM_FIR_OFFSET, reg64);

		/* Swith to fundamental reset */
		pci_slot_set_state(slot, P7IOC_SLOT_FRESET_START);
		return slot->ops.freset(slot);
	default:
		PHBERR(p, "CRESET: Unexpected slot state %08x\n",
		       slot->state);
	}

	pci_slot_set_state(slot, P7IOC_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static struct pci_slot *p7ioc_phb_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return NULL;

	/* Elementary functions */
	slot->ops.get_presence_state   = p7ioc_get_presence_state;
	slot->ops.get_link_state       = p7ioc_get_link_state;
	slot->ops.get_power_state      = p7ioc_get_power_state;
	slot->ops.get_attention_state  = NULL;
	slot->ops.get_latch_state      = NULL;
	slot->ops.set_power_state      = p7ioc_set_power_state;
	slot->ops.set_attention_state  = NULL;

	/*
	 * For PHB slots, we have to split the fundamental reset
	 * into 2 steps. We might not have the first step which
	 * is to power off/on the slot, or it's controlled by
	 * individual platforms.
	 */
	slot->ops.prepare_link_change  = p7ioc_prepare_link_change;
	slot->ops.poll_link            = p7ioc_poll_link;
	slot->ops.hreset               = p7ioc_hreset;
	slot->ops.freset               = p7ioc_freset;
	slot->ops.pfreset              = NULL;
	slot->ops.creset               = p7ioc_creset;

	return slot;
}

static const struct phb_ops p7ioc_phb_ops = {
	.cfg_read8		= p7ioc_pcicfg_read8,
	.cfg_read16		= p7ioc_pcicfg_read16,
	.cfg_read32		= p7ioc_pcicfg_read32,
	.cfg_write8		= p7ioc_pcicfg_write8,
	.cfg_write16		= p7ioc_pcicfg_write16,
	.cfg_write32		= p7ioc_pcicfg_write32,
	.choose_bus		= p7ioc_choose_bus,
	.get_reserved_pe_number	= p7ioc_get_reserved_pe_number,
	.device_init		= p7ioc_device_init,
	.pci_reinit		= p7ioc_pci_reinit,
	.eeh_freeze_status	= p7ioc_eeh_freeze_status,
	.eeh_freeze_clear	= p7ioc_eeh_freeze_clear,
	.eeh_freeze_set		= p7ioc_eeh_freeze_set,
	.err_inject		= p7ioc_err_inject,
	.get_diag_data		= NULL,
	.get_diag_data2		= p7ioc_get_diag_data,
	.next_error		= p7ioc_eeh_next_error,
	.phb_mmio_enable	= p7ioc_phb_mmio_enable,
	.set_phb_mem_window	= p7ioc_set_phb_mem_window,
	.map_pe_mmio_window	= p7ioc_map_pe_mmio_window,
	.set_pe			= p7ioc_set_pe,
	.set_peltv		= p7ioc_set_peltv,
	.map_pe_dma_window	= p7ioc_map_pe_dma_window,
	.map_pe_dma_window_real	= p7ioc_map_pe_dma_window_real,
	.set_mve		= p7ioc_set_mve,
	.set_mve_enable		= p7ioc_set_mve_enable,
	.set_xive_pe		= p7ioc_set_xive_pe,
	.get_xive_source	= p7ioc_get_xive_source,
	.get_msi_32		= p7ioc_get_msi_32,
	.get_msi_64		= p7ioc_get_msi_64,
	.ioda_reset		= p7ioc_ioda_reset,
	.papr_errinjct_reset	= p7ioc_papr_errinjct_reset,
};

/* p7ioc_phb_get_xive - Interrupt control from OPAL */
static int64_t p7ioc_msi_get_xive(struct irq_source *is, uint32_t isn,
				  uint16_t *server, uint8_t *prio)
{
	struct p7ioc_phb *p = is->data;
	uint32_t irq, fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive;

	if (fbuid < p->buid_msi || fbuid >= (p->buid_msi + 0x10))
		return OPAL_PARAMETER;

	irq = isn & 0xff;
	xive = p->mxive_cache[irq];

	*server = GETFIELD(IODA_XIVT_SERVER, xive);
	*prio = GETFIELD(IODA_XIVT_PRIORITY, xive);

	return OPAL_SUCCESS;
}

/* p7ioc_phb_set_xive - Interrupt control from OPAL */
static int64_t p7ioc_msi_set_xive(struct irq_source *is, uint32_t isn,
				  uint16_t server, uint8_t prio)
{
	struct p7ioc_phb *p = is->data;
	uint32_t irq, fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive, m_server, m_prio;

	if (fbuid < p->buid_msi || fbuid >= (p->buid_msi + 0x10))
		return OPAL_PARAMETER;

	/* We cache the arguments because we have to mangle
	 * it in order to hijack 3 bits of priority to extend
	 * the server number
	 */
	irq = isn & 0xff;
	xive = p->mxive_cache[irq];
	xive = SETFIELD(IODA_XIVT_SERVER, xive, server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, prio);
	p->mxive_cache[irq] = xive;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		m_server = 0;
		m_prio = 0xff;
	} else {
		m_server = server >> 3;
		m_prio = (prio >> 3) | ((server & 7) << 5);
	}

	/* We use HRT entry 0 always for now */
	p7ioc_phb_ioda_sel(p, IODA_TBL_MXIVT, irq, false);
	xive = in_be64(p->regs + PHB_IODA_DATA0);
	xive = SETFIELD(IODA_XIVT_SERVER, xive, m_server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, m_prio);
	out_be64(p->regs + PHB_IODA_DATA0, xive);

	return OPAL_SUCCESS;
}

/* p7ioc_phb_get_xive - Interrupt control from OPAL */
static int64_t p7ioc_lsi_get_xive(struct irq_source *is, uint32_t isn,
				  uint16_t *server, uint8_t *prio)
{
	struct p7ioc_phb *p = is->data;
	uint32_t irq = (isn & 0x7);
	uint32_t fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive;

	if (fbuid != p->buid_lsi)
		return OPAL_PARAMETER;

	xive = p->lxive_cache[irq];
	*server = GETFIELD(IODA_XIVT_SERVER, xive);
	*prio = GETFIELD(IODA_XIVT_PRIORITY, xive);

	return OPAL_SUCCESS;
}

/* p7ioc_phb_set_xive - Interrupt control from OPAL */
static int64_t p7ioc_lsi_set_xive(struct irq_source *is, uint32_t isn,
				  uint16_t server, uint8_t prio)
{
	struct p7ioc_phb *p = is->data;
	uint32_t irq = (isn & 0x7);
	uint32_t fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive, m_server, m_prio;

	if (fbuid != p->buid_lsi)
		return OPAL_PARAMETER;

	xive = SETFIELD(IODA_XIVT_SERVER, 0ull, server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, prio);

	/*
	 * We cache the arguments because we have to mangle
	 * it in order to hijack 3 bits of priority to extend
	 * the server number
	 */
	p->lxive_cache[irq] = xive;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		m_server = 0;
		m_prio = 0xff;
	} else {
		m_server = server >> 3;
		m_prio = (prio >> 3) | ((server & 7) << 5);
	}

	/* We use HRT entry 0 always for now */
	p7ioc_phb_ioda_sel(p, IODA_TBL_LXIVT, irq, false);
	xive = in_be64(p->regs + PHB_IODA_DATA0);
	xive = SETFIELD(IODA_XIVT_SERVER, xive, m_server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, m_prio);
	out_be64(p->regs + PHB_IODA_DATA0, xive);

	return OPAL_SUCCESS;
}

static void p7ioc_phb_err_interrupt(struct irq_source *is, uint32_t isn)
{
	struct p7ioc_phb *p = is->data;
	uint64_t peev0, peev1;

	PHBDBG(p, "Got interrupt 0x%04x\n", isn);

	opal_pci_eeh_set_evt(p->phb.opal_id);

	/* If the PHB is broken, go away */
	if (p->state == P7IOC_PHB_STATE_BROKEN)
		return;

	/*
	 * Check if there's an error pending and update PHB fence
	 * state and return, the ER error is drowned at this point
	 */
	phb_lock(&p->phb);
	if (p7ioc_phb_fenced(p)) {
		p->state = P7IOC_PHB_STATE_FENCED;
		PHBERR(p, "ER error ignored, PHB fenced\n");
		phb_unlock(&p->phb);
		return;
	}

	/*
	 * If we already had pending errors, which might be
	 * moved from IOC, then we needn't check PEEV to avoid
	 * overwriting the errors from IOC.
	 */
	if (!p7ioc_phb_err_pending(p)) {
		phb_unlock(&p->phb);
		return;
	}

	/*
	 * We don't have pending errors from IOC, it's safe
	 * to check PEEV for frozen PEs.
	 */
	p7ioc_phb_ioda_sel(p, IODA_TBL_PEEV, 0, true);
	peev0 = in_be64(p->regs + PHB_IODA_DATA0);
	peev1 = in_be64(p->regs + PHB_IODA_DATA0);
	if (peev0 || peev1) {
		p->err.err_src   = P7IOC_ERR_SRC_PHB0 + p->index;
		p->err.err_class = P7IOC_ERR_CLASS_ER;
		p->err.err_bit   = 0;
		p7ioc_phb_set_err_pending(p, true);
	}
	phb_unlock(&p->phb);
}

/* MSIs (OS owned) */
static const struct irq_source_ops p7ioc_msi_irq_ops = {
	.get_xive = p7ioc_msi_get_xive,
	.set_xive = p7ioc_msi_set_xive,
};

/* LSIs (OS owned) */
static const struct irq_source_ops p7ioc_lsi_irq_ops = {
	.get_xive = p7ioc_lsi_get_xive,
	.set_xive = p7ioc_lsi_set_xive,
};

/* PHB Errors (Ski owned) */
static const struct irq_source_ops p7ioc_phb_err_irq_ops = {
	.get_xive = p7ioc_lsi_get_xive,
	.set_xive = p7ioc_lsi_set_xive,
	.interrupt = p7ioc_phb_err_interrupt,
};

static void p7ioc_pcie_add_node(struct p7ioc_phb *p)
{

	uint64_t reg[2], iob, m32b, m64b, tkill;
	uint32_t lsibase, icsp = get_ics_phandle();
	struct dt_node *np;

	reg[0] = cleanup_addr((uint64_t)p->regs);
	reg[1] = 0x100000;

	np = dt_new_addr(p->ioc->dt_node, "pciex", reg[0]);
	if (!np)
		return;

	p->phb.dt_node = np;
	dt_add_property_strings(np, "compatible", "ibm,p7ioc-pciex",
				"ibm,ioda-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */
	dt_add_property_cells(np, "interrupt-parent", icsp);
	/* XXX FIXME: add slot-name */
	//dt_property_cell("bus-width", 8); /* Figure it out from VPD ? */

	/* "ranges", we only expose IO and M32
	 *
	 * Note: The kernel expects us to have chopped of 64k from the
	 * M32 size (for the 32-bit MSIs). If we don't do that, it will
	 * get confused (OPAL does it)
	 */
	iob = cleanup_addr(p->io_base);
	m32b = cleanup_addr(p->m32_base + M32_PCI_START);
	dt_add_property_cells(np, "ranges",
			      /* IO space */
			      0x01000000, 0x00000000, 0x00000000,
			      hi32(iob), lo32(iob), 0, PHB_IO_SIZE,
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0,M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, dmawins, etc... */
	m64b = cleanup_addr(p->m64_base);
	dt_add_property_cells(np, "ibm,opal-m64-window",
			      hi32(m64b), lo32(m64b),
			      hi32(m64b), lo32(m64b),
			      hi32(PHB_M64_SIZE), lo32(PHB_M64_SIZE));
	dt_add_property_cells(np, "ibm,opal-msi-ports", 256);
	dt_add_property_cells(np, "ibm,opal-num-pes", 128);
	dt_add_property_cells(np, "ibm,opal-reserved-pe", 127);
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->buid_msi << 4, 0x100);
	tkill = reg[0] + PHB_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-tce-kill",
			      hi32(tkill), lo32(tkill));

	/* Add associativity properties */
	add_chip_dev_associativity(np);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->buid_lsi << 4;
	p->phb.lstate.int_size = 2;
	p->phb.lstate.int_val[0][0] = lsibase + PHB_LSI_PCIE_INTA;
	p->phb.lstate.int_val[0][1] = 1;
	p->phb.lstate.int_val[1][0] = lsibase + PHB_LSI_PCIE_INTB;
	p->phb.lstate.int_val[1][1] = 1;
	p->phb.lstate.int_val[2][0] = lsibase + PHB_LSI_PCIE_INTC;
	p->phb.lstate.int_val[2][1] = 1;
	p->phb.lstate.int_val[3][0] = lsibase + PHB_LSI_PCIE_INTD;
	p->phb.lstate.int_val[3][1] = 1;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;
}

/* p7ioc_phb_setup - Setup a p7ioc_phb data structure
 *
 * WARNING: This is called before the AIB register routing is
 * established. If this wants to access PHB registers, it must
 * use the ASB hard coded variant (slower)
 */
void p7ioc_phb_setup(struct p7ioc *ioc, uint8_t index)
{
	struct p7ioc_phb *p = &ioc->phbs[index];
	unsigned int buid_base = ioc->buid_base + PHBn_BUID_BASE(index);
	struct pci_slot *slot;

	p->index = index;
	p->ioc = ioc;
	p->gen = 2;	/* Operate in Gen2 mode by default */
	p->phb.ops = &p7ioc_phb_ops;
	p->phb.phb_type = phb_type_pcie_v2;
	p->regs_asb = ioc->regs + PHBn_ASB_BASE(index);
	p->regs = ioc->regs + PHBn_AIB_BASE(index);
	p->buid_lsi = buid_base + PHB_BUID_LSI_OFFSET;
	p->buid_msi = buid_base + PHB_BUID_MSI_OFFSET;
	p->io_base = ioc->mmio1_win_start + PHBn_IO_BASE(index);
	p->m32_base = ioc->mmio2_win_start + PHBn_M32_BASE(index);
	p->m64_base = ioc->mmio2_win_start + PHBn_M64_BASE(index);
	p->state = P7IOC_PHB_STATE_UNINITIALIZED;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */

	/* Find P7IOC base location code in IOC */
	p->phb.base_loc_code = dt_prop_get_def(ioc->dt_node,
					       "ibm,io-base-loc-code", NULL);
	if (!p->phb.base_loc_code)
		prerror("P7IOC: Base location code not found !\n");

	/* Create device node for PHB */
	p7ioc_pcie_add_node(p);

	/* Register OS interrupt sources */
	register_irq_source(&p7ioc_msi_irq_ops, p, p->buid_msi << 4, 256);
	register_irq_source(&p7ioc_lsi_irq_ops, p, p->buid_lsi << 4, 4);

	/* Register internal interrupt source (LSI 7) */
	register_irq_source(&p7ioc_phb_err_irq_ops, p,
			    (p->buid_lsi << 4) + PHB_LSI_PCIE_ERROR, 1);

	/* Initialize IODA table caches */
	p7ioc_phb_init_ioda_cache(p);

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb, OPAL_DYNAMIC_PHB_ID);
	slot = p7ioc_phb_slot_create(&p->phb);
	if (!slot)
		prlog(PR_NOTICE, "P7IOC: Cannot create PHB#%d slot\n",
		      p->phb.opal_id);

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);
}

static bool p7ioc_phb_wait_dlp_reset(struct p7ioc_phb *p)
{
	unsigned int i;
	uint64_t val;

	/*
	 * Firmware cannot access the UTL core regs or PCI config space
	 * until the cores are out of DL_PGRESET.
	 * DL_PGRESET should be polled until it is inactive with a value
	 * of '0'. The recommended polling frequency is once every 1ms.
	 * Firmware should poll at least 200 attempts before giving up.
	 * MMIO Stores to the link are silently dropped by the UTL core if
	 * the link is down.
	 * MMIO Loads to the link will be dropped by the UTL core and will
	 * eventually time-out and will return an all ones response if the
	 * link is down.
	 */
#define DLP_RESET_ATTEMPTS	400

	printf("P7IOC: Waiting for DLP PG reset to complete...\n");
	for (i = 0; i < DLP_RESET_ATTEMPTS; i++) {
		val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(val & PHB_PCIE_DLP_TC_DL_PGRESET))
			break;
		time_wait_ms(1);
	}
	if (val & PHB_PCIE_DLP_TC_DL_PGRESET) {
		PHBERR(p, "Timeout waiting for DLP PG reset !\n");
		return false;
	}
	return true;
}

/* p7ioc_phb_init_rc - Initialize the Root Complex config space
 */
static bool p7ioc_phb_init_rc_cfg(struct p7ioc_phb *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_51..51:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	p7ioc_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_52..57
	 *
	 * IO and Memory base & limits are set to base > limit, which
	 * allows all inbounds.
	 *
	 * XXX This has the potential of confusing the OS which might
	 * think that nothing is forwarded downstream. We probably need
	 * to fix this to match the IO and M32 PHB windows
	 */
	p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_IO_BASE, 0x0010);
	p7ioc_pcicfg_write32(&p->phb, 0, PCI_CFG_MEM_BASE, 0x00000010);
	p7ioc_pcicfg_write32(&p->phb, 0, PCI_CFG_PREF_MEM_BASE, 0x00000010);

	/* Init_58..: Setup bridge control to enable forwarding of CORR, FATAL,
	 * and NONFATAL errors
	*/
	p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, PCI_CFG_BRCTL_SERR_EN);

	/* Init_60..61
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 4K. This has proved to have
	 * some issues as it requires specific claming of MRSS on devices and
	 * we've found devices in the field that misbehave when doing that.
	 *
	 * We currently leave it all to 128 bytes (minimum setting) at init
	 * time. The generic PCIe probing later on might apply a different
	 * value, or the kernel will, but we play it safe at early init
	 */
	if (p->ecap <= 0) {
		ecap = pci_find_cap(&p->phb, 0, PCI_CFG_CAP_ID_EXP);
		if (ecap < 0) {
			PHBERR(p, "Can't locate PCI-E capability\n");
			return false;
		}
		p->ecap = ecap;
	} else {
		ecap = p->ecap;
	}

	p7ioc_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	p7ioc_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_62..63
	 *
	 * Root Control Register. Enable error reporting
	 *
	 * Note: Added CRS visibility.
	 */
	p7ioc_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_RC,
			     PCICAP_EXP_RC_SYSERR_ON_CE		|
			     PCICAP_EXP_RC_SYSERR_ON_NFE	|
			     PCICAP_EXP_RC_SYSERR_ON_FE		|
			     PCICAP_EXP_RC_CRS_VISIBLE);

	/* Init_64..65
	 *
	 * Device Control 2. Enable ARI fwd, set timer
	 */
	p7ioc_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 2) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_66..81
	 *
	 * AER inits
	 */
	aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
	if (aercap < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to locate AER capability in bridge\n");
		return false;
	}
	p->aercap = aercap;

	/* Clear all UE status */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the P7IOC spec */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT		|
			     PCIECAP_AER_UE_ECRC);
	/* Report some errors as fatal */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_SEVERITY,
			     PCIECAP_AER_UE_DLP 		|
			     PCIECAP_AER_UE_SURPRISE_DOWN	|
			     PCIECAP_AER_UE_FLOW_CTL_PROT	|
			     PCIECAP_AER_UE_UNEXP_COMPL		|
			     PCIECAP_AER_UE_RECV_OVFLOW		|
			     PCIECAP_AER_UE_MALFORMED_TLP);
	/* Clear all CE status */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the P7IOC spec */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_MASK,
			     PCIECAP_AER_CE_ADV_NONFATAL);
	/* Enable ECRC generation & checking */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CAPCTL,
			     PCIECAP_AER_CAPCTL_ECRCG_EN	|
			     PCIECAP_AER_CAPCTL_ECRCC_EN);
	/* Enable reporting in root error control */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_CMD,
			     PCIECAP_AER_RERR_CMD_FE		|
			     PCIECAP_AER_RERR_CMD_NFE		|
			     PCIECAP_AER_RERR_CMD_CE);
	/* Clear root error status */
	p7ioc_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);

	return true;
}

static void p7ioc_phb_init_utl(struct p7ioc_phb *p)
{
	/* Init_82..84: Clear spurious errors and assign errors to the
	 * right "interrupt" signal
	 */
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS,       0xffffffffffffffffUL);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_ERR_SEVERITY, 0x0000000000000000UL);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xac80000000000000UL);

	/* Init_85..89: Setup buffer allocations */
	out_be64(p->regs + UTL_OUT_POST_DAT_BUF_ALLOC,     0x0400000000000000UL);
	out_be64(p->regs + UTL_IN_POST_HDR_BUF_ALLOC,      0x1000000000000000UL);
	out_be64(p->regs + UTL_IN_POST_DAT_BUF_ALLOC,      0x4000000000000000UL);
	out_be64(p->regs + UTL_PCIE_TAGS_ALLOC,            0x0800000000000000UL);
	out_be64(p->regs + UTL_GBIF_READ_TAGS_ALLOC,       0x0800000000000000UL);

	/* Init_90: PCI Express port control */
	out_be64(p->regs + UTL_PCIE_PORT_CONTROL,          0x8480000000000000UL);

	/* Init_91..93: Clean & setup port errors */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,           0xff7fffffffffffffUL);
	out_be64(p->regs + UTL_PCIE_PORT_ERROR_SEV,        0x00e0000000000000UL);
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,           0x7e65000000000000UL);

	/* Init_94 : Cleanup RC errors */
	out_be64(p->regs + UTL_RC_STATUS,                  0xffffffffffffffffUL);
}

static void p7ioc_phb_init_errors(struct p7ioc_phb *p)
{
	/* Init_98: LEM Error Mask : Temporarily disable error interrupts */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0xffffffffffffffffUL);

	/* Init_99..107: Configure main error traps & clear old state */
	out_be64(p->regs + PHB_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_LEM_ENABLE,		   0xffffffffefffffffUL);
	out_be64(p->regs + PHB_ERR_FREEZE_ENABLE,	   0x0000000061c00000UL);
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,	   0xffffffc58c000000UL);
	out_be64(p->regs + PHB_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_STATUS_MASK,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_108_116: Configure MMIO error traps & clear old state */
	out_be64(p->regs + PHB_OUT_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_LEM_ENABLE,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_OUT_ERR_FREEZE_ENABLE,	   0x0000430803000000UL);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9df3bc00f0f0700fUL);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_STATUS_MASK,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_117_125: Configure DMA_A error traps & clear old state */
	out_be64(p->regs + PHB_INA_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INA_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_LEM_ENABLE,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INA_ERR_FREEZE_ENABLE,	   0xc00003ff01006000UL);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0x3fff50007e559fd8UL);
	out_be64(p->regs + PHB_INA_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_STATUS_MASK,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_126_134: Configure DMA_B error traps & clear old state */
	out_be64(p->regs + PHB_INB_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INB_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_LEM_ENABLE,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0x18ff80ffff7f0000UL);
	out_be64(p->regs + PHB_INB_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_STATUS_MASK,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_135..138: Cleanup & configure LEM */
	out_be64(p->regs + PHB_LEM_FIR_ACCUM,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_LEM_ACTION0,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_LEM_ACTION1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_LEM_WOF,			   0x0000000000000000UL);
}

/* p7ioc_phb_init - Initialize the PHB hardware
 *
 * This is currently only called at boot time. It will eventually
 * be called at runtime, for example in some cases of error recovery
 * after a PHB reset in which case we might need locks etc... 
 */
int64_t p7ioc_phb_init(struct p7ioc_phb *p)
{
	uint64_t val;

	PHBDBG(p, "Initializing PHB %d...\n", p->index);

	p->state = P7IOC_PHB_STATE_INITIALIZING;

	/* For some reason, the doc wants us to read the version
	 * register, so let's do it. We shoud probably check that
	 * the value makes sense...
	 */
	val = in_be64(p->regs_asb + PHB_VERSION);
	p->rev = ((val >> 16) & 0xffff) | (val & 0xffff);
	PHBDBG(p, "PHB version: %08x\n", p->rev);

	/*
	 * Configure AIB operations
	 *
	 * This register maps upbound commands to AIB channels.
	 * DMA Write=0, DMA Read=2, MMIO Load Response=1,
	 * Interrupt Request=1, TCE Read=3.
	 */
	/* Init_1: AIB TX Channel Mapping */
	out_be64(p->regs_asb + PHB_AIB_TX_CHAN_MAPPING,    0x0211300000000000UL);

	/*
	 * This group of steps initializes the AIB RX credits for
	 * the CI block’s port that is attached to this PHB.
	 *
	 * Channel 0 (Dkill): 32 command credits, 0 data credits
	 *                    (effectively infinite command credits)
	 * Channel 1 (DMA/TCE Read Responses): 32 command credits, 32 data
	 *                                     credits (effectively infinite
	 *                                     command and data credits)
	 * Channel 2 (Interrupt Reissue/Return): 32 command, 0 data credits
	 *                                       (effectively infinite
	 *                                       command credits)
	 * Channel 3 (MMIO Load/Stores, EOIs): 1 command, 1 data credit
	 */

	/* Init_2: AIB RX Command Credit */
	out_be64(p->regs_asb + PHB_AIB_RX_CMD_CRED,        0x0020002000200001UL);
	/* Init_3: AIB RX Data Credit */
	out_be64(p->regs_asb + PHB_AIB_RX_DATA_CRED,       0x0000002000000001UL);
	/* Init_4: AXIB RX Credit Init Timer */
	out_be64(p->regs_asb + PHB_AIB_RX_CRED_INIT_TIMER, 0xFF00000000000000UL);

	/*
	 * Enable all 32 AIB and TCE tags.
	 *
	 * AIB tags are used for DMA read requests.
	 * TCE tags are used for every internal transaction as well as TCE
	 * read requests.
	 */

	/* Init_5:  PHB - AIB Tag Enable Register */
	out_be64(p->regs_asb + PHB_AIB_TAG_ENABLE,         0xFFFFFFFF00000000UL);
	/* Init_6: PHB – TCE Tag Enable Register */
	out_be64(p->regs_asb + PHB_TCE_TAG_ENABLE,         0xFFFFFFFF00000000UL);

	/* Init_7: PCIE - System Configuration Register
	 *
	 * This is the default value out of reset. This register can be
	 * modified to change the following fields if needed:
	 *
	 *  bits 04:09 - SYS_EC0C_MAXLINKWIDTH[5:0]
	 *               The default link width is x8. This can be reduced
	 *               to x1 or x4, if needed.
	 *
	 *  bits 10:12 - SYS_EC04_MAX_PAYLOAD[2:0]
	 *
	 *               The default max payload size is 4KB. This can be
	 *               reduced to the allowed ranges from 128B
	 *               to 2KB if needed.
	 */
	out_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG,         0x422800FC20000000UL);

	/* Init_8: PHB - PCI-E Reset Register
	 *
	 * This will deassert reset for the PCI-E cores, including the
	 * PHY and HSS macros. The TLDLP core will begin link training
	 * shortly after this register is written.
	 * This will also assert reset for the internal scan-only error
	 * report macros. The error report macro reset will be deasserted
	 * in a later step.
	 * Firmware will verify in a later step whether the PCI-E link
	 * has been established.
	 *
	 * NOTE: We perform a PERST at the end of the init sequence so
	 * we could probably skip that link training.
	 */
	out_be64(p->regs + PHB_RESET,                      0xE800000000000000UL);

	/* Init_9: BUID
	 *
	 * Only the top 5 bit of the MSI field are implemented, the bottom
	 * are always 0. Our buid_msi value should also be a multiple of
	 * 16 so it should all fit well
	 */
	val  = SETFIELD(PHB_BUID_LSI, 0ul, P7_BUID_BASE(p->buid_lsi));
	val |= SETFIELD(PHB_BUID_MSI, 0ul, P7_BUID_BASE(p->buid_msi));
	out_be64(p->regs + PHB_BUID, val);

	/* Init_10..12: IO Space */
	out_be64(p->regs + PHB_IO_BASE_ADDR, p->io_base);
	out_be64(p->regs + PHB_IO_BASE_MASK, ~(PHB_IO_SIZE - 1));
	out_be64(p->regs + PHB_IO_START_ADDR, 0);

	/* Init_13..15: M32 Space */
	out_be64(p->regs + PHB_M32_BASE_ADDR, p->m32_base + M32_PCI_START);
	out_be64(p->regs + PHB_M32_BASE_MASK, ~(M32_PCI_SIZE - 1));
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_16: PCIE-E Outbound Request Upper Address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_17: PCIE-E PHB2 Configuration
	 *
	 * We enable IO, M32, 32-bit MSI and 64-bit MSI
	 */
	out_be64(p->regs + PHB_PHB2_CONFIG,
		 PHB_PHB2C_32BIT_MSI_EN	|
		 PHB_PHB2C_IO_EN	|
		 PHB_PHB2C_64BIT_MSI_EN	|
		 PHB_PHB2C_M32_EN |
		 PHB_PHB2C_64B_TCE_EN);

	/* Init_18..xx: Reset all IODA tables */
	p7ioc_ioda_reset(&p->phb, false);

	/* Init_42..47: Clear UTL & DLP error log regs */
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG1,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG2,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG3,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG4,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG1,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG2,	   0xffffffffffffffffUL);

	/* Init_48: Wait for DLP core to be out of reset */
	if (!p7ioc_phb_wait_dlp_reset(p))
		goto failed;

	/* Init_49 - Clear port status */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,	   0xffffffffffffffffUL);

	/* Init_50..81: Init root complex config space */
	if (!p7ioc_phb_init_rc_cfg(p))
		goto failed;

	/* Init_82..94 : Init UTL */
	p7ioc_phb_init_utl(p);

	/* Init_95: PCI-E Reset, deassert reset for internal error macros */
	out_be64(p->regs + PHB_RESET,			   0xe000000000000000UL);

	/* Init_96: PHB Control register. Various PHB settings:
	 *
	 * - Enable ECC for various internal RAMs
	 * - Enable all TCAM entries
	 * - Set failed DMA read requests to return Completer Abort on error
	 */
	out_be64(p->regs + PHB_CONTROL, 	       	   0x7f38000000000000UL);

	/* Init_97: Legacy Control register
	 *
	 * The spec sets bit 0 to enable DKill to flush the TCEs. We do not
	 * use that mechanism however, we require the OS to directly access
	 * the TCE Kill register, so we leave that bit set to 0
	 */
	out_be64(p->regs + PHB_LEGACY_CTRL,		   0x0000000000000000);

	/* Init_98..138  : Setup error registers */
	p7ioc_phb_init_errors(p);

	/* Init_139: Read error summary */
	val = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (val) {
		PHBERR(p, "Errors detected during PHB init: 0x%16llx\n", val);
		goto failed;
	}

	/* Steps Init_140..142 have been removed from the spec. */

	/* Init_143..144: Enable IO, MMIO, Bus master etc... and clear
	 * status bits
	 */
	p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			     PCI_CFG_STAT_SENT_TABORT	|
			     PCI_CFG_STAT_RECV_TABORT	|
			     PCI_CFG_STAT_RECV_MABORT	|
			     PCI_CFG_STAT_SENT_SERR	|
			     PCI_CFG_STAT_RECV_PERR);
	p7ioc_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			     PCI_CFG_CMD_SERR_EN	|
			     PCI_CFG_CMD_PERR_RESP	|
			     PCI_CFG_CMD_BUS_MASTER_EN	|
			     PCI_CFG_CMD_MEM_EN		|
			     PCI_CFG_CMD_IO_EN);

	/* At this point, the spec suggests doing a bus walk. However we
	 * haven't powered up the slots with the SHCP controller. We'll
	 * deal with that and link training issues later, for now, let's
	 * enable the full range of error detection
	 */

	/* Init_145..149: Enable error interrupts and LEM */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,		   0x0000000061c00000UL);
	out_be64(p->regs + PHB_OUT_ERR_IRQ_ENABLE,	   0x0000430803000000UL);
	out_be64(p->regs + PHB_INA_ERR_IRQ_ENABLE,	   0xc00003ff01006000UL);
	out_be64(p->regs + PHB_INB_ERR_IRQ_ENABLE,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0x1249a1147f500f2cUL);

	/* Init_150: Enable DMA read/write TLP address speculation */
	out_be64(p->regs + PHB_TCE_PREFETCH,		   0x0000c00000000000UL);

	/* Init_151..152: Set various timeouts */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,		   0x1611112010200000UL);
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,		   0x0000561300000000UL);

	/* Mark the PHB as functional which enables all the various sequences */
	p->state = P7IOC_PHB_STATE_FUNCTIONAL;

	return OPAL_SUCCESS;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->state = P7IOC_PHB_STATE_BROKEN;

	return OPAL_HARDWARE;
}

void p7ioc_phb_reset(struct phb *phb)
{
	struct p7ioc_phb *p = phb_to_p7ioc_phb(phb);
	struct p7ioc *ioc = p->ioc;
	uint64_t ci_idx, rreg;
	unsigned int i;
	bool fenced;

	/* Check our fence status. The fence bits we care about are
	 * two bits per PHB at IBM bit location 14 and 15 + 4*phb
	 */
	fenced = p7ioc_phb_fenced(p);

	PHBDBG(p, "PHB reset... (fenced: %d)\n", (int)fenced);

	/*
	 * If not fenced and already functional, let's do an IODA reset
	 * to clear pending DMAs and wait a bit for thing to settle. It's
	 * notable that the IODA table cache won't be emptied so that we
	 * can restore them during error recovery.
	 */
	if (p->state == P7IOC_PHB_STATE_FUNCTIONAL && !fenced) {
		PHBDBG(p, "  ioda reset ...\n");
		p7ioc_ioda_reset(&p->phb, false);
		time_wait_ms(100);
	}

	/* CI port index */
	ci_idx = p->index + 2;

	/* Reset register bits for this PHB */
	rreg =  0;/*PPC_BIT(8 + ci_idx * 2);*/	/* CI port config reset */
	rreg |= PPC_BIT(9 + ci_idx * 2);	/* CI port func reset */
	rreg |= PPC_BIT(32 + p->index);		/* PHBn config reset */

	/* Mask various errors during reset and clear pending errors */
	out_be64(ioc->regs + P7IOC_CIn_LEM_ERR_MASK(ci_idx),
		 0xa4f4000000000000ul);
	out_be64(p->regs_asb + PHB_LEM_ERROR_MASK, 0xadb650c9808dd051ul);
	out_be64(ioc->regs + P7IOC_CIn_LEM_FIR(ci_idx), 0);

	/* We need to retry in case the fence doesn't lift due to a
	 * problem with lost credits (HW guys). How many times ?
	 */
#define MAX_PHB_RESET_RETRIES	5
	for (i = 0; i < MAX_PHB_RESET_RETRIES; i++) {
		PHBDBG(p, "  reset try %d...\n", i);
		/* Apply reset */
		out_be64(ioc->regs + P7IOC_CCRR, rreg);
		time_wait_ms(1);
		out_be64(ioc->regs + P7IOC_CCRR, 0);

		/* Check if fence lifed */
		fenced = p7ioc_phb_fenced(p);
		PHBDBG(p, "  fenced: %d...\n", (int)fenced);
		if (!fenced)
			break;
	}

	/* Reset failed, not much to do, maybe add an error return */
	if (fenced) {
		PHBERR(p, "Reset failed, fence still set !\n");
		p->state = P7IOC_PHB_STATE_BROKEN;
		return;
	}

	/* Wait a bit */
	time_wait_ms(100);

	/* Re-initialize the PHB */
	p7ioc_phb_init(p);

	/* Restore the CI error mask */
	out_be64(ioc->regs + P7IOC_CIn_LEM_ERR_MASK_AND(ci_idx), 0);
}


