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
 * PHB4 support
 *
 */

/*
 *
 * FIXME:
 *   More stuff for EEH support:
 *      - PBCQ error reporting interrupt
 *	- I2C-based power management (replacing SHPC)
 *	- Directly detect fenced PHB through one dedicated HW reg
 */

#undef NO_ASB
#undef LOG_CFG
#undef CFG_4B_WORKAROUND

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <vpd.h>
#include <interrupts.h>
#include <opal.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <xscom.h>
#include <affinity.h>
#include <phb4.h>
#include <phb4-regs.h>
#include <capp.h>
#include <fsp.h>
#include <chip.h>
#include <chiptod.h>
#include <xive.h>

/* Enable this to disable error interrupts for debug purposes */
#undef DISABLE_ERR_INTS

static void phb4_init_hw(struct phb4 *p, bool first_init);

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBINF(p, fmt, a...)	prlog(PR_INFO, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB%d: " fmt, \
				      (p)->phb.opal_id, ## a)

/* Note: The "ASB" name is historical, practically this means access via
 * the XSCOM backdoor
 */
static inline uint64_t phb4_read_reg_asb(struct phb4 *p, uint32_t offset)
{
#ifdef NO_ASB
	return in_be64(p->regs + offset);
#else
	int64_t rc;
	uint64_t addr, val;

	/* Address register: must use 4 bytes for built-in config space.
	 *
	 * This path isn't usable for outbound configuration space
	 */
	if ((offset & 0xfffffffc) == PHB_CONFIG_DATA) {
		PHBERR(p, "XSCOM access to CONFIG_DATA unsupported\n");
		return -1ull;
	}
	addr = XETU_HV_IND_ADDR_VALID | offset;
	if (offset >= 0x1000 && offset < 0x1800)
		addr |= XETU_HV_IND_ADDR_4B;
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_ADDRESS, addr);
	if (rc != 0) {
		PHBERR(p, "XSCOM error addressing register 0x%x\n", offset);
		return -1ull;
	}
 	rc = xscom_read(p->chip_id, p->etu_xscom + XETU_HV_IND_DATA, &val);
	if (rc != 0) {
		PHBERR(p, "XSCOM error reading register 0x%x\n", offset);
		return -1ull;
	}
	return val;
#endif
}

static inline void phb4_write_reg_asb(struct phb4 *p,
				      uint32_t offset, uint64_t val)
{
#ifdef NO_ASB
	out_be64(p->regs + offset, val);
#else
	int64_t rc;
	uint64_t addr;

	/* Address register: must use 4 bytes for built-in config space.
	 *
	 * This path isn't usable for outbound configuration space
	 */
	if ((offset & 0xfffffffc) == PHB_CONFIG_DATA) {
		PHBERR(p, "XSCOM access to CONFIG_DATA unsupported\n");
		return;
	}
	addr = XETU_HV_IND_ADDR_VALID | offset;
	if (offset >= 0x1000 && offset < 0x1800)
		addr |= XETU_HV_IND_ADDR_4B;
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_ADDRESS, addr);
	if (rc != 0) {
		PHBERR(p, "XSCOM error addressing register 0x%x\n", offset);
		return;
	}
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_DATA, val);
	if (rc != 0) {
		PHBERR(p, "XSCOM error writing register 0x%x\n", offset);
		return;
	}
#endif
}

/* Helper to select an IODA table entry */
static inline void phb4_ioda_sel(struct phb4 *p, uint32_t table,
				 uint32_t addr, bool autoinc)
{
	out_be64(p->regs + PHB_IODA_ADDR,
		 (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

/* Check if AIB is fenced via PBCQ NFIR */
static bool phb4_fenced(struct phb4 *p)
{
	// FIXME
	return false;
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t phb4_pcicfg_check(struct phb4 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint8_t *pe)
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
	if (p->state == PHB4_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Fetch the PE# from cache */
	*pe = p->rte_cache[bdfn];

	return OPAL_SUCCESS;
}

static int64_t phb4_rc_read(struct phb4 *p, uint32_t offset, uint8_t sz,
			    void *data)
{
	uint32_t reg = offset & ~3;
	uint32_t oval;

	/* Some registers are handled locally */
	switch (reg) {
		/* Bridge base/limit registers are cached here as HW
		 * doesn't implement them (it hard codes values that
		 * will confuse a proper PCI implementation).
		 */
	case PCI_CFG_MEM_BASE:		/* Includes PCI_CFG_MEM_LIMIT */
		oval = p->rc_cache[(reg - 0x20) >> 2] & 0xfff0fff0;
		break;
	case PCI_CFG_PREF_MEM_BASE:	/* Includes PCI_CFG_PREF_MEM_LIMIT */
		oval = p->rc_cache[(reg - 0x20) >> 2] & 0xfff0fff0;
		oval |= 0x00010001;
		break;
	case PCI_CFG_IO_BASE_U16:	/* Includes PCI_CFG_IO_LIMIT_U16 */
		oval = 0;
		break;
	case PCI_CFG_PREF_MEM_BASE_U32:
	case PCI_CFG_PREF_MEM_LIMIT_U32:
		oval = p->rc_cache[(reg - 0x20) >> 2];
		break;
	default:
		/* XXX Add ASB support ? */
		oval = in_le32(p->regs + PHB_RC_CONFIG_BASE + reg);
	}
	switch (sz) {
	case 1:
		offset &= 3;
		*((uint8_t *)data) = (oval >> (offset << 3)) & 0xff;
		break;
	case 2:
		offset &= 2;
		*((uint16_t *)data) = (oval >> (offset << 3)) & 0xffff;
		break;
	case 4:
		*((uint32_t *)data) = oval;
		break;
	default:
		assert(false);
	}
	return OPAL_SUCCESS;
}

static int64_t phb4_rc_write(struct phb4 *p, uint32_t offset, uint8_t sz,
			     uint32_t val)
{
	uint32_t reg = offset & ~3;
	uint32_t old, mask, shift;
	int64_t rc;

	/* If size isn't 4-bytes, do a RMW cycle
	 *
	 * XXX TODO: Filter out registers that do write-1-to-clear !!!
	 */
	if (sz < 4) {
		rc = phb4_rc_read(p, reg, 4, &old);
		if (rc != OPAL_SUCCESS)
			return rc;
		if (sz == 1) {
			shift = (offset & 3) << 3;
			mask = 0xff << shift;
			val = (old & ~mask) | ((val & 0xff) << shift);
		} else {
			shift = (offset & 2) << 3;
			mask = 0xffff << shift;
			val = (old & ~mask) | ((val & 0xffff) << shift);
		}
	}

	/* Some registers are handled locally */
	switch (reg) {
		/* See comment in phb4_rc_read() */
	case PCI_CFG_MEM_BASE:		/* Includes PCI_CFG_MEM_LIMIT */
	case PCI_CFG_PREF_MEM_BASE:	/* Includes PCI_CFG_PREF_MEM_LIMIT */
	case PCI_CFG_PREF_MEM_BASE_U32:
	case PCI_CFG_PREF_MEM_LIMIT_U32:
		p->rc_cache[(reg - 0x20) >> 2] = val;
		break;
	case PCI_CFG_IO_BASE_U16:	/* Includes PCI_CFG_IO_LIMIT_U16 */
		break;
	default:
		/* XXX Add ASB support ? */
		out_le32(p->regs + PHB_RC_CONFIG_BASE + reg, val);
	}
	return OPAL_SUCCESS;
}

static int64_t phb4_pcicfg_read(struct phb4 *p, uint32_t bdfn,
				uint32_t offset, uint32_t size,
				void *data)
{
	uint64_t addr, val64;
	int64_t rc;
	uint8_t pe;
	bool use_asb = false;

	rc = phb4_pcicfg_check(p, bdfn, offset, size, &pe);
	if (rc)
		return rc;

	if (p->flags & PHB4_AIB_FENCED) {
		if (!(p->flags & PHB4_CFG_USE_ASB))
			return OPAL_HARDWARE;
		use_asb = true;
	} else if ((p->flags & PHB4_CFG_BLOCKED) && bdfn != 0) {
		return OPAL_HARDWARE;
	}

	/* Handle root complex MMIO based config space */
	if (bdfn == 0)
		return phb4_rc_read(p, offset, size, data);

	addr = PHB_CA_ENABLE;
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);
	addr = SETFIELD(PHB_CA_REG, addr, offset & ~3u);
	addr = SETFIELD(PHB_CA_PE, addr, pe);
	if (use_asb) {
		phb4_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);
		sync();
		val64 = bswap_64(phb4_read_reg_asb(p, PHB_CONFIG_DATA));
		switch(size) {
		case 1:
			*((uint8_t *)data) = val64 >> (8 * (offset & 3));
			break;
		case 2:
			*((uint16_t *)data) = val64 >> (8 * (offset & 2));
			break;
		case 4:
			*((uint32_t *)data) = val64;
			break;
		default:
			return OPAL_PARAMETER;
		}
	} else {
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);
#ifdef CFG_4B_WORKAROUND
		switch(size) {
		case 1:
			*((uint8_t *)data) =
				in_le32(p->regs + PHB_CONFIG_DATA) >> (8 * (offset & 3));
			break;
		case 2:
			*((uint16_t *)data) =
				in_le32(p->regs + PHB_CONFIG_DATA) >> (8 * (offset & 2));
			break;
		case 4:
			*((uint32_t *)data) = in_le32(p->regs + PHB_CONFIG_DATA);
			break;
		default:
			return OPAL_PARAMETER;
		}
#else
		switch(size) {
		case 1:
			*((uint8_t *)data) =
				in_8(p->regs + PHB_CONFIG_DATA + (offset & 3));
			break;
		case 2:
			*((uint16_t *)data) =
				in_le16(p->regs + PHB_CONFIG_DATA + (offset & 2));
			break;
		case 4:
			*((uint32_t *)data) = in_le32(p->regs + PHB_CONFIG_DATA);
			break;
		default:
			return OPAL_PARAMETER;
		}
#endif
	}
	return OPAL_SUCCESS;
}


#define PHB4_PCI_CFG_READ(size, type)					\
static int64_t phb4_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
                                      uint32_t offset, type *data)	\
{									\
	struct phb4 *p = phb_to_phb4(phb);				\
									\
	/* Initialize data in case of error */				\
	*data = (type)0xffffffff;					\
	return phb4_pcicfg_read(p, bdfn, offset, sizeof(type), data);	\
}

static int64_t phb4_pcicfg_write(struct phb4 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint32_t data)
{
	uint64_t addr;
	int64_t rc;
	uint8_t pe;
	bool use_asb = false;

	rc = phb4_pcicfg_check(p, bdfn, offset, size, &pe);
	if (rc)
		return rc;

	if (p->flags & PHB4_AIB_FENCED) {
		if (!(p->flags & PHB4_CFG_USE_ASB))
			return OPAL_HARDWARE;
		use_asb = true;
	} else if ((p->flags & PHB4_CFG_BLOCKED) && bdfn != 0) {
		return OPAL_HARDWARE;
	}

	/* Handle root complex MMIO based config space */
	if (bdfn == 0)
		return phb4_rc_write(p, offset, size, data);

	addr = PHB_CA_ENABLE;
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);
	addr = SETFIELD(PHB_CA_REG, addr, offset & ~3u);
	addr = SETFIELD(PHB_CA_PE, addr, pe);
	if (use_asb) {
		/* We don't support ASB config space writes */
		return OPAL_UNSUPPORTED;
	} else {
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);
#ifdef CFG_4B_WORKAROUND
		if (size < 4) {
			uint32_t old = in_le32(p->regs + PHB_CONFIG_DATA);
			uint32_t shift, mask;
			if (size == 1) {
				shift = (offset & 3) << 3;
				mask = 0xff << shift;
				data = (old & ~mask) | ((data & 0xff) << shift);
			} else {
				shift = (offset & 2) << 3;
				mask = 0xffff << shift;
				data = (old & ~mask) | ((data & 0xffff) << shift);
			}
		}
		out_le32(p->regs + PHB_CONFIG_DATA, data);

#else
		switch(size) {
		case 1:
			out_8(p->regs + PHB_CONFIG_DATA + (offset & 3), data);
			break;
		case 2:
			out_le16(p->regs + PHB_CONFIG_DATA + (offset & 2), data);
			break;
		case 4:
			out_le32(p->regs + PHB_CONFIG_DATA, data);
			break;
		default:
			return OPAL_PARAMETER;
		}
#endif
	}
        return OPAL_SUCCESS;
}

#define PHB4_PCI_CFG_WRITE(size, type)					\
static int64_t phb4_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
                                       uint32_t offset, type data)	\
{									\
	struct phb4 *p = phb_to_phb4(phb);				\
									\
	return phb4_pcicfg_write(p, bdfn, offset, sizeof(type), data);	\
}

PHB4_PCI_CFG_READ(8, u8)
PHB4_PCI_CFG_READ(16, u16)
PHB4_PCI_CFG_READ(32, u32)
PHB4_PCI_CFG_WRITE(8, u8)
PHB4_PCI_CFG_WRITE(16, u16)
PHB4_PCI_CFG_WRITE(32, u32)

static uint8_t phb4_choose_bus(struct phb *phb __unused,
			       struct pci_device *bridge __unused,
			       uint8_t candidate, uint8_t *max_bus __unused,
			       bool *use_max)
{
	/* Use standard bus number selection */
	*use_max = false;
	return candidate;
}

static int64_t phb4_get_reserved_pe_number(struct phb *phb)
{
	struct phb4 *p = phb_to_phb4(phb);

	return PHB4_RESERVED_PE_NUM(p);
}


static void phb4_root_port_init(struct phb *phb __unused,
				struct pci_device *dev __unused,
				int ecap __unused,
				int aercap __unused)
{
#if 0
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	// FIXME: check recommended init values for phb4

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

	if (!aercap) return;

	/* Mask various unrecoverable errors */
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
#endif
}

static void phb4_switch_port_init(struct phb *phb,
				  struct pci_device *dev,
				  int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	// FIXME: update AER settings for phb4

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
	/* HW279570 - Disable reporting of correctable errors */
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
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

	/*
	 * Mask various correctable errors
	 */
	val32 = PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC generation and disable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= PCIECAP_AER_CAPCTL_ECRCG_EN;
	val32 &= ~PCIECAP_AER_CAPCTL_ECRCC_EN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb4_endpoint_init(struct phb *phb,
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

	/* Enable ECRC generation and check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb4_check_device_quirks(struct phb *phb, struct pci_device *dev)
{
	// FIXME: add quirks later if necessary
}

static int phb4_device_init(struct phb *phb, struct pci_device *dev,
			    void *data __unused)
{
	int ecap = 0;
	int aercap = 0;

	/* Some special adapter tweaks for devices directly under the PHB */
	if (dev->primary_bus == 1)
		phb4_check_device_quirks(phb, dev);

	/* Figure out PCIe & AER capability */
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
		phb4_root_port_init(phb, dev, ecap, aercap);
	else if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT ||
		 dev->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		phb4_switch_port_init(phb, dev, ecap, aercap);
	else
		phb4_endpoint_init(phb, dev, ecap, aercap);

	return 0;
}

static int64_t phb4_pci_reinit(struct phb *phb, uint64_t scope, uint64_t data)
{
	struct pci_device *pd;
	uint16_t bdfn = data;
	int ret;

	if (scope != OPAL_REINIT_PCI_DEV)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	ret = phb4_device_init(phb, pd, NULL);
	if (ret)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

/* Clear IODA cache tables */
static void phb4_init_ioda_cache(struct phb4 *p)
{
	uint32_t i;
	uint64_t mbt0;

	/*
	 * RTT and PELTV. RTE should be 0xFF's to indicate
	 * invalid PE# for the corresponding RID.
	 *
	 * Note: Instead we set all RTE entries to 0x00 to
	 * work around a problem where PE lookups might be
	 * done before Linux has established valid PE's
	 * (during PCI probing). We can revisit that once/if
	 * Linux has been fixed to always setup valid PEs.
	 *
	 * The value 0x00 corresponds to the default PE# Linux
	 * uses to check for config space freezes before it
	 * has assigned PE# to busses.
	 *
	 * WARNING: Additionally, we need to be careful, there's
	 * a HW issue, if we get an MSI on an RTT entry that is
	 * FF, things will go bad. We need to ensure we don't
	 * ever let a live FF RTT even temporarily when resetting
	 * for EEH etc... (HW278969).
	 */
	for (i = 0; i < ARRAY_SIZE(p->rte_cache); i++)
		p->rte_cache[i] = PHB4_RESERVED_PE_NUM(p);
	memset(p->peltv_cache, 0x0,  sizeof(p->peltv_cache));
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));

	/* Since we configure the PHB4 with half the PE's, we need
	 * to give the illusion that we support  only 128/256 segments
	 * half the segments.
	 *
	 * To achieve that, we configure *all* the M64 windows to use
	 * column 1 of the MDT, which is itself set so that segment 0 and 1
	 * map to PE0, 2 and 3 to PE1 etc...
	 *
	 * Column 0, 2 and 3 are left all 0, column 0 will be used for M32
	 * and configured by the OS.
	 */
	mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
	mbt0 = SETFIELD(IODA3_MBT0_MDT_COLUMN, mbt0, 1);
	for (i = 0; i < p->mbt_size; i++) {
		p->mbt_cache[i][0] = mbt0;
		p->mbt_cache[i][1] = 0;
	}

	for (i = 0; i < p->max_num_pes; i++)
		p->mdt_cache[i] = SETFIELD(IODA3_MDT_PE_B, 0ull, i >> 1);

	/* XXX Should we mask them ? */
	memset(p->mist_cache, 0x0, sizeof(p->mist_cache));

	/* Initialise M32 bar using MDT entry 0 */
	p->mbt_cache[0][0] = IODA3_MBT0_TYPE_M32 |
		SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT) |
		SETFIELD(IODA3_MBT0_MDT_COLUMN, 0ull, 0) |
		(p->mm1_base & IODA3_MBT0_BASE_ADDR);
	p->mbt_cache[0][1] = IODA3_MBT1_ENABLE |
		((~(M32_PCI_SIZE - 1)) & IODA3_MBT1_MASK);
}

static int64_t phb4_wait_bit(struct phb4 *p, uint32_t reg,
			     uint64_t mask, uint64_t want_val)
{
	uint64_t val;

	/* Wait for all pending TCE kills to complete
	 *
	 * XXX Add timeout...
	 */
	/* XXX SIMICS is nasty... */
	if ((reg == PHB_TCE_KILL || reg == PHB_DMARD_SYNC) &&
	    chip_quirk(QUIRK_SIMICS))
		return OPAL_SUCCESS;

	for (;;) {
		val = in_be64(p->regs + reg);
		if (val == 0xffffffffffffffffull) {
			/* XXX Fenced ? */
			return OPAL_HARDWARE;
		}
		if ((val & mask) == want_val)
			break;

	}
	return OPAL_SUCCESS;
}

static int64_t phb4_tce_kill(struct phb *phb, uint32_t kill_type,
			     uint32_t pe_num, uint32_t tce_size,
			     uint64_t dma_addr, uint32_t npages)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t val;
	int64_t rc;

	sync();
	switch(kill_type) {
	case OPAL_PCI_TCE_KILL_PAGES:
		while (npages--) {
			/* Wait for a slot in the HW kill queue */
			rc = phb4_wait_bit(p, PHB_TCE_KILL,
					   PHB_TCE_KILL_ALL |
					   PHB_TCE_KILL_PE |
					   PHB_TCE_KILL_ONE, 0);
			if (rc)
				return rc;
			val = SETFIELD(PHB_TCE_KILL_PENUM, dma_addr, pe_num);

			/* Set appropriate page size */
			switch(tce_size) {
			case 0x1000:
				if (dma_addr & 0xf000000000000fffull)
					return OPAL_PARAMETER;
				break;
			case 0x10000:
				if (dma_addr & 0xf00000000000ffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_64K;
				break;
			case 0x200000:
				if (dma_addr & 0xf0000000001fffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_2M;
				break;
			case 0x40000000:
				if (dma_addr & 0xf00000003fffffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_1G;
				break;
			default:
				return OPAL_PARAMETER;
			}
			/* Perform kill */
			out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ONE | val);
			/* Next page */
			dma_addr += tce_size;
		}
		break;
	case OPAL_PCI_TCE_KILL_PE:
		/* Wait for a slot in the HW kill queue */
		rc = phb4_wait_bit(p, PHB_TCE_KILL,
				   PHB_TCE_KILL_ALL |
				   PHB_TCE_KILL_PE |
				   PHB_TCE_KILL_ONE, 0);
		if (rc)
			return rc;
		/* Perform kill */
		out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_PE |
			 SETFIELD(PHB_TCE_KILL_PENUM, 0ull, pe_num));
		break;
	case OPAL_PCI_TCE_KILL_ALL:
		/* Wait for a slot in the HW kill queue */
		rc = phb4_wait_bit(p, PHB_TCE_KILL,
				   PHB_TCE_KILL_ALL |
				   PHB_TCE_KILL_PE |
				   PHB_TCE_KILL_ONE, 0);
		if (rc)
			return rc;
		/* Perform kill */
		out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Start DMA sync process */
	out_be64(p->regs + PHB_DMARD_SYNC, PHB_DMARD_SYNC_START);

	/* Wait for kill to complete */
	rc = phb4_wait_bit(p, PHB_Q_DMA_R, PHB_Q_DMA_R_TCE_KILL_STATUS, 0);
	if (rc)
		return rc;

	/* Wait for DMA sync to complete */
	return phb4_wait_bit(p, PHB_DMARD_SYNC,
			     PHB_DMARD_SYNC_COMPLETE,
			     PHB_DMARD_SYNC_COMPLETE);
}

/* phb4_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t phb4_ioda_reset(struct phb *phb, bool purge)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t i;
	uint64_t val;

	if (purge) {
		prlog(PR_DEBUG, "PHB%d: Purging all IODA tables...\n",
		      p->phb.opal_id);
		phb4_init_ioda_cache(p);
	}

	/* Init_29..30 - Errata workaround, clear PEST */
	/* ... We do that further down as part of our normal IODA reset */

	/* Init_31..32 - MIST  */
	phb4_ioda_sel(p, IODA3_TBL_MIST, 0, true);
	val = in_be64(p->regs + PHB_IODA_ADDR);
	val = SETFIELD(PHB_IODA_AD_MIST_PWV, val, 0xf);
	out_be64(p->regs + PHB_IODA_ADDR, val);
	for (i = 0; i < (p->num_irqs/4); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->mist_cache[i]);

	/* Init_33..34 - MRT */
	phb4_ioda_sel(p, IODA3_TBL_MRT, 0, true);
	for (i = 0; i < p->mrt_size; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_35..36 - TVT */
	phb4_ioda_sel(p, IODA3_TBL_TVT, 0, true);
	for (i = 0; i < p->tvt_size; i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* Init_37..38 - MBT */
	phb4_ioda_sel(p, IODA3_TBL_MBT, 0, true);
	for (i = 0; i < p->mbt_size; i++) {
		out_be64(p->regs + PHB_IODA_DATA0, p->mbt_cache[i][0]);
		out_be64(p->regs + PHB_IODA_DATA0, p->mbt_cache[i][1]);
	}

	/* Init_39..40 - MDT */
	phb4_ioda_sel(p, IODA3_TBL_MDT, 0, true);
	for (i = 0; i < p->max_num_pes; i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->mdt_cache[i]);

	/* Clear RTT and PELTV */
	if (p->tbl_rtt)
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	if (p->tbl_peltv)
		memcpy((void *)p->tbl_peltv, p->peltv_cache, p->tbl_peltv_size);

	/* Clear PEST & PEEV */
	for (i = 0; i < p->max_num_pes; i++) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, i, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		phb4_ioda_sel(p, IODA3_TBL_PESTB, i, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}

	phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
	for (i = 0; i < p->max_num_pes/64; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Invalidate RTE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);

	return phb4_tce_kill(&p->phb, OPAL_PCI_TCE_KILL_ALL, 0, 0, 0, 0);
}

/*
 * Clear anything we have in PAPR Error Injection registers. Though
 * the spec says the PAPR error injection should be one-shot without
 * the "sticky" bit. However, that's false according to the experiments
 * I had. So we have to clear it at appropriate point in kernel to
 * avoid endless frozen PE.
 */
static int64_t phb4_papr_errinjct_reset(struct phb *phb)
{
	struct phb4 *p = phb_to_phb4(phb);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, 0x0ul);

	return OPAL_SUCCESS;
}

static int64_t phb4_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t addr,
				       uint64_t pci_addr,
				       uint64_t size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1;

	/*
	 * We have a unified MBT for all BARs on PHB4. However we
	 * also have a current limitation that only half of the PEs
	 * are available (in order to have 2 TVT entries per PE).
	 *
	 * So we use it as follow:
	 *
	 *  - M32 is hard wired to be MBT[0] and uses MDT column 0
	 *    for remapping.
	 *
	 *  - MBT[1..n] are available to the OS, currently only as
	 *    fully segmented or single PE (we don't yet expose the
	 *    new segmentation modes).
	 *
	 *  - In order to deal with the above PE# limitations, since
	 *    the OS assumes the segmentation is done with as many
	 *    segments as PEs, we effectively fake it by mapping all
	 *    MBT[1..n] to NDT column 1 which has been configured to
	 *    give 2 adjacent segments the same PE# (see comment in
	 *    ioda cache init). We don't expose the other columns to
	 *    the OS.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num == 0 || window_num >= p->mbt_size) {
			PHBERR(p, "%s: Invalid window %d\n",
			       __func__, window_num);
			return OPAL_PARAMETER;
		}

		mbt0 = p->mbt_cache[window_num][0];
		mbt1 = p->mbt_cache[window_num][1];

		/* XXX For now we assume the 4K minimum alignment,
		 * todo: check with the HW folks what the exact limits
		 * are based on the segmentation model.
		 */
		if ((addr & 0xFFFul) || (size & 0xFFFul)) {
			PHBERR(p, "%s: Bad addr/size alignment %llx/%llx\n",
			       __func__, addr, size);
			return OPAL_PARAMETER;
		}

		/* size should be 2^N */
		if (!size || size & (size-1)) {
			PHBERR(p, "%s: size not a power of 2: %llx\n",
			       __func__,  size);
			return OPAL_PARAMETER;
		}

		/* address should be size aligned */
		if (addr & (size - 1)) {
			PHBERR(p, "%s: addr not size aligned %llx/%llx\n",
			       __func__, addr, size);
			return OPAL_PARAMETER;
		}

		break;
	default:
		return OPAL_PARAMETER;
	}

	/* The BAR shouldn't be enabled yet */
	if (mbt0 & IODA3_MBT0_ENABLE)
		return OPAL_PARTIAL;

	/* Apply the settings */
	mbt0 = SETFIELD(IODA3_MBT0_BASE_ADDR, mbt0, addr >> 12);
	mbt1 = SETFIELD(IODA3_MBT1_MASK, mbt1, ~((size >> 12) -1));
	p->mbt_cache[window_num][0] = mbt0;
	p->mbt_cache[window_num][1] = mbt1;

	return OPAL_SUCCESS;
}

/*
 * For one specific M64 BAR, it can be shared by all PEs,
 * or owned by single PE exclusively.
 */
static int64_t phb4_phb_mmio_enable(struct phb __unused *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1, base, mask;

	/*
	 * By design, PHB4 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 *
	 * TODO: Add support for some of the new PHB4 split modes
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		/* Window 0 is reserved for M32 */
		if (window_num == 0 || window_num >= p->mbt_size ||
		    enable > OPAL_ENABLE_M64_NON_SPLIT)
			return OPAL_PARAMETER;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * We need check the base/mask while enabling
	 * the M64 BAR. Otherwise, invalid base/mask
	 * might cause fenced AIB unintentionally
	 */
	mbt0 = p->mbt_cache[window_num][0];
	mbt1 = p->mbt_cache[window_num][1];

	if (enable == OPAL_DISABLE_M64) {
		/* Reset the window to disabled & MDT mode */
		mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
		mbt1 = 0;
	} else {
		/* Verify that the mode is valid and consistent */
		if (enable == OPAL_ENABLE_M64_SPLIT) {
			if (GETFIELD(IODA3_MBT0_MODE, mbt0) !=
			    IODA3_MBT0_MODE_MDT)
				return OPAL_PARAMETER;
		} else if (enable == OPAL_ENABLE_M64_NON_SPLIT) {
			if (GETFIELD(IODA3_MBT0_MODE, mbt0) !=
			    IODA3_MBT0_MODE_SINGLE_PE)
				return OPAL_PARAMETER;
		} else
			return OPAL_PARAMETER;

		base = GETFIELD(IODA3_MBT0_BASE_ADDR, mbt0);
		base = (base << 12);
		mask = GETFIELD(IODA3_MBT1_MASK, mbt1);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		mbt0 |= IODA3_MBT0_ENABLE;
		mbt1 |= IODA3_MBT1_ENABLE;
	}

	/* Update HW and cache */
	p->mbt_cache[window_num][0] = mbt0;
	p->mbt_cache[window_num][1] = mbt1;
	phb4_ioda_sel(p, IODA3_TBL_MBT, window_num << 1, true);
	out_be64(p->regs + PHB_IODA_DATA0, mbt0);
	out_be64(p->regs + PHB_IODA_DATA0, mbt1);

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_mmio_window(struct phb *phb,
				       uint16_t pe_num,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1, mdt;

	if (pe_num >= p->num_pes)
		return OPAL_PARAMETER;

	/*
	 * We support a combined MDT that has 4 columns. We let the OS
	 * use kernel 0 for now, and we configure column1 ourselves
	 * to handle the "half PEs" problem and thus simulate having
	 * smaller segments. columns 2 and 3 are currently unused. We
	 * might later on find a way to let the OS exploit them.
	 */
	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= p->max_num_pes)
			return OPAL_PARAMETER;

		mdt = p->mdt_cache[segment_num];
		mdt = SETFIELD(IODA3_MDT_PE_A, mdt, pe_num);
		p->mdt_cache[segment_num] = mdt;
		phb4_ioda_sel(p, IODA3_TBL_MDT, segment_num, false);
		out_be64(p->regs + PHB_IODA_DATA0, mdt);
		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num == 0 || window_num >= p->mbt_size)
			return OPAL_PARAMETER;

		mbt0 = p->mbt_cache[window_num][0];
		mbt1 = p->mbt_cache[window_num][1];

		/* The BAR shouldn't be enabled yet */
		if (mbt0 & IODA3_MBT0_ENABLE)
			return OPAL_PARTIAL;

		/* Set to single PE mode and configure the PE */
		mbt0 = SETFIELD(IODA3_MBT0_MODE, mbt0,
				IODA3_MBT0_MODE_SINGLE_PE);
		mbt1 = SETFIELD(IODA3_MBT1_SINGLE_PE_NUM, mbt1, pe_num);
		p->mbt_cache[window_num][0] = mbt0;
		p->mbt_cache[window_num][1] = mbt1;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_dma_window(struct phb *phb,
				      uint16_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/*
	 * We configure the PHB in 2 TVE per PE mode to match phb3.
	 * Current Linux implementation *requires* the two windows per
	 * PE.
	 */

	/*
	 * Sanity check. We currently only support "2 window per PE" mode
	 * ie, only bit 59 of the PCI address is used to select the window
	 */
	if (pe_num >= p->num_pes || (window_id >> 1) != pe_num)
		return OPAL_PARAMETER;

	/*
	 * tce_table_size == 0 is used to disable an entry, in this case
	 * we ignore other arguments
	 */
	if (tce_table_size == 0) {
		phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		p->tve_cache[window_id] = 0;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 || tce_levels > 5 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* Encode TCE table size */
	data64 = SETFIELD(IODA3_TVT_TABLE_ADDR, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 31)
		return OPAL_PARAMETER;
	data64 = SETFIELD(IODA3_TVT_TCE_TABLE_SIZE, data64, tts_encoded);

	/* Encode TCE page size */
	switch (tce_page_size) {
	case 0x1000:	/* 4K */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 1);
		break;
	case 0x10000:	/* 64K */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 5);
		break;
	case 0x1000000:	/* 16M */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 13);
		break;
	case 0x10000000: /* 256M */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 17);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Encode number of levels */
	data64 = SETFIELD(IODA3_TVT_NUM_LEVELS, data64, tce_levels - 1);

	printf("PHB4: Setting TVE %d to 0x%016llx\n", window_id, data64);

	phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_dma_window_real(struct phb *phb,
					   uint16_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t end = pci_start_addr + pci_mem_size;
	uint64_t tve;

	if (pe_num >= p->num_pes ||
	    (window_id >> 1) != pe_num)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		/*
		 * Check that the start address has the right TVE index,
		 * we only support the 1 bit mode where each PE has 2
		 * TVEs
		 */
		if ((pci_start_addr >> 59) != (window_id & 1))
			return OPAL_PARAMETER;
		pci_start_addr &= ((1ull << 59) - 1);
		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 48);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51) | IODA3_TVT_NON_TRANSLATE_50;
	} else {
		/* Disable */
		tve = 0;
	}

	printf("PHB4: Setting TVE %d to 0x%016llx (non-xlate)\n", window_id, tve);
	phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t phb4_set_ive_pe(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t mist_idx;
	uint32_t mist_quad;
	uint32_t mist_shift;
	uint64_t val;

	if (pe_num >= p->num_pes || ive_num >= (p->num_irqs - 8))
		return OPAL_PARAMETER;

	mist_idx = ive_num >> 2;
	mist_quad = ive_num & 3;
	mist_shift = (3 - mist_quad) << 4;
	p->mist_cache[mist_idx] &= ~(0x0fffull << mist_shift);
	p->mist_cache[mist_idx] |=  ((uint64_t)pe_num) << mist_shift;

	/* Note: This has the side effect of clearing P/Q, so this
	 * shouldn't be called while the interrupt is "hot"
	 */

	phb4_ioda_sel(p, IODA3_TBL_MIST, mist_idx, false);

	/* We need to inject the appropriate MIST write enable bit
	 * in the IODA table address register
	 */
	val = in_be64(p->regs + PHB_IODA_ADDR);
	val = SETFIELD(PHB_IODA_AD_MIST_PWV, val, 8 >> mist_quad);
	out_be64(p->regs + PHB_IODA_ADDR, val);

	/* Write entry */
	out_be64(p->regs + PHB_IODA_DATA0, p->mist_cache[mist_idx]);

	return OPAL_SUCCESS;
}

static int64_t phb4_get_msi_32(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint32_t *msi_address,
			       uint32_t *message_data)
{
	struct phb4 *p = phb_to_phb4(phb);

	/*
	 * Sanity check. We needn't check on mve_number (PE#)
	 * on PHB3 since the interrupt source is purely determined
	 * by its DMA address and data, but the check isn't
	 * harmful.
	 */
	if (pe_num >= p->num_pes ||
	    ive_num >= (p->num_irqs - 8) ||
	    msi_range != 1 || !msi_address|| !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = 0xFFFF0000 | ((ive_num << 4) & 0xFFFFFE0F);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

static int64_t phb4_get_msi_64(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint64_t *msi_address,
			       uint32_t *message_data)
{
	struct phb4 *p = phb_to_phb4(phb);

	/* Sanity check */
	if (pe_num >= p->num_pes ||
	    ive_num >= (p->num_irqs - 8) ||
	    msi_range != 1 || !msi_address || !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = (0x1ul << 60) | ((ive_num << 4) & 0xFFFFFFFFFFFFFE0Ful);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

/*
 * The function can be called during error recovery for INF
 * and ER class. For INF case, it's expected to be called
 * when grabbing the error log. We will call it explicitly
 * when clearing frozen PE state for ER case.
 */
static void phb4_err_ER_clear(struct phb4 *p)
{
#if 0
	uint32_t val32;
	uint64_t val64;
	uint64_t fir = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 1: Grab the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 2/3/4: Take all inbound transactions */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 5/6/7: Clear pending non-fatal errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ul);
	val32 = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val32 & 0xe0700000) | 0x0f000f00);

	/* Rec 8/9/10: Clear pending fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 11/12/13: Clear pending non-fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 22/23/24: Clear root port errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 25/26/27: Enable IO and MMIO bar */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 28: Release the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 29...34: Clear UTL errors */
	val64 = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, val64);

	/* Rec 39...66: Clear PHB error trap */
	val64 = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, val64);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0x0ul);

	/* Rec 67/68: Clear FIR/WOF */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~fir);
	out_be64(p->regs + PHB_LEM_WOF, 0x0ul);
#endif
}

static void phb4_read_phb_status(struct phb4 *p,
				 struct OpalIoPhb4ErrorData *stat)
{
	memset(stat, 0, sizeof(struct OpalIoPhb4ErrorData));

	/* Error data common part */
	stat->common.version = OPAL_PHB_ERROR_DATA_VERSION_1;
	stat->common.ioType  = OPAL_PHB_ERROR_DATA_TYPE_PHB4;
	stat->common.len     = sizeof(struct OpalIoPhb4ErrorData);
}

static int64_t phb4_set_pe(struct phb *phb,
			   uint64_t pe_num,
                           uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mask, val, tmp, idx;
	int32_t all = 0;
	uint16_t *rte;

	/* Sanity check */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= p->num_pes || bdfn > 0xffff ||
	    bcompare > OpalPciBusAll ||
	    dcompare > OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare > OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_PARAMETER;

	/* Figure out the RID range */
	if (bcompare == OpalPciBusAny) {
		mask = 0x0;
		val  = 0x0;
		all  = 0x1;
	} else {
		tmp  = ((0x1 << (bcompare + 1)) - 1) << (15 - bcompare);
		mask = tmp;
		val  = bdfn & tmp;
	}

	if (dcompare == OPAL_IGNORE_RID_DEVICE_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0xf8;
		val  |= (bdfn & 0xf8);
	}

	if (fcompare == OPAL_IGNORE_RID_FUNCTION_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0x7;
		val  |= (bdfn & 0x7);
	}

	/* Map or unmap the RTT range */
	if (all == 0x7) {
		if (action == OPAL_MAP_PE) {
			for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++)
				p->rte_cache[idx] = pe_num;
		} else {
			for ( idx = 0; idx < ARRAY_SIZE(p->rte_cache); idx++)
				p->rte_cache[idx] = PHB4_RESERVED_PE_NUM(p);
		}
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	} else {
		rte = (uint16_t *)p->tbl_rtt;
		for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++, rte++) {
			if ((idx & mask) != val)
				continue;
			if (action == OPAL_MAP_PE)
				p->rte_cache[idx] = pe_num;
			else
				p->rte_cache[idx] = PHB4_RESERVED_PE_NUM(p);
			*rte = p->rte_cache[idx];
		}
	}

	/* Invalidate the entire RTC */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);

	return OPAL_SUCCESS;
}

static int64_t phb4_set_peltv(struct phb *phb,
			      uint32_t parent_pe,
			      uint32_t child_pe,
			      uint8_t state)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint8_t *peltv;
	uint32_t idx, mask;

	/* Sanity check */
	if (!p->tbl_peltv)
		return OPAL_HARDWARE;
	if (parent_pe >= p->num_pes || child_pe >= p->num_pes)
		return OPAL_PARAMETER;

	/* Find index for parent PE */
	idx = parent_pe * (p->max_num_pes / 8);
	idx += (child_pe / 8);
	mask = 0x1 << (7 - (child_pe % 8));

	peltv = (uint8_t *)p->tbl_peltv;
	peltv += idx;
	if (state) {
		*peltv |= mask;
		p->peltv_cache[idx] |= mask;
	} else {
		*peltv &= ~mask;
		p->peltv_cache[idx] &= ~mask;
	}

	return OPAL_SUCCESS;
}

static void phb4_prepare_link_change(struct pci_slot *slot, bool is_up)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint32_t reg32;

	p->has_link = is_up;

	if (is_up) {
		/* Clear AER receiver error status */
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_STATUS,
				    PCIECAP_AER_CE_RECVR_ERR);
		/* Unmask receiver error status in AER */
		phb4_pcicfg_read32(&p->phb, 0, p->aercap +
				   PCIECAP_AER_CE_MASK, &reg32);
		reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_MASK, reg32);

		/* Don't block PCI-CFG */
		p->flags &= ~PHB4_CFG_BLOCKED;

		/*
		 * We might lose the bus numbers during the reset operation
		 * and we need to restore them. Otherwise, some adapters (e.g.
		 * IPR) can't be probed properly by the kernel. We don't need
		 * to restore bus numbers for every kind of reset, however,
		 * it's not harmful to always restore the bus numbers, which
		 * simplifies the logic.
		 */
		pci_restore_bridge_buses(slot->phb, slot->pd);
		if (slot->phb->ops->device_init)
			pci_walk_dev(slot->phb, slot->pd,
				     slot->phb->ops->device_init, NULL);
	} else {
		/* Mask AER receiver error */
		phb4_pcicfg_read32(&p->phb, 0, p->aercap +
				   PCIECAP_AER_CE_MASK, &reg32);
		reg32 |= PCIECAP_AER_CE_RECVR_ERR;
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_MASK, reg32);
		/* Block PCI-CFG access */
		p->flags |= PHB4_CFG_BLOCKED;
	}
}

static int64_t phb4_get_presence_state(struct pci_slot *slot, uint8_t *val)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t hps, dtctl;

	/* Test for PHB in error state ? */
	if (p->state == PHB4_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Read hotplug status */
	hps = in_be64(p->regs + PHB_PCIE_HOTPLUG_STATUS);

	/* Read link status */
	dtctl = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);

	PHBDBG(p, "hp_status=0x%016llx, dlp_train_ctl=0x%016llx\n",
	       hps, dtctl);

	/* Check presence detect */
	if (hps & PHB_PCIE_HPSTAT_PRESENCE) {
		/* If it says not present but link is up, then we assume
		 * we are on a broken simulation environment and still
		 * return a valid presence. Otherwise, not present.
		 */
		if (dtctl & PHB_PCIE_DLP_TL_LINKACT) {
			PHBERR(p, "Presence detect 0 but link set !\n");
			return OPAL_SHPC_DEV_PRESENT;
		}
		return OPAL_SHPC_DEV_NOT_PRESENT;
	}

	/*
	 * Anything else, we assume device present, the link state
	 * machine will perform an early bail out if no electrical
	 * signaling is established after a second.
	 */
	return OPAL_SHPC_DEV_PRESENT;
}

static int64_t phb4_get_link_state(struct pci_slot *slot, uint8_t *val)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t reg;
	uint16_t state;
	int64_t rc;

	/* Link is up, let's find the actual speed */
	reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	if (!(reg & PHB_PCIE_DLP_TL_LINKACT)) {
		*val = 0;
		return OPAL_SUCCESS;
	}

	rc = phb4_pcicfg_read16(&p->phb, 0,
				p->ecap + PCICAP_EXP_LSTAT, &state);
	if (rc != OPAL_SUCCESS) {
		PHBERR(p, "%s: Error %lld getting link state\n", __func__, rc);
		return OPAL_HARDWARE;
	}

	if (state & PCICAP_EXP_LSTAT_DLLL_ACT)
		*val = ((state & PCICAP_EXP_LSTAT_WIDTH) >> 4);
	else
		*val = 0;

	return OPAL_SUCCESS;
}

static int64_t phb4_retry_state(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);

	if (slot->retry_state == PCI_SLOT_STATE_NORMAL)
		return OPAL_WRONG_STATE;

	PHBDBG(p, "Retry state %08x\n", slot->retry_state);
	slot->delay_tgt_tb = 0;
	pci_slot_set_state(slot, slot->retry_state);
	slot->retry_state = PCI_SLOT_STATE_NORMAL;
	return slot->ops.poll(slot);
}

static int64_t phb4_poll_link(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t reg;
	int64_t rc;

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
	case PHB4_SLOT_LINK_START:
		PHBDBG(p, "LINK: Start polling\n");
		slot->retries = PHB4_LINK_ELECTRICAL_RETRIES;
		pci_slot_set_state(slot, PHB4_SLOT_LINK_WAIT_ELECTRICAL);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB4_SLOT_LINK_WAIT_ELECTRICAL:
		/*
		 * Wait for the link electrical connection to be
		 * established (shorter timeout). This allows us to
		 * workaround spurrious presence detect on some machines
		 * without waiting 10s each time
		 *
		 * Note: We *also* check for the full link up bit here
		 * because simics doesn't seem to implement the electrical
		 * link bit at all
		 */
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & (PHB_PCIE_DLP_INBAND_PRESENCE |
			   PHB_PCIE_DLP_TL_LINKACT)) {
			PHBDBG(p, "LINK: Electrical link detected\n");
			pci_slot_set_state(slot, PHB4_SLOT_LINK_WAIT);
			slot->retries = PHB4_LINK_WAIT_RETRIES;
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
		}

		if (slot->retries-- == 0) {
			PHBDBG(p, "LINK: Timeout waiting for electrical link\n");
			PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
			rc = phb4_retry_state(slot);
			if (rc >= OPAL_SUCCESS)
				return rc;

			pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB4_SLOT_LINK_WAIT:
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & PHB_PCIE_DLP_TL_LINKACT) {
			PHBDBG(p, "LINK: Link is up\n");
			if (slot->ops.prepare_link_change)
				slot->ops.prepare_link_change(slot, true);
			pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}

		if (slot->retries-- == 0) {
			PHBDBG(p, "LINK: Timeout waiting for link up\n");
			PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
			rc = phb4_retry_state(slot);
			if (rc >= OPAL_SUCCESS)
				return rc;

			pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	default:
		PHBERR(p, "LINK: Unexpected slot state %08x\n",
		       slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb4_hreset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint16_t brctl;
	uint8_t presence = 1;

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
		PHBDBG(p, "HRESET: Starts\n");
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "HRESET: No device\n");
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "HRESET: Prepare for link down\n");
		if (slot->ops.prepare_link_change)
			slot->ops.prepare_link_change(slot, false);
		/* fall through */
	case PHB4_SLOT_HRESET_START:
		PHBDBG(p, "HRESET: Assert\n");

		phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		pci_slot_set_state(slot, PHB4_SLOT_HRESET_DELAY);

		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB4_SLOT_HRESET_DELAY:
		PHBDBG(p, "HRESET: Deassert\n");

		phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);

		/*
		 * Due to some oddball adapters bouncing the link
		 * training a couple of times, we wait for a full second
		 * before we start checking the link status, otherwise
		 * we can get a spurrious link down interrupt which
		 * causes us to EEH immediately.
		 */
		pci_slot_set_state(slot, PHB4_SLOT_HRESET_DELAY2);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB4_SLOT_HRESET_DELAY2:
		pci_slot_set_state(slot, PHB4_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb4_pfreset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint8_t presence = 1;
	uint64_t reg;

	switch(slot->state) {
	case PHB4_SLOT_NORMAL:
		PHBDBG(p, "PFRESET: Starts\n");

		/* Nothing to do without adapter connected */
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "PFRESET: No device\n");
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "PFRESET: Prepare for link down\n");
		slot->retry_state = PHB4_SLOT_PFRESET_START;
		if (slot->ops.prepare_link_change)
			slot->ops.prepare_link_change(slot, false);
		/* fall through */
	case PHB4_SLOT_PFRESET_START:
		if (!p->skip_perst) {
			PHBDBG(p, "PFRESET: Assert\n");
			reg = in_be64(p->regs + PHB_PCIE_CRESET);
			reg &= ~PHB_PCIE_CRESET_PERST_N;
			out_be64(p->regs + PHB_PCIE_CRESET, reg);
			pci_slot_set_state(slot,
				PHB4_SLOT_PFRESET_ASSERT_DELAY);
			return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
		}

		/* To skip the assert during boot time */
		PHBDBG(p, "PFRESET: Assert skipped\n");
		pci_slot_set_state(slot, PHB4_SLOT_PFRESET_ASSERT_DELAY);
		p->skip_perst = false;
		/* fall through */
	case PHB4_SLOT_PFRESET_ASSERT_DELAY:
		PHBDBG(p, "PFRESET: Deassert\n");
		reg = in_be64(p->regs + PHB_PCIE_CRESET);
		reg |= PHB_PCIE_CRESET_PERST_N;
		out_be64(p->regs + PHB_PCIE_CRESET, reg);
		pci_slot_set_state(slot,
			PHB4_SLOT_PFRESET_DEASSERT_DELAY);

		/* CAPP FPGA requires 1s to flash before polling link */
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB4_SLOT_PFRESET_DEASSERT_DELAY:
		pci_slot_set_state(slot, PHB4_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb4_creset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
	case PHB4_SLOT_CRESET_START:
		PHBDBG(p, "CRESET: Starts\n");

		/* do steps 3-5 of capp recovery procedure */
#if 0
		if (p->flags & PHB4_CAPP_RECOVERY)
			do_capp_recovery_scoms(p);
#endif
		/* XXX TODO XXX */

		pci_slot_set_state(slot, PHB4_SLOT_CRESET_WAIT_CQ);
		slot->retries = 500;
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB4_SLOT_CRESET_WAIT_CQ:
		/* XXX TODO XXX */
		pci_slot_set_state(slot, PHB4_SLOT_CRESET_REINIT);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB4_SLOT_CRESET_REINIT:
		p->flags &= ~PHB4_AIB_FENCED;
		p->flags &= ~PHB4_CAPP_RECOVERY;
		phb4_init_hw(p, false);
		pci_slot_set_state(slot, PHB4_SLOT_CRESET_FRESET);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB4_SLOT_CRESET_FRESET:
		pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
		return slot->ops.freset(slot);
	default:
		PHBERR(p, "CRESET: Unexpected slot state %08x\n",
		       slot->state);
	}

	/* Mark the PHB as dead and expect it to be removed */
	p->state = PHB4_STATE_BROKEN;
	return OPAL_HARDWARE;
}

/*
 * Initialize root complex slot, which is mainly used to
 * do fundamental reset before PCI enumeration in PCI core.
 * When probing root complex and building its real slot,
 * the operations will be copied over.
 */
static struct pci_slot *phb4_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = phb4_get_presence_state;
	slot->ops.get_link_state      = phb4_get_link_state;
	slot->ops.get_power_state     = NULL;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	/*
	 * For PHB slots, we have to split the fundamental reset
	 * into 2 steps. We might not have the first step which
	 * is to power off/on the slot, or it's controlled by
	 * individual platforms.
	 */
	slot->ops.prepare_link_change	= phb4_prepare_link_change;
	slot->ops.poll_link		= phb4_poll_link;
	slot->ops.hreset		= phb4_hreset;
	slot->ops.freset		= phb4_pfreset;
	slot->ops.pfreset		= phb4_pfreset;
	slot->ops.creset		= phb4_creset;

	return slot;
}

static int64_t phb4_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				      uint8_t *freeze_state,
				      uint16_t *pci_error_type,
				      uint16_t *severity,
				      uint64_t *phb_status)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t peev_bit = PPC_BIT(pe_number & 0x3f);
	uint64_t peev, pesta, pestb;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	/* Check dead */
	if (p->state == PHB4_STATE_BROKEN) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_HARDWARE;
	}

	/* Check fence and CAPP recovery */
	if (phb4_fenced(p) || (p->flags & PHB4_CAPP_RECOVERY)) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		goto bail;
	}

	/* Check the PEEV */
	phb4_ioda_sel(p, IODA3_TBL_PEEV, pe_number / 64, false);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

	/* Indicate that we have an ER pending */
	phb4_set_err_pending(p, true);
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the PESTA & PESTB */
	phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
	pesta = in_be64(p->regs + PHB_IODA_DATA0);
	phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
	pestb = in_be64(p->regs + PHB_IODA_DATA0);

	/* Convert them */
	if (pesta & IODA3_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA3_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

bail:
	if (phb_status)
		PHBERR(p, "%s: deprecated PHB status\n", __func__);

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t err, peev;
	int32_t i;
	bool frozen_pe = false;

	if (p->state == PHB4_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitely by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err == 0xffffffffffffffff) {
		if (phb4_fenced(p)) {
			PHBERR(p, "eeh_freeze_clear on fenced PHB\n");
			return OPAL_HARDWARE;
		}
	}
	if (err != 0)
		phb4_err_ER_clear(p);

	/*
	 * We have PEEV in system memory. It would give more performance
	 * to access that directly.
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


	/* Update ER pending indication */
	phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
	for (i = 0; i < p->num_pes/64; i++) {
		peev = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev) {
			frozen_pe = true;
			break;
		}
	}
	if (frozen_pe) {
		p->err.err_src	 = PHB4_ERR_SRC_PHB;
		p->err.err_class = PHB4_ERR_CLASS_ER;
		p->err.err_bit   = -1;
		phb4_set_err_pending(p, true);
	} else
		phb4_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_freeze_set(struct phb *phb, uint64_t pe_number,
                                   uint64_t eeh_action_token)
{
        struct phb4 *p = phb_to_phb4(phb);
        uint64_t data;

	if (p->state == PHB4_STATE_BROKEN)
		return OPAL_HARDWARE;

	if (pe_number >= p->num_pes)
		return OPAL_PARAMETER;

	if (eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_MMIO &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_DMA &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_ALL)
		return OPAL_PARAMETER;

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_MMIO) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA3_PESTA_MMIO_FROZEN;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_DMA) {
		phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA3_PESTB_DMA_STOPPED;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t peev;
	uint32_t peev_size = p->num_pes/64;
	int32_t i, j;

	/* If the PHB is broken, we needn't go forward */
	if (p->state == PHB4_STATE_BROKEN) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	if ((p->flags & PHB4_CAPP_RECOVERY)) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/*
	 * Check if we already have pending errors. If that's
	 * the case, then to get more information about the
	 * pending errors. Here we try PBCQ prior to PHB.
	 */
	if (phb4_err_pending(p) /*&&
	    !phb4_err_check_pbcq(p) &&
	    !phb4_err_check_lem(p) */)
		phb4_set_err_pending(p, false);

	/* Clear result */
	*pci_error_type  = OPAL_EEH_NO_ERROR;
	*severity	 = OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check frozen PEs */
	if (!phb4_err_pending(p)) {
		phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
		for (i = 0; i < peev_size; i++) {
			peev = in_be64(p->regs + PHB_IODA_DATA0);
			if (peev) {
				p->err.err_src	 = PHB4_ERR_SRC_PHB;
				p->err.err_class = PHB4_ERR_CLASS_ER;
				p->err.err_bit	 = -1;
				phb4_set_err_pending(p, true);
				break;
			}
		}
        }

	/* Mapping errors */
	if (phb4_err_pending(p)) {
		/*
		 * If the frozen PE is caused by a malfunctioning TLP, we
		 * need reset the PHB. So convert ER to PHB-fatal error
		 * for the case.
		 */
		if (p->err.err_class == PHB4_ERR_CLASS_ER) {
#if 0
			// FIXME XXXXX
			fir = phb4_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
			if (fir & PPC_BIT(60)) {
				phb4_pcicfg_read32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_STATUS, &cfg32);
				if (cfg32 & PCIECAP_AER_UE_MALFORMED_TLP)
					p->err.err_class = PHB4_ERR_CLASS_FENCED;
			}
#endif
		}

		switch (p->err.err_class) {
		case PHB4_ERR_CLASS_DEAD:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_DEAD;
			break;
		case PHB4_ERR_CLASS_FENCED:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_FENCED;
			break;
		case PHB4_ERR_CLASS_ER:
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;

			for (i = peev_size - 1; i >= 0; i--) {
				phb4_ioda_sel(p, IODA3_TBL_PEEV, i, false);
				peev = in_be64(p->regs + PHB_IODA_DATA0);
				for (j = 0; j < 64; j++) {
					if (peev & PPC_BIT(j)) {
						*first_frozen_pe = i * 64 + j;
						break;
					}
				}

				if (*first_frozen_pe != (uint64_t)(-1))
					break;
			}

			/* No frozen PE ? */
			if (*first_frozen_pe == (uint64_t)-1) {
				*pci_error_type = OPAL_EEH_NO_ERROR;
				*severity = OPAL_EEH_SEV_NO_ERROR;
				phb4_set_err_pending(p, false);
			}

                        break;
		case PHB4_ERR_CLASS_INF:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_INF;
			break;
		default:
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			phb4_set_err_pending(p, false);
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_err_inject(struct phb *phb, uint32_t pe_no,
			       uint32_t type, uint32_t func,
			       uint64_t addr, uint64_t mask)
{
	return OPAL_UNSUPPORTED;
}

static int64_t phb4_get_diag_data(struct phb *phb,
				  void *diag_buffer,
				  uint64_t diag_buffer_len)
{
	struct phb4 *p = phb_to_phb4(phb);
	struct OpalIoPhb4ErrorData *data = diag_buffer;

	if (diag_buffer_len < sizeof(struct OpalIoPhb4ErrorData))
		return OPAL_PARAMETER;
	if (p->state == PHB4_STATE_BROKEN)
		return OPAL_HARDWARE;

	/*
	 * Dummy check for fence so that phb4_read_phb_status knows
	 * whether to use ASB or AIB
	 */
	phb4_fenced(p);
	phb4_read_phb_status(p, data);

	/*
	 * We're running to here probably because of errors
	 * (INF class). For that case, we need clear the error
	 * explicitly.
	 */
	if (phb4_err_pending(p) &&
	    p->err.err_class == PHB4_ERR_CLASS_INF &&
	    p->err.err_src == PHB4_ERR_SRC_PHB) {
		phb4_err_ER_clear(p);
		phb4_set_err_pending(p, false);
	}

	return OPAL_SUCCESS;
}

static const struct phb_ops phb4_ops = {
	.cfg_read8		= phb4_pcicfg_read8,
	.cfg_read16		= phb4_pcicfg_read16,
	.cfg_read32		= phb4_pcicfg_read32,
	.cfg_write8		= phb4_pcicfg_write8,
	.cfg_write16		= phb4_pcicfg_write16,
	.cfg_write32		= phb4_pcicfg_write32,
	.choose_bus		= phb4_choose_bus,
	.get_reserved_pe_number	= phb4_get_reserved_pe_number,
	.device_init		= phb4_device_init,
	.ioda_reset		= phb4_ioda_reset,
	.papr_errinjct_reset	= phb4_papr_errinjct_reset,
	.pci_reinit		= phb4_pci_reinit,
	.set_phb_mem_window	= phb4_set_phb_mem_window,
	.phb_mmio_enable	= phb4_phb_mmio_enable,
	.map_pe_mmio_window	= phb4_map_pe_mmio_window,
	.map_pe_dma_window	= phb4_map_pe_dma_window,
	.map_pe_dma_window_real = phb4_map_pe_dma_window_real,
	.set_xive_pe		= phb4_set_ive_pe,
	.get_msi_32		= phb4_get_msi_32,
	.get_msi_64		= phb4_get_msi_64,
	.set_pe			= phb4_set_pe,
	.set_peltv		= phb4_set_peltv,
	.eeh_freeze_status	= phb4_eeh_freeze_status,
	.eeh_freeze_clear	= phb4_eeh_freeze_clear,
	.eeh_freeze_set		= phb4_eeh_freeze_set,
	.next_error		= phb4_eeh_next_error,
	.err_inject		= phb4_err_inject,
	.get_diag_data		= NULL,
	.get_diag_data2		= phb4_get_diag_data,
	.tce_kill		= phb4_tce_kill,
};

static void phb4_init_ioda3(struct phb4 *p)
{
	/* Init_17 - Interrupt Notify Base Address */
	out_be64(p->regs + PHB_INT_NOTIFY_ADDR, p->irq_port);

	/* Init_18 - Interrupt Notify Base Index */
	out_be64(p->regs + PHB_INT_NOTIFY_INDEX, p->base_msi);

	/* Init_xx - Not in spec: Initialize source ID */
	PHBDBG(p, "Reset state SRC_ID: %016llx\n",
	       in_be64(p->regs + PHB_LSI_SOURCE_ID));
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ull, (p->num_irqs - 1) >> 3));

	/* Init_19 - RTT BAR */
	out_be64(p->regs + PHB_RTT_BAR, p->tbl_rtt | PHB_RTT_BAR_ENABLE);

	/* Init_20 - PELT-V BAR */
	out_be64(p->regs + PHB_PELTV_BAR, p->tbl_peltv | PHB_PELTV_BAR_ENABLE);

	/* Init_21 - Setup M32 starting address */
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_22 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR,
		 p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_23 - CRW Base Address Reg */
	// XXX FIXME learn CAPI :-(

	/* Init_24 - ASN Compare/Mask */
	// XXX FIXME learn CAPI :-(

	/* Init_25 - CAPI Compare/Mask */
	// XXX FIXME learn CAPI :-(

	/* Init_26 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_27 - PHB4 Configuration */
	out_be64(p->regs + PHB_PHB4_CONFIG,
		 PHB_PHB4C_32BIT_MSI_EN |
		 PHB_PHB4C_64BIT_MSI_EN);

	/* Init_28 - At least 256ns delay according to spec. Do a dummy
	 * read first to flush posted writes
	 */
	in_be64(p->regs + PHB_PHB4_CONFIG);
	time_wait_us(2);

	/* Init_29..40 - On-chip IODA tables init */
	phb4_ioda_reset(&p->phb, false);
}

/* phb4_init_rc - Initialize the Root Complex config space
 */
static bool phb4_init_rc_cfg(struct phb4 *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_45:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	phb4_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_46 - Clear errors */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, 0xffff);

	/* Init_47
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 512. This has proved to have
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

	phb4_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	phb4_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_48 - Device Control/Status 2 */
	phb4_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 0x5) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_49..53
	 *
	 * AER inits
	 */
	aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
	if (aercap < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to locate AER Ecapability in bridge\n");
		return false;
	}
	p->aercap = aercap;

	/* Clear all UE status */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB4 spec */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT);
 
	/* Clear all CE status */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Enable ECRC generation & checking */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CAPCTL,
			     PCIECAP_AER_CAPCTL_ECRCG_EN	|
			     PCIECAP_AER_CAPCTL_ECRCC_EN);
	/* Clear root error status */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);

	return true;
}

static void phb4_init_errors(struct phb4 *p)
{
	/* Init_54..62 - PBL errors */
	out_be64(p->regs + 0x1900,	0xffffffffffffffffull);
	out_be64(p->regs + 0x1908,	0x0000000000000000ull);
	out_be64(p->regs + 0x1920,	0x000000004d1780f8ull);
	out_be64(p->regs + 0x1928,	0x0000000000000000ull);
	out_be64(p->regs + 0x1930,	0xffffffffb2e87f07ull);
	out_be64(p->regs + 0x1940,	0x0000000000000000ull);
	out_be64(p->regs + 0x1948,	0x0000000000000000ull);
	out_be64(p->regs + 0x1950,	0x0000000000000000ull);
	out_be64(p->regs + 0x1958,	0x0000000000000000ull);

	/* Init_63..71 - REGB errors */
	out_be64(p->regs + 0x1c00,	0xffffffffffffffffull);
	out_be64(p->regs + 0x1c08,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c20,	0x2130006efca8bc00ull);
	out_be64(p->regs + 0x1c28,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c30,	0xde8fff91035743ffull);
	out_be64(p->regs + 0x1c40,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c48,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c50,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c58,	0x0000000000000000ull);

	/* Init_72..80 - TXE errors */
	out_be64(p->regs + 0x0d00,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0d08,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d18,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0d28,	0x0000420a00000000ull);
	out_be64(p->regs + 0x0d30,	0xdff7bd01f7ddfff0ull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0d40,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d48,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d50,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d58,	0x0000000000000000ull);

	/* Init_81..89 - RXE_ARB errors */
	out_be64(p->regs + 0x0d80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0d88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d98,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0da8,	0xd00000b801000060ull);
	out_be64(p->regs + 0x0db0,	0x2bffd703fe7fbf8full); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0dc0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dc8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dd0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dd8,	0x0000000000000000ull);

	/* Init_90..98 - RXE_MRG errors */
	out_be64(p->regs + 0x0e00,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e08,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e18,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e28,	0x0000600000000000ull);
	out_be64(p->regs + 0x0e30,	0xffff9effff7fff57ull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0e40,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e48,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e50,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e58,	0x0000000000000000ull);

	/* Init_99..107 - RXE_TCE errors */
	out_be64(p->regs + 0x0e80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e98,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0ea8,	0x6000000000000000ull);
	out_be64(p->regs + 0x0eb0,	0x9baeffaf00000000ull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0ec0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ec8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ed0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ed8,	0x0000000000000000ull);

	/* Init_108..116 - RXPHB errors */
	out_be64(p->regs + 0x0c80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0c88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0c98,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0ca8,	0x0000004000000000ull);
	out_be64(p->regs + 0x0cb0,	0x35777033ff000000ull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0cc0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cc8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cd0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cd8,	0x0000000000000000ull);

	/* Init_117..120 - LEM */
	out_be64(p->regs + 0x0c00,	0x0000000000000000ull);
	out_be64(p->regs + 0x0c30,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0c38,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0c40,	0x0000000000000000ull);
}


static void phb4_init_hw(struct phb4 *p, bool first_init)
{
	uint64_t val, creset;

	PHBDBG(p, "Initializing PHB4...\n");

	/* Init_1 - Async reset
	 *
	 * At this point we assume the PHB has already been reset.
	 */

	/* Init_2 - Mask FIRs */
	out_be64(p->regs + 0xc18,				0xffffffffffffffffull);

	/* Init_3 - TCE tag enable */
	out_be64(p->regs + 0x868,				0xffffffffffffffffull);

	/* Init_4 - PCIE System Configuration Register
	 *
	 * Adjust max speed based on system config
	 */
	val = in_be64(p->regs + PHB_PCIE_SCR);
	PHBDBG(p, "Default system config: 0x%016llx\n", val);
	val = SETFIELD(PHB_PCIE_SCR_MAXLINKSPEED, val, p->max_link_speed);
	out_be64(p->regs + PHB_PCIE_SCR, val);
	PHBDBG(p, "New system config    : 0x%016llx\n",
	       in_be64(p->regs + PHB_PCIE_SCR));

	/* Init_5 - deassert CFG reset */
	creset = in_be64(p->regs + PHB_PCIE_CRESET);
	PHBDBG(p, "Initial PHB CRESET is 0x%016llx\n", creset);
	creset &= ~PHB_PCIE_CRESET_CFG_CORE;
	out_be64(p->regs + PHB_PCIE_CRESET,			creset);

	/* Init_6..13 - PCIE DLP Lane EQ control */
	if (p->lane_eq) {
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL0, be64_to_cpu(p->lane_eq[0]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL1, be64_to_cpu(p->lane_eq[1]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL2, be64_to_cpu(p->lane_eq[2]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL3, be64_to_cpu(p->lane_eq[3]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL20, be64_to_cpu(p->lane_eq[4]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL21, be64_to_cpu(p->lane_eq[5]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL22, be64_to_cpu(p->lane_eq[6]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL23, be64_to_cpu(p->lane_eq[7]));
	}

	/* Init_14 - Clear link training */
	phb4_pcicfg_write32(&p->phb, 0, 0x78, 0x0000FE07);

	/* Init_15 - deassert cores reset */
	/*
	 * Lift the PHB resets but not PERST, this will be lifted
	 * later by the initial PERST state machine
	 */
	creset &= ~(PHB_PCIE_CRESET_TLDLP | PHB_PCIE_CRESET_PBL);
	creset |= PHB_PCIE_CRESET_PIPE_N;
	out_be64(p->regs + PHB_PCIE_CRESET,			   creset);

	/* Init_16 - PHB Control */
	out_be64(p->regs + PHB_CTRLR,
		 PHB_CTRLR_IRQ_PGSZ_64K |
		 PHB_CTRLR_CFG_EEH_DISABLE | /* EEH disable for now ! */
		 SETFIELD(PHB_CTRLR_TVT_ADDR_SEL, 0ull, TVT_2_PER_PE));

	/* Init_17..40 - Architected IODA3 inits */
	phb4_init_ioda3(p);

	/* Init_41..44 - Clear DLP error logs */
	out_be64(p->regs + 0x1aa0,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1aa8,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1ab0,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1ab8,			0x0);


	/* Init_45..53 : Init root complex config space */
	if (!phb4_init_rc_cfg(p))
		goto failed;

	/* Init_54..120  : Setup error registers */
	phb4_init_errors(p);

	/* Init_121..122 : Wait for link
         * NOTE: At this point the spec waits for the link to come up. We
	 * don't bother as we are doing a PERST soon.
	 */

	/* Init_123 :  NBW. XXX TODO */
	// XXX FIXME learn CAPI :-(

	/* Init_124 : Setup PCI command/status on root complex
         * I don't know why the spec does this now and not earlier, so
	 * to be sure to get it right we might want to move it to the freset
	 * state machine, though the generic PCI layer will probably do
	 * this anyway (ie, enable MEM, etc... in the RC)

	 */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			    PCI_CFG_CMD_MEM_EN |
			    PCI_CFG_CMD_BUS_MASTER_EN);

	/* Clear errors */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			    PCI_CFG_STAT_SENT_TABORT |
			    PCI_CFG_STAT_RECV_TABORT |
			    PCI_CFG_STAT_RECV_MABORT |
			    PCI_CFG_STAT_SENT_SERR |
			    PCI_CFG_STAT_RECV_PERR);

	/* Init_125..130 - Re-enable error interrupts */
	/* XXX TODO along with EEH/error interrupts support */

	/* Init_131 - Enable DMA address speculation */
	out_be64(p->regs + PHB_TCE_SPEC_CTL,			0xf000000000000000ull);

	/* Init_132 - Timeout Control Register 1 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,			0x0018150000200000ull);

	/* Init_133 - Timeout Control Register 2 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,			0x0000181700000000ull);

	/* Init_134 - PBL Timeout Control Register */
	out_be64(p->regs + PHB_PBL_TIMEOUT_CTRL,		0x2015000000000000ull);

	/* Mark the PHB as functional which enables all the various sequences */
	p->state = PHB4_STATE_FUNCTIONAL;

	PHBDBG(p, "Initialization complete\n");

	return;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->state = PHB4_STATE_BROKEN;
}

/* FIXME: Use scoms rather than MMIO incase we are fenced */
static bool phb4_read_capabilities(struct phb4 *p)
{
	uint64_t val;

	/* XXX Should make sure ETU is out of reset ! */

	/* Grab version and fit it in an int */
	val = phb4_read_reg_asb(p, PHB_VERSION);
	if (val == 0 || val == 0xffffffffffffffff) {
		PHBERR(p, "Failed to read version, PHB appears broken\n");
		return false;
	}

	p->rev = ((val >> 16) & 0x00ff0000) | (val & 0xffff);
	PHBDBG(p, "Core revision 0x%x\n", p->rev);

	/* Read EEH capabilities */
	val = in_be64(p->regs + PHB_PHB4_EEH_CAP);
	p->max_num_pes = val >> 52;
	if (p->max_num_pes >= 512) {
		p->mrt_size = 16;
		p->mbt_size = 32;
		p->tvt_size = 512;
	} else {
		p->mrt_size = 8;
		p->mbt_size = 16;
		p->tvt_size = 256;
	}

	val = in_be64(p->regs + PHB_PHB4_IRQ_CAP);
	p->num_irqs = val & 0xffff;

	/* This works for 512 PEs.  FIXME calculate for any hardware
	 * size returned above
	 */
	p->tbl_peltv_size = PELTV_TABLE_SIZE_MAX;

	p->tbl_pest_size = p->max_num_pes*16;

	PHBDBG(p, "Found %d max PEs and %d IRQs \n",
	       p->max_num_pes, p->num_irqs);

	return true;
}

static void phb4_allocate_tables(struct phb4 *p)
{
	uint16_t *rte;
	uint32_t i;

	/* XXX Our current memalign implementation sucks,
	 *
	 * It will do the job, however it doesn't support freeing
	 * the memory and wastes space by always allocating twice
	 * as much as requested (size + alignment)
	 */
	p->tbl_rtt = (uint64_t)local_alloc(p->chip_id, RTT_TABLE_SIZE, RTT_TABLE_SIZE);
	assert(p->tbl_rtt);
	rte = (uint16_t *)(p->tbl_rtt);
	for (i = 0; i < RTT_TABLE_ENTRIES; i++, rte++)
		*rte = PHB4_RESERVED_PE_NUM(p);

	p->tbl_peltv = (uint64_t)local_alloc(p->chip_id, p->tbl_peltv_size, p->tbl_peltv_size);
	assert(p->tbl_peltv);
	memset((void *)p->tbl_peltv, 0, p->tbl_peltv_size);

	p->tbl_pest = (uint64_t)local_alloc(p->chip_id, p->tbl_pest_size, p->tbl_pest_size);
	assert(p->tbl_pest);
	memset((void *)p->tbl_pest, 0, p->tbl_pest_size);
}

static void phb4_add_properties(struct phb4 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, m64b, m64s;

	/* Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc...
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */

	dt_add_property_cells(np, "interrupt-parent", icsp);

	/* XXX FIXME: add slot-name */
	//dt_property_cell("bus-width", 8); /* Figure it out from VPD ? */

	/* "ranges", we only expose M32 (PHB4 doesn't do IO)
	 *
	 * Note: The kernel expects us to have chopped of 64k from the
	 * M32 size (for the 32-bit MSIs). If we don't do that, it will
	 * get confused (OPAL does it)
	 */
	m32b = cleanup_addr(p->mm1_base);
	m64b = cleanup_addr(p->mm0_base);
	m64s = p->mm0_size;
	dt_add_property_cells(np, "ranges",
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0, M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, dmawins, etc... */
	dt_add_property_cells(np, "ibm,opal-m64-window",
			      hi32(m64b), lo32(m64b),
			      hi32(m64b), lo32(m64b),
			      hi32(m64s), lo32(m64s));
	dt_add_property(np, "ibm,opal-single-pe", NULL, 0);
	dt_add_property_cells(np, "ibm,opal-num-pes", p->num_pes);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      PHB4_RESERVED_PE_NUM(p));
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->base_msi, p->num_irqs - 8);
	/* M64 ranges start at 1 as MBT0 is used for M32 */
	dt_add_property_cells(np, "ibm,opal-available-m64-ranges",
			      1, p->mbt_size - 1);

	/* Tell Linux about alignment limits for segment splits.
	 *
	 * XXX We currently only expose splits of 1 and "num PEs",
	 */
	dt_add_property_cells(np, "ibm,opal-m64-segment-splits",
			      /* Full split, number of segments: */
			      p->num_pes,
			      /* Encoding passed to the enable call */
			      OPAL_ENABLE_M64_SPLIT,
			      /* Alignement/size restriction in #bits*/
			      /* XXX VERIFY VALUE */
			      12,
			      /* Unused */
			      0,
			      /* single PE, number of segments: */
			      1,
			      /* Encoding passed to the enable call */
			      OPAL_ENABLE_M64_NON_SPLIT,
			      /* Alignement/size restriction in #bits*/
			      /* XXX VERIFY VALUE */
			      12,
			      /* Unused */
			      0);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->base_lsi;
	p->phb.lstate.int_size = 2;
	p->phb.lstate.int_val[0][0] = lsibase + PHB4_LSI_PCIE_INTA;
	p->phb.lstate.int_val[0][1] = 1;
	p->phb.lstate.int_val[1][0] = lsibase + PHB4_LSI_PCIE_INTB;
	p->phb.lstate.int_val[1][1] = 1;
	p->phb.lstate.int_val[2][0] = lsibase + PHB4_LSI_PCIE_INTC;
	p->phb.lstate.int_val[2][1] = 1;
	p->phb.lstate.int_val[3][0] = lsibase + PHB4_LSI_PCIE_INTD;
	p->phb.lstate.int_val[3][1] = 1;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* Indicators for variable tables */
	dt_add_property_cells(np, "ibm,opal-rtt-table",
		hi32(p->tbl_rtt), lo32(p->tbl_rtt), RTT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-peltv-table",
		hi32(p->tbl_peltv), lo32(p->tbl_peltv), p->tbl_peltv_size);
	dt_add_property_cells(np, "ibm,opal-pest-table",
		hi32(p->tbl_pest), lo32(p->tbl_pest), p->tbl_pest_size);
}

static bool phb4_calculate_windows(struct phb4 *p)
{
	const struct dt_property *prop;

	/* Get PBCQ MMIO windows from device-tree */
	prop = dt_require_property(p->phb.dt_node,
				   "ibm,mmio-windows", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));

	p->mm0_base = ((const uint64_t *)prop->prop)[0];
	p->mm0_size = ((const uint64_t *)prop->prop)[1];
	if (prop->len > 16) {
		p->mm1_base = ((const uint64_t *)prop->prop)[2];
		p->mm1_size = ((const uint64_t *)prop->prop)[3];
	}

	/* Sort them so that 0 is big and 1 is small */
	if (p->mm1_size && p->mm1_size > p->mm0_size) {
		uint64_t b = p->mm0_base;
		uint64_t s = p->mm0_size;
		p->mm0_base = p->mm1_base;
		p->mm0_size = p->mm1_size;
		p->mm1_base = b;
		p->mm1_size = s;
	}

	/* If 1 is too small, ditch it */
	if (p->mm1_size < M32_PCI_SIZE)
		p->mm1_size = 0;

	/* If 1 doesn't exist, carve it out of 0 */
	if (p->mm1_size == 0) {
		p->mm0_size /= 2;
		p->mm1_base = p->mm0_base + p->mm0_size;
		p->mm1_size = p->mm0_size;
	}

	/* Crop mm1 to our desired size */
	if (p->mm1_size > M32_PCI_SIZE)
		p->mm1_size = M32_PCI_SIZE;

	return true;
}


static int64_t phb4_get_xive(struct irq_source *is __unused, uint32_t isn,
			     uint16_t *server, uint8_t *prio)
{
	uint32_t target_id;

	if (xive_get_eq_info(isn, &target_id, prio)) {
		*server = target_id;
		return OPAL_SUCCESS;
	} else
		return OPAL_PARAMETER;
}

static int64_t phb4_set_xive(struct irq_source *is, uint32_t isn,
			     uint16_t server, uint8_t prio)
{
	struct phb4 *p = is->data;
	uint32_t idx = isn - p->base_msi;
	void *mmio_base;

	/* Let XIVE configure the EQ */
	if (!xive_set_eq_info(isn, server, prio))
		return OPAL_PARAMETER;

	/* Ensure it's enabled/disabled in the PHB. This won't do much
	 * for LSIs but will work for MSIs and will ensure that a stray
	 * P bit left over won't block further interrupts when enabling
	 */
	mmio_base = p->int_mmio + 0x10000 * idx;
	if (prio == 0xff)
		in_8(mmio_base + 0xd00); /* PQ = 01 */
	else
		in_8(mmio_base + 0xc00); /* PQ = 00 */

	return OPAL_SUCCESS;
}

static void phb4_eoi(struct irq_source *is, uint32_t isn)
{
	struct phb4 *p = is->data;
	uint32_t idx = isn - p->base_msi;
	void *mmio_base;
	uint8_t eoi_val;

	/* For EOI, we use the special MMIO that does a clear of both
	 * P and Q and returns the old Q.
	 *
	 * This allows us to then do a re-trigger if Q was set rather
	 * than synthetizing an interrupt in software
	 */
	mmio_base = p->int_mmio + 0x10000 * idx;
	eoi_val = in_8(mmio_base + 0xc00);
	if (eoi_val & 1) {
		/* PHB doesn't use a separate replay, use the same page */
		out_8(mmio_base, 0);
	}
}

static const struct irq_source_ops phb4_irq_ops = {
	.get_xive = phb4_get_xive,
	.set_xive = phb4_set_xive,
	.eoi = phb4_eoi
};

/* Error LSIs (skiboot owned) */
//static const struct irq_source_ops phb3_err_lsi_irq_ops = {
//	.get_xive = phb3_lsi_get_xive,
//	.set_xive = phb3_lsi_set_xive,
//	.interrupt = phb3_err_interrupt,
//};

static void phb4_create(struct dt_node *np)
{
	const struct dt_property *prop;
	struct phb4 *p = zalloc(sizeof(struct phb4));
	struct pci_slot *slot;
	size_t lane_eq_len;
	struct dt_node *iplp;
	char *path;
	uint32_t irq_base;

	assert(p);

	/* Populate base stuff */
	p->index = dt_prop_get_u32(np, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(np, "ibm,chip-id");
	p->regs = (void *)dt_get_address(np, 0, NULL);
	p->int_mmio = (void *)dt_get_address(np, 1, NULL);
	p->phb.dt_node = np;
	p->phb.ops = &phb4_ops;
	p->phb.phb_type = phb_type_pcie_v4;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */
	p->max_link_speed = dt_prop_get_u32_def(np, "ibm,max-link-speed", 3);
	p->state = PHB4_STATE_UNINITIALIZED;

	if (!phb4_calculate_windows(p))
		return;

	/* Get the various XSCOM register bases from the device-tree */
	prop = dt_require_property(np, "ibm,xscom-bases", 5 * sizeof(uint32_t));
	p->pe_xscom = ((const uint32_t *)prop->prop)[0];
	p->pe_stk_xscom = ((const uint32_t *)prop->prop)[1];
	p->pci_xscom = ((const uint32_t *)prop->prop)[2];
	p->pci_stk_xscom = ((const uint32_t *)prop->prop)[3];
	p->etu_xscom = ((const uint32_t *)prop->prop)[4];

	/*
	 * We skip the initial PERST assertion requested by the generic code
	 * when doing a cold boot because we are coming out of cold boot already
	 * so we save boot time that way. The PERST state machine will still
	 * handle waiting for the link to come up, it will just avoid actually
	 * asserting & deasserting the PERST output
	 *
	 * For a hot IPL, we still do a PERST
	 *
	 * Note: In absence of property (ie, FSP-less), we stick to the old
	 * behaviour and set skip_perst to true
	 */
	p->skip_perst = true; /* Default */

	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp) {
		const char *ipl_type = dt_prop_get_def(iplp, "cec-major-type", NULL);
		if (ipl_type && (!strcmp(ipl_type, "hot")))
			p->skip_perst = false;
	}

	/* By default link is assumed down */
	p->has_link = false;

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb, p->chip_id * 6 + p->index); //6 PHBs per chip?

	/* Create slot structure */
	slot = phb4_slot_create(&p->phb);
	if (!slot)
		PHBERR(p, "Cannot create PHB slot\n");

	/* Hello ! */
	path = dt_get_path(np);
	PHBINF(p, "Found %s @%p\n", path, p->regs);
	PHBINF(p, "  M32 [0x%016llx..0x%016llx]\n",
	       p->mm1_base, p->mm1_base + p->mm1_size - 1);
	PHBINF(p, "  M64 [0x%016llx..0x%016llx]\n",
	       p->mm0_base, p->mm0_base + p->mm0_size - 1);
	free(path);

	/* Find base location code from root node */
	p->phb.base_loc_code = dt_prop_get_def(dt_root,
					       "ibm,io-base-loc-code", NULL);
	if (!p->phb.base_loc_code)
		PHBERR(p, "Base location code not found !\n");

	/* Check for lane equalization values from HB or HDAT */
	p->lane_eq = dt_prop_get_def_size(np, "ibm,lane-eq", NULL, &lane_eq_len);
	if (p->lane_eq && lane_eq_len != (16 * 4)) {
		PHBERR(p, "Device-tree has ibm,lane-eq with wrong len %ld\n",
			lane_eq_len);
		p->lane_eq = NULL;
	}
	if (p->lane_eq) {
		PHBDBG(p, "Override lane equalization settings:\n");
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[0]), be64_to_cpu(p->lane_eq[1]));
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[2]), be64_to_cpu(p->lane_eq[3]));
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[4]), be64_to_cpu(p->lane_eq[5]));
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[6]), be64_to_cpu(p->lane_eq[7]));
	}

	/*
	 * Grab CEC IO VPD load info from the root of the device-tree,
	 * on P8 there's a single such VPD for the whole machine
	 */
	prop = dt_find_property(dt_root, "ibm,io-vpd");
	if (!prop) {
		/* LX VPD Lid not already loaded */
		vpd_iohub_load(dt_root);
	}

	/* Obtain informatin about the PHB from the hardware directly */
	if (!phb4_read_capabilities(p))
		goto failed;

	/* Allocate a block of interrupts. We need to know if it needs
	 * 2K or 4K interrupts ... for now we just use 4K but that
	 * needs to be fixed
	 */
	irq_base = xive_alloc_hw_irqs(p->chip_id, p->num_irqs, p->num_irqs);
	if (irq_base == XIVE_IRQ_ERROR) {
		PHBERR(p, "Failed to allocate %d interrupt sources\n",
		       p->num_irqs);
		goto failed;
	}
	p->base_msi = irq_base;
	p->base_lsi = irq_base + p->num_irqs - 8;
	p->irq_port = xive_get_notify_port(p->chip_id,
					   XIVE_HW_SRC_PHBn(p->index));

	/*
	 * XXXX FIXME: figure out how to deal with TVT entry mess
	 * For now configure for 2 entries per PE and half #PEs.
	 * WARNING: if changing this, update PHB_CTRLR in Init_16
	 */
	p->num_pes = p->max_num_pes/2;

	/* Allocate the SkiBoot internal in-memory tables for the PHB */
	phb4_allocate_tables(p);

	phb4_add_properties(p);

	/* Clear IODA3 cache */
	phb4_init_ioda_cache(p);

	/* Register interrupt sources */
	register_irq_source(&phb4_irq_ops, p, p->base_msi, p->num_irqs);

#ifndef DISABLE_ERR_INTS
	//	register_irq_source(&phb4_err_lsi_irq_ops, p,
	//		    p->base_lsi + PHB4_LSI_PCIE_INF, 2);
#endif
	/* Get the HW up and running */
	phb4_init_hw(p, true);

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);

	dt_add_property_string(np, "status", "okay");

	return;

 failed:
	p->state = PHB4_STATE_BROKEN;

	/* Tell Linux it's broken */
	dt_add_property_string(np, "status", "error");
}

/* Hack for assigning global MMIO space */
#define MMIO_CHIP_STRIDE 0x0000040000000000ULL
#define	PHB_BAR_BASE     0x000600c3c0000000ULL
#define	PHB_BAR_SIZE     0x0000000000100000ULL
#define	ESB_BAR_BASE     0x000600c300000000ULL
#define	ESB_BAR_SIZE     0x0000000020000000ULL
#define	MMIO0_BAR_BASE   0x0006000000000000ULL
#define	MMIO0_BAR_SIZE   0x0000002000000000ULL
#define	MMIO1_BAR_BASE   0x000600c000000000ULL
#define	MMIO1_BAR_SIZE   0x0000000080000000ULL

#define MMIO_CALC(__c, __p, __b) \
	(MMIO_CHIP_STRIDE * (__c) | __b##_SIZE * (__p) | __b##_BASE)

static void phb4_probe_stack(struct dt_node *stk_node, uint32_t pec_index,
			     uint32_t nest_base, uint32_t pci_base)
{
	uint32_t pci_stack, nest_stack, etu_base, gcid, phb_num, stk_index;
	uint64_t val, phb_bar = 0, irq_bar = 0, bar_en;
	uint64_t mmio0_bar = 0, mmio0_bmask, mmio0_sz;
	uint64_t mmio1_bar, mmio1_bmask, mmio1_sz;
	uint64_t reg[4];
	void *foo;
	uint64_t mmio_win[4];
	unsigned int mmio_win_sz;
	struct dt_node *np;
	char *path;
	uint64_t capp_ucode_base;
	unsigned int max_link_speed;
	bool force_assign;

	gcid = dt_get_chip_id(stk_node);
	stk_index = dt_prop_get_u32(stk_node, "reg");
	phb_num = dt_prop_get_u32(stk_node, "ibm,phb-index");
	path = dt_get_path(stk_node);
	prlog(PR_NOTICE, "PHB4: Chip %d Found PBCQ%d Stack %d at %s\n",
	      gcid, pec_index, stk_index, path);
	free(path);

	force_assign = dt_has_node_property(stk_node,
					    "force-assign-bars", NULL);

	pci_stack = pci_base + 0x40 * (stk_index + 1);
	nest_stack = nest_base + 0x40 * (stk_index + 1);
	etu_base = pci_base + 0x100 + 0x40 * stk_index;

	prlog(PR_DEBUG, "PHB4[%d:%d] X[PE]=0x%08x/0x%08x X[PCI]=0x%08x/0x%08x X[ETU]=0x%08x\n",
	      gcid, phb_num, nest_base, nest_stack, pci_base, pci_stack, etu_base);

	/* Default BAR enables */
	bar_en = 0;

	/* Get and/or initialize PHB register BAR */
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_PHB_REG_BAR, &phb_bar);
	if (phb_bar == 0 || force_assign) {
		prerror("PHB4[%d:%d] No PHB BAR set ! Overriding\n", gcid, phb_num);
		phb_bar = MMIO_CALC(gcid, phb_num, PHB_BAR);
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_PHB_REG_BAR, phb_bar << 8);
	}
	bar_en |= XPEC_NEST_STK_BAR_EN_PHB;

	xscom_read(gcid, nest_stack + XPEC_NEST_STK_PHB_REG_BAR, &phb_bar);
	phb_bar >>= 8;
	prlog(PR_ERR, "PHB4[%d:%d] REGS     = 0x%016llx [4k]\n", gcid, phb_num, phb_bar);

	/* Same with INT BAR (ESB) */
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_IRQ_BAR, &irq_bar);
	if (irq_bar == 0 || force_assign) {
		prerror("PHB4[%d:%d] No IRQ BAR set ! Overriding\n", gcid, phb_num);
		irq_bar = MMIO_CALC(gcid, phb_num, ESB_BAR);
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_IRQ_BAR, irq_bar << 8);
	}
	bar_en |= XPEC_NEST_STK_BAR_EN_INT;

	xscom_read(gcid, nest_stack + XPEC_NEST_STK_IRQ_BAR, &irq_bar);
	irq_bar >>= 8;
	prlog(PR_ERR, "PHB4[%d:%d] ESB      = 0x%016llx [...]\n", gcid, phb_num, irq_bar);

	/* Same with MMIO windows */
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0, &mmio0_bar);
	if (mmio0_bar == 0 || force_assign) {
		prerror("PHB4[%d:%d] No MMIO BAR set ! Overriding\n", gcid, phb_num);
		mmio0_bar = MMIO_CALC(gcid, phb_num, MMIO0_BAR);
		mmio0_bmask =  (~(MMIO0_BAR_SIZE - 1)) & 0x00FFFFFFFFFFFFFFULL;
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0, mmio0_bar << 8);
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0_MASK, mmio0_bmask << 8);

		mmio1_bar = MMIO_CALC(gcid, phb_num, MMIO1_BAR);
		mmio1_bmask =  (~(MMIO1_BAR_SIZE - 1)) & 0x00FFFFFFFFFFFFFFULL;
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1, mmio1_bar << 8);
		xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1_MASK, mmio1_bmask << 8);
	}
	bar_en |= XPEC_NEST_STK_BAR_EN_MMIO0 | XPEC_NEST_STK_BAR_EN_MMIO1;

	xscom_read(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0, &mmio0_bar);
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0_MASK, &mmio0_bmask);
	mmio0_bmask &= 0xffffffffff000000ull;
	mmio0_sz = ((~mmio0_bmask) >> 8) + 1;
	mmio0_bar >>= 8;
	prlog(PR_DEBUG, "PHB4[%d:%d] MMIO0    = 0x%016llx [0x%016llx]\n",
	      gcid, phb_num, mmio0_bar, mmio0_sz);

	xscom_read(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1, &mmio1_bar);
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1_MASK, &mmio1_bmask);
	mmio1_bmask &= 0xffffffffff000000ull;
	mmio1_sz = ((~mmio1_bmask) >> 8) + 1;
	mmio1_bar >>= 8;
	prlog(PR_DEBUG, "PHB4[%d:%d] MMIO1    = 0x%016llx [0x%016llx]\n",
	      gcid, phb_num, mmio1_bar, mmio1_sz);

	/* Build MMIO windows list */
	mmio_win_sz = 0;
	if (mmio0_bar) {
		mmio_win[mmio_win_sz++] = mmio0_bar;
		mmio_win[mmio_win_sz++] = mmio0_sz;
		bar_en |= XPEC_NEST_STK_BAR_EN_MMIO0;
	}
	if (mmio1_bar) {
		mmio_win[mmio_win_sz++] = mmio1_bar;
		mmio_win[mmio_win_sz++] = mmio1_sz;
		bar_en |= XPEC_NEST_STK_BAR_EN_MMIO1;
	}

	/* Set the appropriate enables */
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_BAR_EN, &val);
	val |= bar_en;
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_BAR_EN, val);

	/* No MMIO windows ? Barf ! */
	if (mmio_win_sz == 0) {
		prerror("PHB4[%d:%d] No MMIO windows enabled !\n", gcid, phb_num);
		return;
	}

	// show we can read phb mmio space
	foo = (void *)(phb_bar + 0x800); // phb version register
	prlog(PR_ERR, "Version reg: 0x%016llx\n", in_be64(foo));

	/* Create PHB node */
	reg[0] = phb_bar;
	reg[1] = 0x1000;
	reg[2] = irq_bar;
	reg[3] = 0x10000000;

	np = dt_new_addr(dt_root, "pciex", reg[0]);
	if (!np)
		return;

	dt_add_property_strings(np, "compatible", "ibm,power9-pciex", "ibm,ioda3-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));

	/* Everything else is handled later by skiboot, we just
	 * stick a few hints here
	 */
	dt_add_property_cells(np, "ibm,xscom-bases",
			      nest_base, nest_stack, pci_base, pci_stack, etu_base);
	dt_add_property(np, "ibm,mmio-windows", mmio_win, 8 * mmio_win_sz);
	dt_add_property_cells(np, "ibm,phb-index", phb_num);
	dt_add_property_cells(np, "ibm,phb-stack", stk_node->phandle);
	dt_add_property_cells(np, "ibm,phb-stack-index", stk_index);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	if (dt_has_node_property(stk_node, "ibm,use-ab-detect", NULL))
		dt_add_property(np, "ibm,use-ab-detect", NULL, 0);
	if (dt_has_node_property(stk_node, "ibm,hub-id", NULL))
		dt_add_property_cells(np, "ibm,hub-id",
				      dt_prop_get_u32(stk_node, "ibm,hub-id"));
	if (dt_has_node_property(stk_node, "ibm,loc-code", NULL)) {
		const char *lc = dt_prop_get(stk_node, "ibm,loc-code");
		dt_add_property_string(np, "ibm,loc-code", lc);
	}
	if (dt_has_node_property(stk_node, "ibm,lane-eq", NULL)) {
		size_t leq_size;
		const void *leq = dt_prop_get_def_size(stk_node, "ibm,lane-eq",
						       NULL, &leq_size);
		if (leq != NULL && leq_size == 4 * 8)
			dt_add_property(np, "ibm,lane-eq", leq, leq_size);
	}
	if (dt_has_node_property(stk_node, "ibm,capp-ucode", NULL)) {
		capp_ucode_base = dt_prop_get_u32(stk_node, "ibm,capp-ucode");
		dt_add_property_cells(np, "ibm,capp-ucode", capp_ucode_base);
	}
	max_link_speed = dt_prop_get_u32_def(stk_node, "ibm,max-link-speed", 4);
	dt_add_property_cells(np, "ibm,max-link-speed", max_link_speed);
	dt_add_property_cells(np, "ibm,capi-flags",
			      OPAL_PHB_CAPI_FLAG_SNOOP_CONTROL);

	add_chip_dev_associativity(np);
}

static void phb4_probe_pbcq(struct dt_node *pbcq)
{
	uint32_t nest_base, pci_base, pec_index;
	struct dt_node *stk;

	nest_base = dt_get_address(pbcq, 0, NULL);
	pci_base = dt_get_address(pbcq, 1, NULL);
	pec_index = dt_prop_get_u32(pbcq, "ibm,pec-index");

	dt_for_each_child(pbcq, stk) {
		if (dt_node_is_enabled(stk))
			phb4_probe_stack(stk, pec_index, nest_base, pci_base);
	}
}

void phb4_preload_vpd(void)
{
	const struct dt_property *prop;

	prop = dt_find_property(dt_root, "ibm,io-vpd");
	if (!prop) {
		/* LX VPD Lid not already loaded */
		vpd_preload(dt_root);
	}
}

void probe_phb4(void)
{
	struct dt_node *np;

	/* Look for PBCQ XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-pbcq")
		phb4_probe_pbcq(np);

	/* Look for newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-pciex")
		phb4_create(np);
}
