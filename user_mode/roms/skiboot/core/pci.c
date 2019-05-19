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
#include <cpu.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <timebase.h>
#include <device.h>
#include <fsp.h>

#define MAX_PHB_ID	256
static struct phb *phbs[MAX_PHB_ID];
int last_phb_id = 0;

#define PCITRACE(_p, _bdfn, fmt, a...) \
	prlog(PR_TRACE, "PHB#%04x:%02x:%02x.%x " fmt,	\
	      (_p)->opal_id,				\
	      ((_bdfn) >> 8) & 0xff,			\
	      ((_bdfn) >> 3) & 0x1f, (_bdfn) & 0x7, ## a)
#define PCIDBG(_p, _bdfn, fmt, a...) \
	prlog(PR_DEBUG, "PHB#%04x:%02x:%02x.%x " fmt,	\
	      (_p)->opal_id,				\
	      ((_bdfn) >> 8) & 0xff,			\
	      ((_bdfn) >> 3) & 0x1f, (_bdfn) & 0x7, ## a)
#define PCINOTICE(_p, _bdfn, fmt, a...) \
	prlog(PR_NOTICE, "PHB#%04x:%02x:%02x.%x " fmt,	\
	      (_p)->opal_id,				\
	      ((_bdfn) >> 8) & 0xff,			\
	      ((_bdfn) >> 3) & 0x1f, (_bdfn) & 0x7, ## a)
#define PCIERR(_p, _bdfn, fmt, a...) \
	prlog(PR_ERR, "PHB#%04x:%02x:%02x.%x " fmt,	\
	      (_p)->opal_id,				\
	      ((_bdfn) >> 8) & 0xff,			\
	      ((_bdfn) >> 3) & 0x1f, (_bdfn) & 0x7, ## a)

/*
 * Generic PCI utilities
 */

static int64_t __pci_find_cap(struct phb *phb, uint16_t bdfn,
			      uint8_t want, bool check_cap_indicator)
{
	int64_t rc;
	uint16_t stat, cap;
	uint8_t pos, next;

	rc = pci_cfg_read16(phb, bdfn, PCI_CFG_STAT, &stat);
	if (rc)
		return rc;
	if (check_cap_indicator && !(stat & PCI_CFG_STAT_CAP))
		return OPAL_UNSUPPORTED;
	rc = pci_cfg_read8(phb, bdfn, PCI_CFG_CAP, &pos);
	if (rc)
		return rc;
	pos &= 0xfc;
	while(pos) {
		rc = pci_cfg_read16(phb, bdfn, pos, &cap);
		if (rc)
			return rc;
		if ((cap & 0xff) == want)
			return pos;
		next = (cap >> 8) & 0xfc;
		if (next == pos) {
			PCIERR(phb, bdfn, "pci_find_cap hit a loop !\n");
			break;
		}
		pos = next;
	}
	return OPAL_UNSUPPORTED;
}

/* pci_find_cap - Find a PCI capability in a device config space
 *
 * This will return a config space offset (positive) or a negative
 * error (OPAL error codes).
 *
 * OPAL_UNSUPPORTED is returned if the capability doesn't exist
 */
int64_t pci_find_cap(struct phb *phb, uint16_t bdfn, uint8_t want)
{
	return __pci_find_cap(phb, bdfn, want, true);
}

/* pci_find_ecap - Find a PCIe extended capability in a device
 *                 config space
 *
 * This will return a config space offset (positive) or a negative
 * error (OPAL error code). Additionally, if the "version" argument
 * is non-NULL, the capability version will be returned there.
 *
 * OPAL_UNSUPPORTED is returned if the capability doesn't exist
 */
int64_t pci_find_ecap(struct phb *phb, uint16_t bdfn, uint16_t want,
		      uint8_t *version)
{
	int64_t rc;
	uint32_t cap;
	uint16_t off, prev = 0;

	for (off = 0x100; off && off < 0x1000; off = (cap >> 20) & 0xffc ) {
		if (off == prev) {
			PCIERR(phb, bdfn, "pci_find_ecap hit a loop !\n");
			break;
		}
		prev = off;
		rc = pci_cfg_read32(phb, bdfn, off, &cap);
		if (rc)
			return rc;
		if ((cap & 0xffff) == want) {
			if (version)
				*version = (cap >> 16) & 0xf;
			return off;
		}
	}
	return OPAL_UNSUPPORTED;
}

static struct pci_device *pci_scan_one(struct phb *phb, struct pci_device *parent,
				       uint16_t bdfn)
{
	struct pci_device *pd = NULL;
	uint32_t retries, vdid, val;
	int64_t rc, ecap;
	uint8_t htype;
	uint16_t capreg;
	bool had_crs = false;

	for (retries = 40; retries; retries--) {
		rc = pci_cfg_read32(phb, bdfn, 0, &vdid);
		if (rc)
			return NULL;
		if (vdid == 0xffffffff || vdid == 0x00000000)
			return NULL;
		if (vdid != 0xffff0001)
			break;
		had_crs = true;
		time_wait_ms(100);
	}
	if (vdid == 0xffff0001) {
		PCIERR(phb, bdfn, "CRS timeout !\n");
		return NULL;
	}
	if (had_crs)
		PCIDBG(phb, bdfn, "Probe success after CRS\n");

	/* Perform a dummy write to the device in order for it to
	 * capture it's own bus number, so any subsequent error
	 * messages will be properly tagged
	 */
	pci_cfg_write32(phb, bdfn, 0, vdid);

	pd = zalloc(sizeof(struct pci_device));
	if (!pd) {
		PCIERR(phb, bdfn,"Failed to allocate structure pci_device !\n");
		goto fail;
	}
	pd->bdfn = bdfn;
	pd->vdid = vdid;
	pci_cfg_read32(phb, bdfn, PCI_CFG_SUBSYS_VENDOR_ID, &pd->sub_vdid);
	pci_cfg_read32(phb, bdfn, PCI_CFG_REV_ID, &pd->class);
	pd->class >>= 8;

	pd->parent = parent;
	list_head_init(&pd->pcrf);
	list_head_init(&pd->children);
	rc = pci_cfg_read8(phb, bdfn, PCI_CFG_HDR_TYPE, &htype);
	if (rc) {
		PCIERR(phb, bdfn, "Failed to read header type !\n");
		goto fail;
	}
	pd->is_multifunction = !!(htype & 0x80);
	pd->is_bridge = (htype & 0x7f) != 0;
	pd->scan_map = 0xffffffff; /* Default */
	pd->primary_bus = (bdfn >> 8);

	/* On the upstream port of PLX bridge 8724 (rev ba), PCI_STATUS
	 * register doesn't have capability indicator though it support
	 * various PCI capabilities. So we need ignore that bit when
	 * looking for PCI capabilities on the upstream port, which is
	 * limited to one that seats directly under root port.
	 */
	if (vdid == 0x872410b5 && parent && !parent->parent) {
		uint8_t rev;

		pci_cfg_read8(phb, bdfn, PCI_CFG_REV_ID, &rev);
		if (rev == 0xba)
			ecap = __pci_find_cap(phb, bdfn,
					      PCI_CFG_CAP_ID_EXP, false);
		else
			ecap = pci_find_cap(phb, bdfn, PCI_CFG_CAP_ID_EXP);
	} else {
		ecap = pci_find_cap(phb, bdfn, PCI_CFG_CAP_ID_EXP);
	}
	if (ecap > 0) {
		pci_set_cap(pd, PCI_CFG_CAP_ID_EXP, ecap, false);
		pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_CAPABILITY_REG,
			       &capreg);
		pd->dev_type = GETFIELD(PCICAP_EXP_CAP_TYPE, capreg);

		/*
		 * XXX We observe a problem on some PLX switches where one
		 * of the downstream ports appears as an upstream port, we
		 * fix that up here otherwise, other code will misbehave
		 */
		if (pd->parent && pd->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
		    pd->parent->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
		    vdid == 0x874810b5) {
			PCIDBG(phb, bdfn,
			       "Fixing up bad PLX downstream port !\n");
			pd->dev_type = PCIE_TYPE_SWITCH_DNPORT;
		}

		/* XXX Handle ARI */
		if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT ||
		    pd->dev_type == PCIE_TYPE_ROOT_PORT)
			pd->scan_map = 0x1;

		/* Read MPS capability, whose maximal size is 4096 */
		pci_cfg_read32(phb, bdfn, ecap + PCICAP_EXP_DEVCAP, &val);
		pd->mps = (128 << GETFIELD(PCICAP_EXP_DEVCAP_MPSS, val));
		if (pd->mps > 4096)
			pd->mps = 4096;
	} else {
		pd->dev_type = PCIE_TYPE_LEGACY;
	}

	/* If it's a bridge, sanitize the bus numbers to avoid forwarding
	 *
	 * This will help when walking down those bridges later on
	 */
	if (pd->is_bridge) {
		pci_cfg_write8(phb, bdfn, PCI_CFG_PRIMARY_BUS, pd->primary_bus);
		pci_cfg_write8(phb, bdfn, PCI_CFG_SECONDARY_BUS, 0);
		pci_cfg_write8(phb, bdfn, PCI_CFG_SUBORDINATE_BUS, 0);
	}

	/* XXX Need to do some basic setups, such as MPSS, MRS,
	 * RCB, etc...
	 */

	PCIDBG(phb, bdfn, "Found VID:%04x DEV:%04x TYP:%d MF%s BR%s EX%s\n",
	       vdid & 0xffff, vdid >> 16, pd->dev_type,
	       pd->is_multifunction ? "+" : "-",
	       pd->is_bridge ? "+" : "-",
	       pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false) ? "+" : "-");

	/*
	 * Call PHB hook
	 */
	if (phb->ops->device_init)
		phb->ops->device_init(phb, pd, NULL);

	return pd;
 fail:
	if (pd)
		free(pd);
	return NULL;
}

/* pci_check_clear_freeze - Probing empty slot will result in an EEH
 *                          freeze. Currently we have a single PE mapping
 *                          everything (default state of our backend) so
 *                          we just check and clear the state of PE#0
 *
 * NOTE: We currently only handle simple PE freeze, not PHB fencing
 *       (or rather our backend does)
 */
static void pci_check_clear_freeze(struct phb *phb)
{
	uint8_t freeze_state;
	uint16_t pci_error_type, sev;
	int64_t pe_number, rc;

	/* Retrieve the reserved PE number */
	pe_number = OPAL_PARAMETER;
	if (phb->ops->get_reserved_pe_number)
		pe_number = phb->ops->get_reserved_pe_number(phb);
	if (pe_number < 0)
		return;

	/* Retrieve the frozen state */
	rc = phb->ops->eeh_freeze_status(phb, pe_number, &freeze_state,
					 &pci_error_type, &sev, NULL);
	if (rc)
		return;
	if (freeze_state == OPAL_EEH_STOPPED_NOT_FROZEN)
		return;
	/* We can't handle anything worse than an ER here */
	if (sev > OPAL_EEH_SEV_NO_ERROR &&
	    sev < OPAL_EEH_SEV_PE_ER) {
		PCIERR(phb, 0, "Fatal probe in %s error !\n", __func__);
		return;
	}
	phb->ops->eeh_freeze_clear(phb, pe_number,
				   OPAL_EEH_ACTION_CLEAR_FREEZE_ALL);
}

/* pci_enable_bridge - Called before scanning a bridge
 *
 * Ensures error flags are clean, disable master abort, and
 * check if the subordinate bus isn't reset, the slot is enabled
 * on PCIe, etc...
 */
static bool pci_enable_bridge(struct phb *phb, struct pci_device *pd)
{
	uint16_t bctl;
	bool was_reset = false;
	int64_t ecap = 0;

	/* Disable master aborts, clear errors */
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_BRCTL, &bctl);
	bctl &= ~PCI_CFG_BRCTL_MABORT_REPORT;
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_BRCTL, bctl);

	/* PCI-E bridge, check the slot state. We don't do that on the
	 * root complex as this is handled separately and not all our
	 * RCs implement the standard register set.
	 */
	if ((pd->dev_type == PCIE_TYPE_ROOT_PORT && pd->primary_bus > 0) ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		uint16_t slctl, slcap, slsta, lctl;

		ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);

		/* Read the slot status & check for presence detect */
		pci_cfg_read16(phb, pd->bdfn, ecap+PCICAP_EXP_SLOTSTAT, &slsta);
		PCITRACE(phb, pd->bdfn, "slstat=%04x\n", slsta);
		if (!(slsta & PCICAP_EXP_SLOTSTAT_PDETECTST)) {
			PCIDBG(phb, pd->bdfn, "No card in slot\n");
			return false;
		}
		
		/* Read the slot capabilities */
		pci_cfg_read16(phb, pd->bdfn, ecap+PCICAP_EXP_SLOTCAP, &slcap);
		PCITRACE(phb, pd->bdfn, "slcap=%04x\n", slcap);
		if (!(slcap & PCICAP_EXP_SLOTCAP_PWCTRL))
			goto power_is_on;

		/* Read the slot control register, check if the slot is off */
		pci_cfg_read16(phb, pd->bdfn, ecap+PCICAP_EXP_SLOTCTL, &slctl);
		PCITRACE(phb, pd->bdfn, "slctl=%04x\n", slctl);
		if (!(slctl & PCICAP_EXP_SLOTCTL_PWRCTLR))
			goto power_is_on;

		/* Turn power on
		 *
		 * XXX This is a "command", we should wait for it to complete
		 * etc... but just waiting 2s will do for now
		 */
		PCIDBG(phb, pd->bdfn, "Bridge power is off, turning on ...\n");
		slctl &= ~PCICAP_EXP_SLOTCTL_PWRCTLR;
		slctl |= SETFIELD(PCICAP_EXP_SLOTCTL_PWRI, 0, PCIE_INDIC_ON);
		pci_cfg_write16(phb, pd->bdfn, ecap+PCICAP_EXP_SLOTCTL, slctl);

		/* Wait a couple of seconds */
		time_wait_ms(2000);

 power_is_on:
		/* Enable link */
		pci_cfg_read16(phb, pd->bdfn, ecap+PCICAP_EXP_LCTL, &lctl);
		PCITRACE(phb, pd->bdfn, " lctl=%04x\n", lctl);
		lctl &= ~PCICAP_EXP_LCTL_LINK_DIS;
		pci_cfg_write16(phb, pd->bdfn, ecap+PCICAP_EXP_LCTL, lctl);
	}

	/* Clear secondary reset */
	if (bctl & PCI_CFG_BRCTL_SECONDARY_RESET) {
		PCIDBG(phb, pd->bdfn,
		       "Bridge secondary reset is on, clearing it ...\n");
		bctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		pci_cfg_write16(phb, pd->bdfn, PCI_CFG_BRCTL, bctl);
		time_wait_ms(1000);
		was_reset = true;
	}

	/* PCI-E bridge, wait for link */
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		uint32_t lcap;

		/* Read link caps */
		pci_cfg_read32(phb, pd->bdfn, ecap+PCICAP_EXP_LCAP, &lcap);

		/* Did link capability say we got reporting ?
		 *
		 * If yes, wait up to 10s, if not, wait 1s if we didn't already
		 */
		if (lcap & PCICAP_EXP_LCAP_DL_ACT_REP) {
			uint32_t retries = 100;
			uint16_t lstat;

			PCIDBG(phb, pd->bdfn, "waiting for link... \n");

			while(retries--) {
				pci_cfg_read16(phb, pd->bdfn,
					       ecap+PCICAP_EXP_LSTAT, &lstat);
				if (lstat & PCICAP_EXP_LSTAT_DLLL_ACT)
					break;
				time_wait_ms(100);
			}
			PCIDBG(phb, pd->bdfn, "end wait for link...\n");
			if (!(lstat & PCICAP_EXP_LSTAT_DLLL_ACT)) {
				PCIERR(phb, pd->bdfn, "Timeout waiting"
					" for downstream link\n");
				return false;
			}
			/* Need to wait another 100ms before touching
			 * the config space
			 */
			time_wait_ms(100);
		} else if (!was_reset)
			time_wait_ms(1000);
	}

	/* Clear error status */
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_STAT, 0xffff);

	return true;
}

/* Clear up bridge resources */
static void pci_cleanup_bridge(struct phb *phb, struct pci_device *pd)
{
	uint16_t cmd;

	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_IO_BASE_U16, 0xffff);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_IO_BASE, 0xf0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_IO_LIMIT_U16, 0);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_IO_LIMIT, 0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_MEM_BASE, 0xfff0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_MEM_LIMIT, 0);
	pci_cfg_write32(phb, pd->bdfn, PCI_CFG_PREF_MEM_BASE_U32, 0xffffffff);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_PREF_MEM_BASE, 0xfff0);
	pci_cfg_write32(phb, pd->bdfn, PCI_CFG_PREF_MEM_LIMIT_U32, 0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_PREF_MEM_LIMIT, 0);

	/* Note: This is a bit fishy but since we have closed all the
	 * bridge windows above, it shouldn't be a problem. Basically
	 * we enable Memory, IO and Bus Master on the bridge because
	 * some versions of Linux will fail to do it themselves.
	 */
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_CMD, &cmd);
	cmd |= PCI_CFG_CMD_IO_EN | PCI_CFG_CMD_MEM_EN;
	cmd |= PCI_CFG_CMD_BUS_MASTER_EN;
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_CMD, cmd);	
}

/* Remove all subordinate PCI devices leading from the indicated
 * PCI bus. It's used to remove all PCI devices behind one PCI
 * slot at unplugging time
 */
void pci_remove_bus(struct phb *phb, struct list_head *list)
{
	struct pci_device *pd, *tmp;

	list_for_each_safe(list, pd, tmp, link) {
		pci_remove_bus(phb, &pd->children);

		/* Release device node and PCI slot */
		if (pd->dn)
			dt_free(pd->dn);
		if (pd->slot)
			free(pd->slot);

		/* Remove from parent list and release itself */
		list_del(&pd->link);
		free(pd);
	}
}

/*
 * Turn off slot's power supply if there are nothing connected for
 * 2 purposes: power saving obviously and initialize the slot to
 * to initial power-off state for hotplug.
 */
static void pci_slot_power_off(struct phb *phb, struct pci_device *pd)
{
	struct pci_slot *slot;
	int32_t wait = 100;
	int64_t rc;

	if (!pd || !pd->slot)
		return;

	slot = pd->slot;
	if (!slot->pluggable || !slot->ops.set_power_state)
		return;

	/* Bail if there're something connected */
	if (!list_empty(&pd->children))
		return;

	pci_slot_add_flags(slot, PCI_SLOT_FLAG_BOOTUP);
	rc = slot->ops.set_power_state(slot, PCI_SLOT_POWER_OFF);
	if (rc == OPAL_SUCCESS) {
		PCIDBG(phb, pd->bdfn, "Power off hotpluggable slot\n");
		return;
	} else if (rc != OPAL_ASYNC_COMPLETION) {
		pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
		PCINOTICE(phb, pd->bdfn, "Error %lld powering off slot\n", rc);
		return;
	}

	do {
		if (slot->state == PCI_SLOT_STATE_SPOWER_DONE)
			break;

		check_timers(false);
		time_wait_ms(10);
	} while (--wait >= 0);

	pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
	if (wait >= 0)
		PCIDBG(phb, pd->bdfn, "Power off hotpluggable slot\n");
	else
		PCINOTICE(phb, pd->bdfn, "Timeout powering off slot\n");
}

/* Perform a recursive scan of the bus at bus_number populating
 * the list passed as an argument. This also performs the bus
 * numbering, so it returns the largest bus number that was
 * assigned.
 *
 * Note: Eventually this might want to access some VPD information
 *       in order to know what slots to scan and what not etc..
 *
 * XXX NOTE: We might want to enable ARI along the way...
 *
 * XXX NOTE: We might also want to setup the PCIe MPS/MRSS properly
 *           here as Linux may or may not do it
 */
uint8_t pci_scan_bus(struct phb *phb, uint8_t bus, uint8_t max_bus,
		     struct list_head *list, struct pci_device *parent,
		     bool scan_downstream)
{
	struct pci_device *pd = NULL;
	uint8_t dev, fn, next_bus, max_sub, save_max;
	uint32_t scan_map;

	/* Decide what to scan  */
	scan_map = parent ? parent->scan_map : phb->scan_map;

	/* Do scan */
	for (dev = 0; dev < 32; dev++) {
		if (!(scan_map & (1ul << dev)))
			continue;

		/* Scan the device */
		pd = pci_scan_one(phb, parent, (bus << 8) | (dev << 3));
		pci_check_clear_freeze(phb);
		if (!pd)
			continue;

		/* Get slot info if any */
		if (platform.pci_get_slot_info)
			platform.pci_get_slot_info(phb, pd);

		/* Link it up */
		list_add_tail(list, &pd->link);

		/* XXX Handle ARI */
		if (!pd->is_multifunction)
			continue;
		for (fn = 1; fn < 8; fn++) {
			pd = pci_scan_one(phb, parent,
					  ((uint16_t)bus << 8) | (dev << 3) | fn);
			pci_check_clear_freeze(phb);
			if (pd) {
				if (platform.pci_get_slot_info)
					platform.pci_get_slot_info(phb, pd);
				list_add_tail(list, &pd->link);
			}
		}
	}

	/*
	 * We only scan downstream if instructed to do so by the
	 * caller. Typically we avoid the scan when we know the
	 * link is down already, which happens for the top level
	 * root complex, and avoids a long secondary timeout
	 */
	if (!scan_downstream) {
		list_for_each(list, pd, link)
			pci_slot_power_off(phb, pd);

		return bus;
	}

	next_bus = bus + 1;
	max_sub = bus;
	save_max = max_bus;

	/* Scan down bridges */
	list_for_each(list, pd, link) {
		bool use_max, do_scan;

		if (!pd->is_bridge)
			continue;

		/* We need to figure out a new bus number to start from.
		 *
		 * This can be tricky due to our HW constraints which differ
		 * from bridge to bridge so we are going to let the phb
		 * driver decide what to do. This can return us a maximum
		 * bus number to assign as well
		 *
		 * This function will:
		 *
		 *  - Return the bus number to use as secondary for the
		 *    bridge or 0 for a failure
		 *
		 *  - "max_bus" will be adjusted to represent the max
		 *    subordinate that can be associated with the downstream
		 *    device
		 *
		 *  - "use_max" will be set to true if the returned max_bus
		 *    *must* be used as the subordinate bus number of that
		 *    bridge (when we need to give aligned powers of two's
		 *    on P7IOC). If is is set to false, we just adjust the
		 *    subordinate bus number based on what we probed.
		 *
		 */
		max_bus = save_max;
		next_bus = phb->ops->choose_bus(phb, pd, next_bus,
						&max_bus, &use_max);

		/* Configure the bridge with the returned values */
		if (next_bus <= bus) {
			PCIERR(phb, pd->bdfn, "Out of bus numbers !\n");
			max_bus = next_bus = 0; /* Failure case */
		}

		pd->secondary_bus = next_bus;
		pd->subordinate_bus = max_bus;
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SECONDARY_BUS, next_bus);
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS, max_bus);
		if (!next_bus)
			break;

		PCIDBG(phb, pd->bdfn, "Bus %02x..%02x %s scanning...\n",
		       next_bus, max_bus, use_max ? "[use max]" : "");

		/* Clear up bridge resources */
		pci_cleanup_bridge(phb, pd);

		/* Configure the bridge. This will enable power to the slot
		 * if it's currently disabled, lift reset, etc...
		 *
		 * Return false if we know there's nothing behind the bridge
		 */
		do_scan = pci_enable_bridge(phb, pd);

		/* Perform recursive scan */
		if (do_scan) {
			max_sub = pci_scan_bus(phb, next_bus, max_bus,
					       &pd->children, pd, true);
		} else if (!use_max) {
			/* XXX Empty bridge... we leave room for hotplug
			 * slots etc.. but we should be smarter at figuring
			 * out if this is actually a hotpluggable one
			 */
			max_sub = next_bus + 4;
			if (max_sub > max_bus)
				max_sub = max_bus;
		}

		/* Update the max subordinate as described previously */
		if (use_max)
			max_sub = max_bus;
		pd->subordinate_bus = max_sub;
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS, max_sub);
		next_bus = max_sub + 1;

		pci_slot_power_off(phb, pd);
	}

	return max_sub;
}

static int pci_get_mps(struct phb *phb,
		       struct pci_device *pd, void *userdata)
{
	uint32_t *mps = (uint32_t *)userdata;

	/* Only check PCI device that had MPS capacity */
	if (phb && pd && pd->mps && *mps > pd->mps)
		*mps = pd->mps;

	return 0;
}

static int pci_configure_mps(struct phb *phb,
			     struct pci_device *pd,
			     void *userdata __unused)
{
	uint32_t ecap, aercap, mps;
	uint16_t val;

	assert(phb);
	assert(pd);

	/* If the MPS isn't acceptable one, bail immediately */
	mps = phb->mps;
	if (mps < 128 || mps > 4096)
		return 1;

	/* Retrieve PCIe and AER capability */
	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	aercap = pci_cap(pd, PCIECAP_ID_AER, true);

	/* PCIe device always has MPS capacity */
	if (pd->mps) {
		mps = ilog2(mps) - 7;

		pci_cfg_read16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVCTL, &val);
		val = SETFIELD(PCICAP_EXP_DEVCTL_MPS, val, mps);
		pci_cfg_write16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVCTL, val);
	}

	/* Changing MPS on upstream PCI bridge might cause some error
	 * bits in PCIe and AER capability. To clear them to avoid
	 * confusion.
	 */
	if (aercap) {
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_UE_STATUS,
				0xffffffff);
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_CE_STATUS,
				0xffffffff);
	}
	if (ecap)
		pci_cfg_write16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVSTAT, 0xf);

	return 0;
}

static void pci_disable_completion_timeout(struct phb *phb, struct pci_device *pd)
{
	uint32_t ecap;
	uint32_t val;

	/* PCIE capability required */
	if (!pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		return;

	/* Check if it has capability to disable completion timeout */
	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	pci_cfg_read32(phb, pd->bdfn, ecap + PCIECAP_EXP_DCAP2, &val);
	if (!(val & PCICAP_EXP_DCAP2_CMPTOUT_DIS))
		return;

	/* Disable completion timeout without more check */
	pci_cfg_read32(phb, pd->bdfn, ecap + PCICAP_EXP_DCTL2, &val);
	val |= PCICAP_EXP_DCTL2_CMPTOUT_DIS;
	pci_cfg_write32(phb, pd->bdfn, ecap + PCICAP_EXP_DCTL2, val);
}

void pci_device_init(struct phb *phb, struct pci_device *pd)
{
	pci_configure_mps(phb, pd, NULL);
	pci_disable_completion_timeout(phb, pd);
}

static void pci_reset_phb(void *data)
{
	struct phb *phb = data;
	struct pci_slot *slot = phb->slot;
	int64_t rc;

	if (!slot || !slot->ops.freset) {
		PCINOTICE(phb, 0, "Cannot issue fundamental reset\n");
		return;
	}

	pci_slot_add_flags(slot, PCI_SLOT_FLAG_BOOTUP);
	rc = slot->ops.freset(slot);
	while (rc > 0) {
		time_wait(rc);
		rc = slot->ops.poll(slot);
	}
	pci_slot_remove_flags(slot, PCI_SLOT_FLAG_BOOTUP);
	if (rc < 0)
		PCIERR(phb, 0, "Error %lld fundamental resetting\n", rc);
}

static void pci_scan_phb(void *data)
{
	struct phb *phb = data;
	struct pci_slot *slot = phb->slot;
	uint8_t link;
	uint32_t mps = 0xffffffff;
	int64_t rc;

	if (!slot || !slot->ops.get_link_state) {
		PCIERR(phb, 0, "Cannot query link status\n");
		link = 0;
	} else {
		rc = slot->ops.get_link_state(slot, &link);
		if (rc != OPAL_SUCCESS) {
			PCIERR(phb, 0, "Error %lld querying link status\n",
			       rc);
			link = 0;
		}
	}

	if (!link)
		PCIDBG(phb, 0, "Link down\n");
	else
		PCIDBG(phb, 0, "Link up at x%d width\n", link);

	/* Scan root port and downstream ports if applicable */
	PCIDBG(phb, 0, "Scanning (upstream%s)...\n",
	       link ? "+downsteam" : " only");
	pci_scan_bus(phb, 0, 0xff, &phb->devices, NULL, link);

	/* Configure MPS (Max Payload Size) for PCIe domain */
	pci_walk_dev(phb, NULL, pci_get_mps, &mps);
	phb->mps = mps;
	pci_walk_dev(phb, NULL, pci_configure_mps, NULL);
}

int64_t pci_register_phb(struct phb *phb, int opal_id)
{
	/* The user didn't specify an opal_id, allocate one */
	if (opal_id == OPAL_DYNAMIC_PHB_ID) {
		/* This is called at init time in non-concurrent way, so no lock needed */
		for (opal_id = 0; opal_id < ARRAY_SIZE(phbs); opal_id++)
			if (!phbs[opal_id])
				break;
		if (opal_id >= ARRAY_SIZE(phbs)) {
			prerror("PHB: Failed to find a free ID slot\n");
			return OPAL_RESOURCE;
		}
	} else {
		if (opal_id >= ARRAY_SIZE(phbs)) {
			prerror("PHB: ID %d out of range !\n", opal_id);
			return OPAL_PARAMETER;
		}
		/* The user did specify an opal_id, check it's free */
		if (phbs[opal_id]) {
			prerror("PHB: Duplicate registration of ID %d\n", opal_id);
			return OPAL_PARAMETER;
		}
	}

	phbs[opal_id] = phb;
	phb->opal_id = opal_id;
	if (opal_id > last_phb_id)
		last_phb_id = opal_id;
	dt_add_property_cells(phb->dt_node, "ibm,opal-phbid", 0, phb->opal_id);
	PCIDBG(phb, 0, "PCI: Registered PHB\n");

	init_lock(&phb->lock);
	list_head_init(&phb->devices);

	return OPAL_SUCCESS;
}

int64_t pci_unregister_phb(struct phb *phb)
{
	/* XXX We want some kind of RCU or RWlock to make things
	 * like that happen while no OPAL callback is in progress,
	 * that way we avoid taking a lock in each of them.
	 *
	 * Right now we don't unregister so we are fine
	 */
	phbs[phb->opal_id] = phb;

	return OPAL_SUCCESS;
}

struct phb *pci_get_phb(uint64_t phb_id)
{
	if (phb_id >= ARRAY_SIZE(phbs))
		return NULL;

	/* XXX See comment in pci_unregister_phb() about locking etc... */
	return phbs[phb_id];
}

static const char *pci_class_name(uint32_t class_code)
{
	uint8_t class = class_code >> 16;
	uint8_t sub = (class_code >> 8) & 0xff;
	uint8_t pif = class_code & 0xff;

	switch(class) {
	case 0x00:
		switch(sub) {
		case 0x00: return "device";
		case 0x01: return "vga";
		}
		break;
	case 0x01:
		switch(sub) {
		case 0x00: return "scsi";
		case 0x01: return "ide";
		case 0x02: return "fdc";
		case 0x03: return "ipi";
		case 0x04: return "raid";
		case 0x05: return "ata";
		case 0x06: return "sata";
		case 0x07: return "sas";
		default:   return "mass-storage";
		}
	case 0x02:
		switch(sub) {
		case 0x00: return "ethernet";
		case 0x01: return "token-ring";
		case 0x02: return "fddi";
		case 0x03: return "atm";
		case 0x04: return "isdn";
		case 0x05: return "worldfip";
		case 0x06: return "picmg";
		default:   return "network";
		}
	case 0x03:
		switch(sub) {
		case 0x00: return "vga";
		case 0x01: return "xga";
		case 0x02: return "3d-controller";
		default:   return "display";
		}
	case 0x04:
		switch(sub) {
		case 0x00: return "video";
		case 0x01: return "sound";
		case 0x02: return "telephony";
		default:   return "multimedia-device";
		}
	case 0x05:
		switch(sub) {
		case 0x00: return "memory";
		case 0x01: return "flash";
		default:   return "memory-controller";
		}
	case 0x06:
		switch(sub) {
		case 0x00: return "host";
		case 0x01: return "isa";
		case 0x02: return "eisa";
		case 0x03: return "mca";
		case 0x04: return "pci";
		case 0x05: return "pcmcia";
		case 0x06: return "nubus";
		case 0x07: return "cardbus";
		case 0x08: return "raceway";
		case 0x09: return "semi-transparent-pci";
		case 0x0a: return "infiniband";
		default:   return "unknown-bridge";
		}
	case 0x07:
		switch(sub) {
		case 0x00:
			switch(pif) {
			case 0x01: return "16450-serial";
			case 0x02: return "16550-serial";
			case 0x03: return "16650-serial";
			case 0x04: return "16750-serial";
			case 0x05: return "16850-serial";
			case 0x06: return "16950-serial";
			default:   return "serial";
			}
		case 0x01:
			switch(pif) {
			case 0x01: return "bi-directional-parallel";
			case 0x02: return "ecp-1.x-parallel";
			case 0x03: return "ieee1284-controller";
			case 0xfe: return "ieee1284-device";
			default:   return "parallel";
			}
		case 0x02: return "multiport-serial";
		case 0x03:
			switch(pif) {
			case 0x01: return "16450-modem";
			case 0x02: return "16550-modem";
			case 0x03: return "16650-modem";
			case 0x04: return "16750-modem";
			default:   return "modem";
			}
		case 0x04: return "gpib";
		case 0x05: return "smart-card";
		default:   return "communication-controller";
		}
	case 0x08:
		switch(sub) {
		case 0x00:
			switch(pif) {
			case 0x01: return "isa-pic";
			case 0x02: return "eisa-pic";
			case 0x10: return "io-apic";
			case 0x20: return "iox-apic";
			default:   return "interrupt-controller";
			}
		case 0x01:
			switch(pif) {
			case 0x01: return "isa-dma";
			case 0x02: return "eisa-dma";
			default:   return "dma-controller";
			}
		case 0x02:
			switch(pif) {
			case 0x01: return "isa-system-timer";
			case 0x02: return "eisa-system-timer";
			default:   return "timer";
			}
		case 0x03:
			switch(pif) {
			case 0x01: return "isa-rtc";
			default:   return "rtc";
			}
		case 0x04: return "hotplug-controller";
		case 0x05: return "sd-host-controller";
		default:   return "system-peripheral";
		}
	case 0x09:
		switch(sub) {
		case 0x00: return "keyboard";
		case 0x01: return "pen";
		case 0x02: return "mouse";
		case 0x03: return "scanner";
		case 0x04: return "gameport";
		default:   return "input-controller";
		}
	case 0x0a:
		switch(sub) {
		case 0x00: return "clock";
		default:   return "docking-station";
		}
	case 0x0b:
		switch(sub) {
		case 0x00: return "386";
		case 0x01: return "486";
		case 0x02: return "pentium";
		case 0x10: return "alpha";
		case 0x20: return "powerpc";
		case 0x30: return "mips";
		case 0x40: return "co-processor";
		default:   return "cpu";
		}
	case 0x0c:
		switch(sub) {
		case 0x00: return "firewire";
		case 0x01: return "access-bus";
		case 0x02: return "ssa";
		case 0x03:
			switch(pif) {
			case 0x00: return "usb-uhci";
			case 0x10: return "usb-ohci";
			case 0x20: return "usb-ehci";
			case 0x30: return "usb-xhci";
			case 0xfe: return "usb-device";
			default:   return "usb";
			}
		case 0x04: return "fibre-channel";
		case 0x05: return "smb";
		case 0x06: return "infiniband";
		case 0x07:
			switch(pif) {
			case 0x00: return "impi-smic";
			case 0x01: return "impi-kbrd";
			case 0x02: return "impi-bltr";
			default:   return "impi";
			}
		case 0x08: return "secos";
		case 0x09: return "canbus";
		default:   return "serial-bus";
		}
	case 0x0d:
		switch(sub) {
		case 0x00: return "irda";
		case 0x01: return "consumer-ir";
		case 0x10: return "rf-controller";
		case 0x11: return "bluetooth";
		case 0x12: return "broadband";
		case 0x20: return "enet-802.11a";
		case 0x21: return "enet-802.11b";
		default:   return "wireless-controller";
		}
	case 0x0e: return "intelligent-controller";
	case 0x0f:
		switch(sub) {
		case 0x01: return "satellite-tv";
		case 0x02: return "satellite-audio";
		case 0x03: return "satellite-voice";
		case 0x04: return "satellite-data";
		default:   return "satellite-device";
		}
	case 0x10:
		switch(sub) {
		case 0x00: return "network-encryption";
		case 0x01: return "entertainment-encryption";
		default:   return "encryption";
		}
	case 0x011:
		switch(sub) {
		case 0x00: return "dpio";
		case 0x01: return "counter";
		case 0x10: return "measurement";
		case 0x20: return "management-card";
		default:   return "data-processing";
		}
	}
	return "device";
}

void pci_std_swizzle_irq_map(struct dt_node *np,
			     struct pci_device *pd,
			     struct pci_lsi_state *lstate,
			     uint8_t swizzle)
{
	uint32_t *map, *p;
	int dev, irq, esize, edevcount;
	size_t map_size, isize;

	/* Some emulated setups don't use standard interrupts
	 * representation
	 */
	if (lstate->int_size == 0)
		return;

	/* Size in bytes of a target interrupt */
	isize = lstate->int_size * sizeof(uint32_t);

	/* Calculate the size of a map entry:
	 *
	 * 3 cells : PCI Address
	 * 1 cell  : PCI IRQ
	 * 1 cell  : PIC phandle
	 * n cells : PIC irq (n = lstate->int_size)
	 *
	 * Assumption: PIC address is 0-size
	 */
	esize = 3 + 1 + 1 + lstate->int_size;

	/* Number of map "device" entries
	 *
	 * A PCI Express root or downstream port needs only one
	 * entry for device 0. Anything else will get a full map
	 * for all possible 32 child device numbers
	 *
	 * If we have been passed a host bridge (pd == NULL) we also
	 * do a simple per-pin map
	 */
	if (!pd || (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
		    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT)) {
		edevcount = 1;
		dt_add_property_cells(np, "interrupt-map-mask", 0, 0, 0, 7);
	} else {
		edevcount = 32;
		dt_add_property_cells(np, "interrupt-map-mask",
				      0xf800, 0, 0, 7);
	}
	map_size = esize * edevcount * 4 * sizeof(uint32_t);
	map = p = zalloc(map_size);
	if (!map) {
		prerror("Failed to allocate interrupt-map-mask !\n");
		return;
	}

	for (dev = 0; dev < edevcount; dev++) {
		for (irq = 0; irq < 4; irq++) {
			/* Calculate pin */
			uint32_t new_irq = (irq + dev + swizzle) % 4;

			/* PCI address portion */
			*(p++) = dev << (8 + 3);
			*(p++) = 0;
			*(p++) = 0;

			/* PCI interrupt portion */
			*(p++) = irq + 1;

			/* Parent phandle */
			*(p++) = lstate->int_parent[new_irq];

			/* Parent desc */
			memcpy(p, lstate->int_val[new_irq], isize);
			p += lstate->int_size;
		}
	}

	dt_add_property(np, "interrupt-map", map, map_size);
	free(map);
}

static void pci_add_loc_code(struct dt_node *np, struct pci_device *pd)
{
	struct dt_node *p = np->parent;
	const char *blcode = NULL;
	char *lcode;
	uint32_t class_code;
	uint8_t class, sub;
	uint8_t pos, len;

	/* If there is a label assigned to the function, use it on openpower machines */
	if (pd->slot)
		blcode = dt_prop_get_def(np, "ibm,slot-label", NULL);

	/* Look for a parent with a slot-location-code */
	while (!blcode && p) {
		blcode = dt_prop_get_def(p, "ibm,slot-location-code", NULL);
		p = p->parent;
	}
	if (!blcode)
		return;

	/* ethernet devices get port codes */
	class_code = dt_prop_get_u32(np, "class-code");
	class = class_code >> 16;
	sub = (class_code >> 8) & 0xff;

	/* XXX Don't do that on openpower for now, we will need to sort things
	 * out later, otherwise the mezzanine slot on Habanero gets weird results
	 */
	if (class == 0x02 && sub == 0x00 && fsp_present()) {
		/* There's usually several spaces at the end of the property.
		   Test for, but don't rely on, that being the case */
		len = strlen(blcode);
		for (pos = 0; pos < len; pos++)
			if (blcode[pos] == ' ') break;
		if (pos + 3 < len)
			lcode = strdup(blcode);
		else {
			lcode = malloc(pos + 3);
			memcpy(lcode, blcode, len);
		}
		lcode[pos++] = '-';
		lcode[pos++] = 'T';
		lcode[pos++] = (char)(pd->bdfn & 0x7) + '1';
		lcode[pos++] = '\0';
		dt_add_property_string(np, "ibm,loc-code", lcode);
		free(lcode);
	} else
		dt_add_property_string(np, "ibm,loc-code", blcode);
}

static void pci_print_summary_line(struct phb *phb, struct pci_device *pd,
				   struct dt_node *np, u32 rev_class,
				   const char *cname)
{
	const char *label, *dtype, *s;
	u32 vdid;
#define MAX_SLOTSTR 32
	char slotstr[MAX_SLOTSTR  + 1] = { 0, };

	pci_cfg_read32(phb, pd->bdfn, 0, &vdid);

	/* If it's a slot, it has a slot-label */
	label = dt_prop_get_def(np, "ibm,slot-label", NULL);
	if (label) {
		u32 lanes = dt_prop_get_u32_def(np, "ibm,slot-wired-lanes", 0);
		static const char *lanestrs[] = {
			"", " x1", " x2", " x4", " x8", "x16", "x32", "32b", "64b"
		};
		const char *lstr = lanes > PCI_SLOT_WIRED_LANES_PCIX_64 ? "" : lanestrs[lanes];
		snprintf(slotstr, MAX_SLOTSTR, "SLOT=%3s %s", label, lstr);
		/* XXX Add more slot info */
	} else {
		/*
		 * No label, ignore downstream switch legs and root complex,
		 * Those would essentially be non-populated
		 */
		if (pd->dev_type != PCIE_TYPE_ROOT_PORT &&
		    pd->dev_type != PCIE_TYPE_SWITCH_DNPORT) {
			/* It's a mere device, get loc code */
			s = dt_prop_get_def(np, "ibm,loc-code", NULL);
			if (s)
				snprintf(slotstr, MAX_SLOTSTR, "LOC_CODE=%s", s);
		}
	}

	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
		static const char *pcie_types[] = {
			"EP  ", "LGCY", "????", "????", "ROOT", "SWUP", "SWDN",
			"ETOX", "XTOE", "RINT", "EVTC" };
		if (pd->dev_type >= ARRAY_SIZE(pcie_types))
			dtype = "????";
		else
			dtype = pcie_types[pd->dev_type];
	} else
		dtype = pd->is_bridge ? "PCIB" : "PCID";

	if (pd->is_bridge)
		PCINOTICE(phb, pd->bdfn,
			  "[%s] %04x %04x R:%02x C:%06x B:%02x..%02x %s\n",
			  dtype, vdid & 0xffff, vdid >> 16,
			  rev_class & 0xff, rev_class >> 8, pd->secondary_bus,
			  pd->subordinate_bus, slotstr);
	else
		PCINOTICE(phb, pd->bdfn,
			  "[%s] %04x %04x R:%02x C:%06x (%14s) %s\n",
			  dtype, vdid & 0xffff, vdid >> 16,
			  rev_class & 0xff, rev_class >> 8, cname, slotstr);
}

static void pci_add_one_device_node(struct phb *phb,
				    struct pci_device *pd,
				    struct dt_node *parent_node,
				    struct pci_lsi_state *lstate,
				    uint8_t swizzle)
{
	struct dt_node *np;
	const char *cname;
#define MAX_NAME 256
	char name[MAX_NAME];
	char compat[MAX_NAME];
	uint32_t rev_class, vdid;
	uint32_t reg[5];
	uint8_t intpin;
	const uint32_t ranges_direct[] = {
				/* 64-bit direct mapping. We know the bridges
				 * don't cover the entire address space so
				 * use 0xf00... as a good compromise. */
				0x02000000, 0x0, 0x0,
				0x02000000, 0x0, 0x0,
				0xf0000000, 0x0};

	pci_cfg_read32(phb, pd->bdfn, 0, &vdid);
	pci_cfg_read32(phb, pd->bdfn, PCI_CFG_REV_ID, &rev_class);
	pci_cfg_read8(phb, pd->bdfn, PCI_CFG_INT_PIN, &intpin);

	/*
	 * Quirk for IBM bridge bogus class on PCIe root complex.
	 * Without it, the PCI DN won't be created for its downstream
	 * devices in Linux.
	 */
	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false) &&
	    parent_node == phb->dt_node)
		rev_class = (rev_class & 0xff) | 0x6040000;
	cname = pci_class_name(rev_class >> 8);

	if (pd->bdfn & 0x7)
		snprintf(name, MAX_NAME - 1, "%s@%x,%x",
			 cname, (pd->bdfn >> 3) & 0x1f, pd->bdfn & 0x7);
	else
		snprintf(name, MAX_NAME - 1, "%s@%x",
			 cname, (pd->bdfn >> 3) & 0x1f);
	pd->dn = np = dt_new(parent_node, name);

	/* XXX FIXME: make proper "compatible" properties */
	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
		snprintf(compat, MAX_NAME, "pciex%x,%x",
			 vdid & 0xffff, vdid >> 16);
		dt_add_property_cells(np, "ibm,pci-config-space-type", 1);
	} else {
		snprintf(compat, MAX_NAME, "pci%x,%x",
			 vdid & 0xffff, vdid >> 16);
		dt_add_property_cells(np, "ibm,pci-config-space-type", 0);
	}
	dt_add_property_cells(np, "class-code", rev_class >> 8);
	dt_add_property_cells(np, "revision-id", rev_class & 0xff);
	dt_add_property_cells(np, "vendor-id", vdid & 0xffff);
	dt_add_property_cells(np, "device-id", vdid >> 16);
	if (intpin)
		dt_add_property_cells(np, "interrupts", intpin);

	/* XXX FIXME: Add a few missing ones such as
	 *
	 *  - devsel-speed (!express)
	 *  - max-latency
	 *  - min-grant
	 *  - subsystem-id
	 *  - subsystem-vendor-id
	 *  - ...
	 */

	/* Add slot properties if needed and iff this is a bridge */
	if (pd->slot)
		pci_slot_add_dt_properties(pd->slot, np);

	/* Make up location code */
	pci_add_loc_code(np, pd);

	/* XXX FIXME: We don't look for BARs, we only put the config space
	 * entry in the "reg" property. That's enough for Linux and we might
	 * even want to make this legit in future ePAPR
	 */
	reg[0] = pd->bdfn << 8;
	reg[1] = reg[2] = reg[3] = reg[4] = 0;
	dt_add_property(np, "reg", reg, sizeof(reg));

	/* Print summary info about the device */
	pci_print_summary_line(phb, pd, np, rev_class, cname);
	if (!pd->is_bridge)
		return;

	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);

	/* We want "device_type" for bridges */
	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		dt_add_property_string(np, "device_type", "pciex");
	else
		dt_add_property_string(np, "device_type", "pci");

	/* Update the current interrupt swizzling level based on our own
	 * device number
	 */
	swizzle = (swizzle + ((pd->bdfn >> 3) & 0x1f)) & 3;

	/* We generate a standard-swizzling interrupt map. This is pretty
	 * big, we *could* try to be smarter for things that aren't hotplug
	 * slots at least and only populate those entries for which there's
	 * an actual children (especially on PCI Express), but for now that
	 * will do
	 */
	pci_std_swizzle_irq_map(np, pd, lstate, swizzle);

	/* Parts of the OF address translation in the kernel will fail to
	 * correctly translate a PCI address if translating a 1:1 mapping
	 * (ie. an empty ranges property).
	 * Instead add a ranges property that explicitly translates 1:1.
	 */
	dt_add_property(np, "ranges", ranges_direct, sizeof(ranges_direct));
}

void pci_add_device_nodes(struct phb *phb,
			  struct list_head *list,
			  struct dt_node *parent_node,
			  struct pci_lsi_state *lstate,
			  uint8_t swizzle)
{
	struct pci_device *pd;

	/* Add all child devices */
	list_for_each(list, pd, link) {
		pci_add_one_device_node(phb, pd, parent_node,
					lstate, swizzle);
		if (list_empty(&pd->children))
			continue;

		pci_add_device_nodes(phb, &pd->children,
				     pd->dn, lstate, swizzle);
	}
}

static void __pci_reset(struct list_head *list)
{
	struct pci_device *pd;

	while ((pd = list_pop(list, struct pci_device, link)) != NULL) {
		__pci_reset(&pd->children);
		free(pd);
	}
}

void pci_reset(void)
{
	unsigned int i;

	prlog(PR_NOTICE, "PCI: Clearing all devices...\n");

	/* This is a remnant of fast-reboot, not currently used */

	/* XXX Do those in parallel (at least the power up
	 * state machine could be done in parallel)
	 */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i])
			continue;
		__pci_reset(&phbs[i]->devices);
	}
}

static void pci_do_jobs(void (*fn)(void *))
{
	struct cpu_job **jobs;
	int i;

	jobs = zalloc(sizeof(struct cpu_job *) * ARRAY_SIZE(phbs));
	assert(jobs);
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i]) {
			jobs[i] = NULL;
			continue;
		}

		jobs[i] = __cpu_queue_job(NULL, phbs[i]->dt_node->name,
					  fn, phbs[i], false);
		assert(jobs[i]);

	}

	/* If no secondary CPUs, do everything sync */
	cpu_process_local_jobs();

	/* Wait until all tasks are done */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!jobs[i])
			continue;

		cpu_wait_job(jobs[i], true);
	}
	free(jobs);
}

void pci_init_slots(void)
{
	unsigned int i;

	prlog(PR_NOTICE, "PCI: Resetting PHBs...\n");
	pci_do_jobs(pci_reset_phb);

	prlog(PR_NOTICE, "PCI: Probing slots...\n");
	pci_do_jobs(pci_scan_phb);

	if (platform.pci_probe_complete)
		platform.pci_probe_complete();

	prlog(PR_DEBUG, "PCI Summary:\n");

	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i])
			continue;

		pci_add_device_nodes(phbs[i], &phbs[i]->devices,
				     phbs[i]->dt_node, &phbs[i]->lstate, 0);
	}

	/* PHB final fixup */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i] || !phbs[i]->ops || !phbs[i]->ops->phb_final_fixup)
			continue;

		phbs[i]->ops->phb_final_fixup(phbs[i]);
	}
}

/*
 * Complete iteration on current level before switching to
 * child level, which is the proper order for restoring
 * PCI bus range on bridges.
 */
static struct pci_device *__pci_walk_dev(struct phb *phb,
					 struct list_head *l,
					 int (*cb)(struct phb *,
						   struct pci_device *,
						   void *),
					 void *userdata)
{
	struct pci_device *pd, *child;

	if (list_empty(l))
		return NULL;

	list_for_each(l, pd, link) {
		if (cb && cb(phb, pd, userdata))
			return pd;
	}

	list_for_each(l, pd, link) {
		child = __pci_walk_dev(phb, &pd->children, cb, userdata);
		if (child)
			return child;
	}

	return NULL;
}

struct pci_device *pci_walk_dev(struct phb *phb,
				struct pci_device *pd,
				int (*cb)(struct phb *,
					  struct pci_device *,
					  void *),
				void *userdata)
{
	if (pd)
		return __pci_walk_dev(phb, &pd->children, cb, userdata);

	return __pci_walk_dev(phb, &phb->devices, cb, userdata);
}

static int __pci_find_dev(struct phb *phb,
			  struct pci_device *pd, void *userdata)
{
	uint16_t bdfn = *((uint16_t *)userdata);

	if (!phb || !pd)
		return 0;

	if (pd->bdfn == bdfn)
		return 1;

	return 0;
}

struct pci_device *pci_find_dev(struct phb *phb, uint16_t bdfn)
{
	return pci_walk_dev(phb, NULL, __pci_find_dev, &bdfn);
}

static int __pci_restore_bridge_buses(struct phb *phb,
				      struct pci_device *pd,
				      void *data __unused)
{
	if (!pd->is_bridge) {
		uint32_t vdid;

		/* Make all devices below a bridge "re-capture" the bdfn */
		if (pci_cfg_read32(phb, pd->bdfn, 0, &vdid) == 0)
			pci_cfg_write32(phb, pd->bdfn, 0, vdid);
		return 0;
	}

	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_PRIMARY_BUS,
		       pd->primary_bus);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SECONDARY_BUS,
		       pd->secondary_bus);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS,
		       pd->subordinate_bus);
	return 0;
}

void pci_restore_bridge_buses(struct phb *phb, struct pci_device *pd)
{
	pci_walk_dev(phb, pd, __pci_restore_bridge_buses, NULL);
}

struct pci_cfg_reg_filter *pci_find_cfg_reg_filter(struct pci_device *pd,
						   uint32_t start, uint32_t len)
{
	struct pci_cfg_reg_filter *pcrf;

	/* Check on the cached range, which contains holes */
	if ((start + len) <= pd->pcrf_start ||
	    pd->pcrf_end <= start)
		return NULL;

	list_for_each(&pd->pcrf, pcrf, link) {
		if (start >= pcrf->start &&
		    (start + len) <= (pcrf->start + pcrf->len))
			return pcrf;
	}

	return NULL;
}

struct pci_cfg_reg_filter *pci_add_cfg_reg_filter(struct pci_device *pd,
						  uint32_t start, uint32_t len,
						  uint32_t flags,
						  pci_cfg_reg_func func)
{
	struct pci_cfg_reg_filter *pcrf;

	pcrf = pci_find_cfg_reg_filter(pd, start, len);
	if (pcrf)
		return pcrf;

	pcrf = zalloc(sizeof(*pcrf) + ((len + 0x4) & ~0x3));
	if (!pcrf)
		return NULL;

	/* Don't validate the flags so that the private flags
	 * can be supported for debugging purpose.
	 */
	pcrf->flags = flags;
	pcrf->start = start;
	pcrf->len = len;
	pcrf->func = func;
	pcrf->data = (uint8_t *)(pcrf + 1);

	if (start < pd->pcrf_start)
		pd->pcrf_start = start;
	if (pd->pcrf_end < (start + len))
		pd->pcrf_end = start + len;
	list_add_tail(&pd->pcrf, &pcrf->link);

	return pcrf;
}
