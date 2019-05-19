/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <opal-msg.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>

/* Debugging options */
#define PCI_SLOT_PREFIX	"PCI-SLOT-%016llx "
#define PCI_SLOT_DBG(s, fmt, a...)		 \
	prlog(PR_DEBUG, PCI_SLOT_PREFIX fmt, (s)->id, ##a)

static void pci_slot_prepare_link_change(struct pci_slot *slot, bool up)
{
	struct phb *phb = slot->phb;
	struct pci_device *pd = slot->pd;
	uint32_t aercap, mask;

	/*
	 * Mask the link down and receiver error before the link becomes
	 * down. Otherwise, unmask the errors when the link is up.
	 */
	if (pci_has_cap(pd, PCIECAP_ID_AER, true)) {
		aercap = pci_cap(pd, PCIECAP_ID_AER, true);

		/* Link down error */
		pci_cfg_read32(phb, pd->bdfn, aercap + PCIECAP_AER_UE_MASK,
			       &mask);
		if (up)
			mask &= ~PCIECAP_AER_UE_MASK_SURPRISE_DOWN;
		else
			mask |= PCIECAP_AER_UE_MASK_SURPRISE_DOWN;
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_UE_MASK,
				mask);

		/* Receiver error */
		pci_cfg_read32(phb, pd->bdfn, aercap + PCIECAP_AER_CE_MASK,
			       &mask);
		if (up)
			mask &= ~PCIECAP_AER_CE_RECVR_ERR;
		else
			mask |= PCIECAP_AER_CE_RECVR_ERR;
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_CE_MASK,
				mask);
	}

	/*
	 * We're coming back from reset. We need restore bus ranges
	 * and reinitialize the affected bridges and devices.
	 */
	if (up) {
		pci_restore_bridge_buses(phb, pd);
		if (phb->ops->device_init)
			pci_walk_dev(phb, pd, phb->ops->device_init, NULL);
	}
}

static int64_t pci_slot_sm_poll(struct pci_slot *slot)
{
	uint64_t now = mftb();
	int64_t ret;

	/* Return remaining timeout if we're still waiting */
	if (slot->delay_tgt_tb &&
	    tb_compare(now, slot->delay_tgt_tb) == TB_ABEFOREB)
		return slot->delay_tgt_tb - now;

	slot->delay_tgt_tb = 0;
	switch (slot->state & PCI_SLOT_STATE_MASK) {
	case PCI_SLOT_STATE_LINK:
		ret = slot->ops.poll_link(slot);
		break;
	case PCI_SLOT_STATE_HRESET:
		ret = slot->ops.hreset(slot);
		break;
	case PCI_SLOT_STATE_FRESET:
		ret = slot->ops.freset(slot);
		break;
	case PCI_SLOT_STATE_PFRESET:
		ret = slot->ops.pfreset(slot);
		break;
	case PCI_SLOT_STATE_CRESET:
		ret = slot->ops.creset(slot);
		break;
	default:
		prlog(PR_ERR, PCI_SLOT_PREFIX
		      "Invalid state %08x\n", slot->id, slot->state);
		pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
		return OPAL_HARDWARE;
	}

	return ret;
}

void pci_slot_add_dt_properties(struct pci_slot *slot,
				struct dt_node *np)
{
	/* Bail without device node */
	if (!np)
		return;

	dt_add_property_cells(np, "ibm,reset-by-firmware", 1);
	dt_add_property_cells(np, "ibm,slot-pluggable", slot->pluggable);
	dt_add_property_cells(np, "ibm,slot-power-ctl", slot->power_ctl);
	dt_add_property_cells(np, "ibm,slot-power-led-ctlled",
			      slot->power_led_ctl);
	dt_add_property_cells(np, "ibm,slot-attn-led", slot->attn_led_ctl);
	dt_add_property_cells(np, "ibm,slot-connector-type",
			      slot->connector_type);
	dt_add_property_cells(np, "ibm,slot-card-desc", slot->card_desc);
	dt_add_property_cells(np, "ibm,slot-card-mech", slot->card_mech);
	dt_add_property_cells(np, "ibm,slot-wired-lanes", slot->wired_lanes);

	if (slot->ops.add_properties)
		slot->ops.add_properties(slot, np);
}

struct pci_slot *pci_slot_alloc(struct phb *phb,
				struct pci_device *pd)
{
	struct pci_slot *slot = NULL;

	/*
	 * The function can be used to allocate either PHB slot or normal
	 * one. For both cases, the @phb should be always valid.
	 */
	if (!phb)
		return NULL;

	/*
	 * When @pd is NULL, we're going to create a PHB slot. Otherwise,
	 * a normal slot will be created. Check if the specified slot
	 * already exists or not.
	 */
	slot = pd ? pd->slot : phb->slot;
	if (slot) {
		prlog(PR_ERR, PCI_SLOT_PREFIX "Already exists\n", slot->id);
		return slot;
	}

	/* Allocate memory chunk */
	slot = zalloc(sizeof(struct pci_slot));
	if (!slot) {
		prlog(PR_ERR, "%s: Out of memory\n", __func__);
		return NULL;
	}

	/*
	 * The polling function sholdn't be overridden by individual
	 * platforms
	 */
	slot->phb = phb;
	slot->pd = pd;
	pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
	slot->power_state = PCI_SLOT_POWER_ON;
	slot->ops.poll = pci_slot_sm_poll;
	slot->ops.prepare_link_change = pci_slot_prepare_link_change;
	if (!pd) {
		slot->id = PCI_PHB_SLOT_ID(phb);
		phb->slot = slot;
	} else {
		slot->id = PCI_SLOT_ID(phb, pd->bdfn);
		pd->slot = slot;
	}

	return slot;
}

struct pci_slot *pci_slot_find(uint64_t id)
{
	struct phb *phb;
	struct pci_device *pd;
	struct pci_slot *slot;
	uint64_t index;
	uint16_t bdfn;

	index = PCI_SLOT_PHB_INDEX(id);
	phb = pci_get_phb(index);

	/* PHB slot */
	if (!(id & PCI_SLOT_ID_PREFIX)) {
		slot = phb ? phb->slot : NULL;
		return slot;
	}

	/* Normal PCI slot */
	bdfn = PCI_SLOT_BDFN(id);
	pd = phb ? pci_find_dev(phb, bdfn) : NULL;
	slot = pd ? pd->slot : NULL;
	return slot;
}
