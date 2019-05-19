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
#include <device.h>
#include <console.h>
#include <chip.h>
#include <pci.h>
#include <pci-slot.h>

#include "astbmc.h"

static const struct slot_table_entry *slot_top_table;

void slot_table_init(const struct slot_table_entry *top_table)
{
	slot_top_table = top_table;
}

static const struct slot_table_entry *match_slot_phb_entry(struct phb *phb)
{
	uint32_t chip_id = dt_get_chip_id(phb->dt_node);
	uint32_t phb_idx = dt_prop_get_u32_def(phb->dt_node,
					       "ibm,phb-index", 0);
	const struct slot_table_entry *ent;

	if (!slot_top_table)
		return NULL;

	for (ent = slot_top_table; ent->etype != st_end; ent++) {
		if (ent->etype != st_phb) {
			prerror("SLOT: Bad DEV entry type in table !\n");
			continue;
		}
		if (ent->location == ST_LOC_PHB(chip_id, phb_idx))
			return ent;
	}
	return NULL;
}

static const struct slot_table_entry *match_slot_dev_entry(struct phb *phb,
							   struct pci_device *pd)
{
	const struct slot_table_entry *parent, *ent;
	uint32_t bdfn;

	/* Find a parent recursively */
	if (pd->parent)
		parent = match_slot_dev_entry(phb, pd->parent);
	else {
		/* No parent, this is a root complex, find the PHB */
		parent = match_slot_phb_entry(phb);
	}
	/* No parent ? Oops ... */
	if (!parent || !parent->children)
		return NULL;
	for (ent = parent->children; ent->etype != st_end; ent++) {
		if (ent->etype == st_phb) {
			prerror("SLOT: Bad PHB entry type in table !\n");
			continue;
		}

		/* NPU slots match on device, not function */
		if (ent->etype == st_npu_slot)
			bdfn = pd->bdfn & 0xf8;
		else
			bdfn = pd->bdfn & 0xff;

		if (ent->location == bdfn)
			return ent;
	}
	return NULL;
}

static void add_slot_properties(struct pci_slot *slot,
				struct dt_node *np)
{
	struct phb *phb = slot->phb;
	struct slot_table_entry *ent = slot->data;
	size_t base_loc_code_len, slot_label_len;
	char loc_code[LOC_CODE_SIZE];

	if (!np || !ent)
		return;

	base_loc_code_len = phb->base_loc_code ? strlen(phb->base_loc_code) : 0;
	slot_label_len = strlen(ent->name);
	if ((base_loc_code_len + slot_label_len + 1) >= LOC_CODE_SIZE)
		return;

	/* Location code */
	if (phb->base_loc_code) {
		strcpy(loc_code, phb->base_loc_code);
		strcat(loc_code, "-");
	} else {
		loc_code[0] = '\0';
	}

	strcat(loc_code, ent->name);
	dt_add_property(np, "ibm,slot-location-code",
			loc_code, strlen(loc_code) + 1);
	dt_add_property_string(np, "ibm,slot-label", ent->name);
}

void slot_table_get_slot_info(struct phb *phb, struct pci_device * pd)
{
	const struct slot_table_entry *ent;
	struct pci_slot *slot;

	if (!pd || pd->slot)
		return;
	ent = match_slot_dev_entry(phb, pd);
	if (!ent || !ent->name)
		return;

	slot = pcie_slot_create(phb, pd);
	assert(slot);
	slot->ops.add_properties = add_slot_properties;
	slot->data = (void *)ent;

	slot->pluggable      = ent->etype == st_pluggable_slot;
	slot->power_ctl      = false;
	slot->wired_lanes    = PCI_SLOT_WIRED_LANES_UNKNOWN;
	slot->connector_type = PCI_SLOT_CONNECTOR_PCIE_NS;
	slot->card_desc      = PCI_SLOT_DESC_NON_STANDARD;
	slot->card_mech      = PCI_SLOT_MECH_NONE;
	slot->power_led_ctl  = PCI_SLOT_PWR_LED_CTL_NONE;
	slot->attn_led_ctl   = PCI_SLOT_ATTN_LED_CTL_NONE;
}
