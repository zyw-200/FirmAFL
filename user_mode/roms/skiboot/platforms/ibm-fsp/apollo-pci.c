/* Copyright 2013-2015 IBM Corp.
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
#include <device.h>
#include <fsp.h>
#include <p7ioc.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

/* Debugging option */
#define APOLLO_PCI_DBG(fmt, a...)	\
	prlog(PR_DEBUG, "APOLLO-PCI: " fmt, ##a)
#define APOLLO_PCI_INFO(fmt, a...)	\
	prlog(PR_INFO, "APOLLO-PCI: " fmt, ##a)
#define APOLLO_PCI_ERR(fmt, a...)	\
	prlog(PR_ERR, "APOLLO-PCI: " fmt, ##a)

void apollo_pci_setup_phb(struct phb *phb, unsigned int index)
{
	struct dt_node *ioc_node;

	/* Grab the device-tree node of the IOC */
	ioc_node = phb->dt_node->parent;
	if (!ioc_node) {
		APOLLO_PCI_DBG("No IOC devnode for PHB%04x\n",
			       phb->opal_id);
		return;
	}

	/*
	 * Process the pcie slot entries from the lx vpd lid
	 *
	 * FIXME: We currently assume chip 1 always, this will have to be
	 * fixed once we understand the right way to get the BRxy/BRxy "x"
	 * "x" value. It's not working well. I found 2 different root ports
	 * on Firebird-L has been assigned to same slot label.
	 */
	lxvpd_process_slot_entries(phb, ioc_node, 1,
				   index, sizeof(struct lxvpd_pci_slot));
}

void apollo_pci_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	struct pci_slot *slot;
	struct lxvpd_pci_slot *s = NULL;

	if (pd->dev_type != PCIE_TYPE_ROOT_PORT     &&
	    pd->dev_type != PCIE_TYPE_SWITCH_UPPORT &&
	    pd->dev_type != PCIE_TYPE_SWITCH_DNPORT &&
	    pd->dev_type != PCIE_TYPE_PCIE_TO_PCIX)
		return;

	/* Create PCIe slot */
	slot = pcie_slot_create(phb, pd);
	if (!slot)
		return;

	/* Root complex inherits methods from PHB slot */
	if (!pd->parent && phb->slot)
		memcpy(&slot->ops, &phb->slot->ops, sizeof(struct pci_slot_ops));

	/* Patch PCIe slot */
	s = lxvpd_get_slot(slot);
	if (s) {
		lxvpd_extract_info(slot, s);
		slot->ops.add_properties = lxvpd_add_slot_properties;
	}
}
