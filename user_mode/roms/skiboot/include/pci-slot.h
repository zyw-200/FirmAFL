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

#ifndef __PCI_SLOT_H
#define __PCI_SLOT_H

#include <opal.h>
#include <device.h>
#include <timebase.h>
#include <timer.h>
#include <ccan/list/list.h>

/*
 * PCI Slot Info: Wired Lane Values
 *
 * Values 0 to 6 match slot map 1005. In case of *any* change here
 * make sure to keep the lxvpd.c parsing code in sync *and* the
 * corresponding label strings in pci.c
 */
#define PCI_SLOT_WIRED_LANES_UNKNOWN	0x00
#define PCI_SLOT_WIRED_LANES_PCIE_X1	0x01
#define PCI_SLOT_WIRED_LANES_PCIE_X2	0x02
#define PCI_SLOT_WIRED_LANES_PCIE_X4	0x03
#define PCI_SLOT_WIRED_LANES_PCIE_X8	0x04
#define PCI_SLOT_WIRED_LANES_PCIE_X16	0x05
#define PCI_SLOT_WIRED_LANES_PCIE_X32	0x06
#define PCI_SLOT_WIRED_LANES_PCIX_32	0x07
#define PCI_SLOT_WIRED_LANES_PCIX_64	0x08

/* PCI Slot Info: Bus Clock Values */
#define PCI_SLOT_BUS_CLK_RESERVED	0x00
#define PCI_SLOT_BUS_CLK_GEN_1		0x01
#define PCI_SLOT_BUS_CLK_GEN_2		0x02
#define PCI_SLOT_BUS_CLK_GEN_3		0x03

/* PCI Slot Info: Connector Type Values */
#define PCI_SLOT_CONNECTOR_PCIE_EMBED	0x00
#define PCI_SLOT_CONNECTOR_PCIE_X1	0x01
#define PCI_SLOT_CONNECTOR_PCIE_X2	0x02
#define PCI_SLOT_CONNECTOR_PCIE_X4	0x03
#define PCI_SLOT_CONNECTOR_PCIE_X8	0x04
#define PCI_SLOT_CONNECTOR_PCIE_X16	0x05
#define PCI_SLOT_CONNECTOR_PCIE_NS	0x0E	/* Non-Standard */

/* PCI Slot Info: Card Description Values */
#define PCI_SLOT_DESC_NON_STANDARD	0x00	/* Embed/Non-Standard       */
#define PCI_SLOT_DESC_PCIE_FH_FL	0x00	/* Full Height, Full Length */
#define PCI_SLOT_DESC_PCIE_FH_HL	0x01	/* Full Height, Half Length */
#define PCI_SLOT_DESC_PCIE_HH_FL	0x02	/* Half Height, Full Length */
#define PCI_SLOT_DESC_PCIE_HH_HL	0x03	/* Half Height, Half Length */

/* PCI Slot Info: Mechanicals Values */
#define PCI_SLOT_MECH_NONE		0x00
#define PCI_SLOT_MECH_RIGHT		0x01
#define PCI_SLOT_MECH_LEFT		0x02
#define PCI_SLOT_MECH_RIGHT_LEFT	0x03

/* PCI Slot Info: Power LED Control Values */
#define PCI_SLOT_PWR_LED_CTL_NONE	0x00	/* No Control        */
#define PCI_SLOT_PWR_LED_CTL_FSP	0x01	/* FSP Controlled    */
#define PCI_SLOT_PWR_LED_CTL_KERNEL	0x02	/* Kernel Controlled */

/* PCI Slot Info: ATTN LED Control Values */
#define PCI_SLOT_ATTN_LED_CTL_NONE	0x00	/* No Control        */
#define PCI_SLOT_ATTN_LED_CTL_FSP	0x01	/* FSP Controlled    */
#define PCI_SLOT_ATTN_LED_CTL_KERNEL	0x02	/* Kernel Controlled */

/* Attention LED */
#define PCI_SLOT_ATTN_LED_OFF		0
#define PCI_SLOT_ATTN_LED_ON		1
#define PCI_SLOT_ATTN_LED_BLINK		2

/* Power state */
#define PCI_SLOT_POWER_OFF		0
#define PCI_SLOT_POWER_ON		1

/*
 * We have hard and soft reset for slot. Hard reset requires
 * power-off and then power-on, but soft reset only resets
 * secondary bus.
 */
struct pci_slot;
struct pci_slot_ops {
	/* For slot management */
	int64_t (*get_presence_state)(struct pci_slot *slot, uint8_t *val);
	int64_t (*get_link_state)(struct pci_slot *slot, uint8_t *val);
	int64_t (*get_power_state)(struct pci_slot *slot, uint8_t *val);
	int64_t (*get_attention_state)(struct pci_slot *slot, uint8_t *val);
	int64_t (*get_latch_state)(struct pci_slot *slot, uint8_t *val);
	int64_t (*set_power_state)(struct pci_slot *slot, uint8_t val);
	int64_t (*set_attention_state)(struct pci_slot *slot, uint8_t val);

	/* SM based functions for reset */
	void (*prepare_link_change)(struct pci_slot *slot, bool is_up);
	int64_t (*poll_link)(struct pci_slot *slot);
	int64_t (*creset)(struct pci_slot *slot);
	int64_t (*freset)(struct pci_slot *slot);
	int64_t (*pfreset)(struct pci_slot *slot);
	int64_t (*hreset)(struct pci_slot *slot);
	int64_t (*poll)(struct pci_slot *slot);

	/* Auxillary functions */
	void (*add_properties)(struct pci_slot *slot, struct dt_node *np);
};

/*
 * The PCI slot state is split up into base and number. With this
 * design, the individual platforms can introduce their own PCI
 * slot states with addition to the base. Eventually, the base
 * state can be recognized by PCI slot core.
 */
#define PCI_SLOT_STATE_MASK			0xFFFFFF00
#define PCI_SLOT_STATE_NORMAL			0x00000000
#define PCI_SLOT_STATE_LINK			0x00000100
#define   PCI_SLOT_STATE_LINK_START_POLL	0x00000101
#define   PCI_SLOT_STATE_LINK_DELAY_FINALIZED	0x00000102
#define   PCI_SLOT_STATE_LINK_POLLING		0x00000103
#define PCI_SLOT_STATE_HRESET			0x00000200
#define   PCI_SLOT_STATE_HRESET_START		0x00000201
#define   PCI_SLOT_STATE_HRESET_HOLD		0x00000202
#define PCI_SLOT_STATE_FRESET			0x00000300
#define   PCI_SLOT_STATE_FRESET_POWER_OFF	0x00000301
#define PCI_SLOT_STATE_PFRESET			0x00000400
#define   PCI_SLOT_STATE_PFRESET_START		0x00000401
#define PCI_SLOT_STATE_CRESET			0x00000500
#define   PCI_SLOT_STATE_CRESET_START		0x00000501
#define PCI_SLOT_STATE_GPOWER			0x00000600
#define   PCI_SLOT_STATE_GPOWER_START		0x00000601
#define PCI_SLOT_STATE_SPOWER			0x00000700
#define   PCI_SLOT_STATE_SPOWER_START		0x00000701
#define   PCI_SLOT_STATE_SPOWER_DONE		0x00000702
#define PCI_SLOT_STATE_GPRESENCE		0x00000800
#define   PCI_SLOT_STATE_GPRESENCE_START	0x00000801


struct pci_slot {
	uint32_t		flags;
#define PCI_SLOT_FLAG_BOOTUP		0x1

	struct phb		*phb;
	struct pci_device	*pd;

	/* Identifier */
	uint64_t		id;
	struct timer		timer;
	uint64_t		async_token;
	uint8_t			power_state;

	/* Slot information */
	uint8_t			pluggable;
	uint8_t			power_ctl;
	uint8_t			power_led_ctl;
	uint8_t			attn_led_ctl;
	uint8_t			connector_type;
	uint8_t			card_desc;
	uint8_t			card_mech;
	uint8_t			wired_lanes;

	/*
	 * PCI slot is driven by state machine with polling function.
	 * @delay_tgt_tb tracks the current delay while @retries has
	 * the left rounds of delays. They should be set prior to
	 * switching next PCI slot state and changed (decreased)
	 * accordingly in the polling function.
	 */
	uint32_t		state;
	uint32_t		retry_state;
	uint32_t		link_cap;
	uint32_t		slot_cap;
	uint64_t		delay_tgt_tb;
	uint64_t		retries;
	struct pci_slot_ops	ops;
	void			*data;
};

#define PCI_SLOT_ID_PREFIX	0x8000000000000000
#define PCI_SLOT_ID(phb, bdfn)	\
	(PCI_SLOT_ID_PREFIX | ((uint64_t)(bdfn) << 16) | (phb)->opal_id)
#define PCI_PHB_SLOT_ID(phb)	((phb)->opal_id)
#define PCI_SLOT_PHB_INDEX(id)	((id) & 0xfffful)
#define PCI_SLOT_BDFN(id)	(((id) >> 16) & 0xfffful)

static inline uint32_t pci_slot_add_flags(struct pci_slot *slot,
					  uint32_t flags)
{
	uint32_t old = 0;

	if (slot) {
		old = slot->flags;
		slot->flags |= flags;
	}

	return old;
}

static inline bool pci_slot_has_flags(struct pci_slot *slot,
				      uint32_t flags)
{
	if (!slot)
		return false;

	if ((slot->flags & flags) == flags)
		return true;

	return false;
}

static inline uint32_t pci_slot_remove_flags(struct pci_slot *slot,
					     uint32_t flags)
{
	uint32_t old = 0;

	if (slot) {
		old = slot->flags;
		slot->flags &= ~flags;
	}

	return old;
}

static inline void pci_slot_set_state(struct pci_slot *slot, uint32_t state)
{
	if (slot)
		slot->state = state;
}

static inline uint64_t pci_slot_set_sm_timeout(struct pci_slot *slot,
					       uint64_t dur)
{
	if (slot)
		slot->delay_tgt_tb = mftb() + dur;
	return dur;
}

extern struct pci_slot *pci_slot_alloc(struct phb *phb,
				       struct pci_device *pd);
extern struct pci_slot *pcie_slot_create(struct phb *phb,
					 struct pci_device *pd);
extern void pci_slot_add_dt_properties(struct pci_slot *slot,
				       struct dt_node *np);
extern struct pci_slot *pci_slot_find(uint64_t id);
#endif /* __PCI_SLOT_H */
