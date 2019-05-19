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

#ifndef __LXVPD_H
#define __LXVPD_H

#define LX_VPD_1S2U_BACKPLANE	0x3100040100300041ull
#define LX_VPD_2S2U_BACKPLANE	0x3100040100300042ull
#define LX_VPD_SHARK_BACKPLANE	0x3100040100300942ull
#define LX_VPD_1S4U_BACKPLANE	0x3100040100300043ull
#define LX_VPD_2S4U_BACKPLANE	0x3100040100300044ull

struct slot_p0 {
	union {
		uint8_t     byte;
		struct {
			uint8_t     pluggable:1;
			uint8_t     pluggable_location:3;
			uint8_t     power_ctl:1;
			uint8_t     rsvd_5:1;
			uint8_t     upstream_port:1;
			uint8_t     alt_load_source:1;
		};
	};
};

struct slot_p1 {
	uint8_t     rsvd_0:1;
	uint8_t     wired_lanes:3;
	uint8_t     rsvd_4:4;
};

struct slot_p2 {
	uint8_t     rsvd_0:1;
	uint8_t     bus_clock:3;
	uint8_t     connector_type:4;
};

struct slot_p3 {
	union {
		uint8_t     byte;
		struct {
			uint8_t    height:1;
			uint8_t    length:1;
			uint8_t    left_mech:1;
			uint8_t    right_mech:1;
			uint8_t    pow_led_kvm:1;
			uint8_t    pow_led_fsp:1;
			uint8_t    attn_led_kvm:1;
			uint8_t    attn_led_fsp:1;
		};
	};
};

struct pci_slot_entry_1004 {
	uint8_t               pba;
	uint8_t               sba;
	uint8_t               phb_or_slot_type;
	char                  label[3];
	uint16_t              bis;
	struct slot_p0        p0;
	struct slot_p1        p1;
	struct slot_p2        p2;
	struct slot_p3        p3;
	uint8_t               left_pitch;
	uint8_t               right_pitch;
	uint8_t               slot_index;
	uint8_t               max_slot_power;
};

/* P8 PCI Slot Entry Definitions -- 1005 */
struct pci_slot_entry_1005 {
	union {
		uint8_t    pba;
		struct {
			uint8_t    switch_id:4;
			uint8_t    vswitch_id:4;
		};
	};
	uint8_t               switch_device_id;
	uint8_t               slot_type:4;
	uint8_t               phb_id:4;
	char                  label[8];
	uint8_t               rsvd_11[4];
	struct slot_p0        p0;
	struct slot_p1        p1;
	struct slot_p2        p2;
	struct slot_p3        p3;
	uint8_t               left_pitch;
	uint8_t               right_pitch;
	uint8_t               slot_index;
	uint8_t               rsvd_22[2];
};

struct lxvpd_pci_slot {
	struct pci_slot	*pci_slot;
	uint8_t		switch_id;
	uint8_t		vswitch_id;
	uint8_t		dev_id;
	char		label[9];
	bool		pluggable;
	bool		power_ctl;
	uint8_t		wired_lanes;
	uint8_t		bus_clock;
	uint8_t		connector_type;
	uint8_t		card_desc;
	uint8_t		card_mech;
	uint8_t		pwr_led_ctl;
	uint8_t		attn_led_ctl;
	uint8_t		slot_index;
};

extern void lxvpd_process_slot_entries(struct phb *phb, struct dt_node *node,
				       uint8_t chip_id, uint8_t index,
				       uint32_t slot_size);
extern void *lxvpd_get_slot(struct pci_slot *slot);
extern void lxvpd_extract_info(struct pci_slot *slot,
			       struct lxvpd_pci_slot *s);
extern void lxvpd_add_slot_properties(struct pci_slot *slot,
				      struct dt_node *np);
#endif /* __LXVPD_H */
