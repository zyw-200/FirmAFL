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

#ifndef __PCI_H
#define __PCI_H

#include <opal.h>
#include <device.h>
#include <lock.h>
#include <ccan/list/list.h>

struct pci_device;
struct pci_cfg_reg_filter;

typedef void (*pci_cfg_reg_func)(struct pci_device *pd,
				 struct pci_cfg_reg_filter *pcrf,
				 uint32_t offset, uint32_t len,
				 uint32_t *data, bool write);
struct pci_cfg_reg_filter {
	uint32_t		flags;
#define PCI_REG_FLAG_READ	0x1
#define PCI_REG_FLAG_WRITE	0x2
#define PCI_REG_FLAG_MASK	0x3
	uint32_t		start;
	uint32_t		len;
	uint8_t			*data;
	pci_cfg_reg_func	func;
	struct list_node	link;
};

/*
 * While this might not be necessary in the long run, the existing
 * Linux kernels expect us to provide a device-tree that contains
 * a representation of all PCI devices below the host bridge. Thus
 * we need to perform a bus scan. We don't need to assign MMIO/IO
 * resources, but we do need to assign bus numbers in a way that
 * is going to be compatible with the HW constraints for PE filtering
 * that is naturally aligned power of twos for ranges below a bridge.
 *
 * Thus the structure pci_device is used for the tracking of the
 * detected devices and the later generation of the device-tree.
 *
 * We do not keep a separate structure for a bus, however a device
 * can have children in which case a device is a bridge.
 *
 * Because this is likely to change, we avoid putting too much
 * information in that structure nor relying on it for anything
 * else but the construction of the flat device-tree.
 */
struct pci_device {
	uint16_t		bdfn;
	bool			is_bridge;
	bool			is_multifunction;
	uint8_t			dev_type; /* PCIE */
	uint8_t			primary_bus;
	uint8_t			secondary_bus;
	uint8_t			subordinate_bus;
	uint32_t		scan_map;

	uint32_t		vdid;
	uint32_t		sub_vdid;
	uint32_t		class;
	uint64_t		cap_list;
	uint32_t		cap[64];
	uint32_t		mps;		/* Max payload size capability */

	uint32_t		pcrf_start;
	uint32_t		pcrf_end;
	struct list_head	pcrf;

	struct dt_node		*dn;
	struct pci_slot		*slot;
	struct pci_device	*parent;
	struct list_head	children;
	struct list_node	link;
};

static inline void pci_set_cap(struct pci_device *pd,
			       int id, int pos, bool ext)
{
	if (!ext) {
		pd->cap_list |= (0x1ul << id);
		pd->cap[id] = pos;
	} else {
		pd->cap_list |= (0x1ul << (id + 32));
		pd->cap[id + 32] = pos;
	}
}

static inline bool pci_has_cap(struct pci_device *pd,
			       int id, bool ext)
{
	if (!ext)
		return !!(pd->cap_list & (0x1ul << id));
	else
		return !!(pd->cap_list & (0x1ul << (id + 32)));
}

static inline int pci_cap(struct pci_device *pd,
			  int id, bool ext)
{
	if (!ext)
		return pd->cap[id];
	else
		return pd->cap[id + 32];
}

/*
 * When generating the device-tree, we need to keep track of
 * the LSI mapping & swizzle it. This state structure is
 * passed by the PHB to pci_add_nodes() and will be used
 * internally.
 *
 * We assume that the interrupt parent (PIC) #address-cells
 * is 0 and #interrupt-cells has a max value of 2.
 */
struct pci_lsi_state {
#define MAX_INT_SIZE	2
	uint32_t int_size;			/* #cells */
	uint32_t int_val[4][MAX_INT_SIZE];	/* INTA...INTD */
	uint32_t int_parent[4];
};

/*
 * NOTE: All PCI functions return negative OPAL error codes
 *
 * In addition, some functions may return a positive timeout
 * value or some other state information, see the description
 * of individual functions. If nothing is specified, it's
 * just an error code or 0 (success).
 *
 * Functions that operate asynchronously will return a positive
 * delay value and will require the ->poll() op to be called after
 * that delay. ->poll() will then return success, a negative error
 * code, or another delay.
 *
 * Note: If an asynchronous function returns 0, it has completed
 * successfully and does not require a call to ->poll(). Similarly
 * if ->poll() is called while no operation is in progress, it will
 * simply return 0 (success)
 *
 * Note that all functions except ->lock() itself assume that the
 * caller is holding the PHB lock.
 *
 * TODO: Add more interfaces to control things like link width
 *       reduction for power savings etc...
 */

struct phb;
extern int last_phb_id;

struct phb_ops {
	/*
	 * Config space ops
	 */
	int64_t (*cfg_read8)(struct phb *phb, uint32_t bdfn,
			     uint32_t offset, uint8_t *data);
	int64_t (*cfg_read16)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint16_t *data);
	int64_t (*cfg_read32)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint32_t *data);
	int64_t (*cfg_write8)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint8_t data);
	int64_t (*cfg_write16)(struct phb *phb, uint32_t bdfn,
			       uint32_t offset, uint16_t data);
	int64_t (*cfg_write32)(struct phb *phb, uint32_t bdfn,
			       uint32_t offset, uint32_t data);

	/*
	 * Bus number selection. See pci_scan() for a description
	 */
	uint8_t (*choose_bus)(struct phb *phb, struct pci_device *bridge,
			      uint8_t candidate, uint8_t *max_bus,
			      bool *use_max);
	int64_t (*get_reserved_pe_number)(struct phb *phb);

	/*
	 * Device init method is called after a device has been detected
	 * and before probing further. It can alter things like scan_map
	 * for bridge ports etc...
	 */
	int (*device_init)(struct phb *phb, struct pci_device *device,
			   void *data);

	/* PHB final fixup is called after PCI probing is completed */
	void (*phb_final_fixup)(struct phb *phb);

	/*
	 * EEH methods
	 *
	 * The various arguments are identical to the corresponding
	 * OPAL functions
	 */
	int64_t (*eeh_freeze_status)(struct phb *phb, uint64_t pe_number,
				     uint8_t *freeze_state,
				     uint16_t *pci_error_type,
				     uint16_t *severity,
				     uint64_t *phb_status);
	int64_t (*eeh_freeze_clear)(struct phb *phb, uint64_t pe_number,
				    uint64_t eeh_action_token);
	int64_t (*eeh_freeze_set)(struct phb *phb, uint64_t pe_number,
				  uint64_t eeh_action_token);
	int64_t (*err_inject)(struct phb *phb, uint32_t pe_no, uint32_t type,
			      uint32_t func, uint64_t addr, uint64_t mask);
	int64_t (*get_diag_data)(struct phb *phb, void *diag_buffer,
				 uint64_t diag_buffer_len);
	int64_t (*get_diag_data2)(struct phb *phb, void *diag_buffer,
				  uint64_t diag_buffer_len);
	int64_t (*next_error)(struct phb *phb, uint64_t *first_frozen_pe,
			      uint16_t *pci_error_type, uint16_t *severity);

	/*
	 * Other IODA methods
	 *
	 * The various arguments are identical to the corresponding
	 * OPAL functions
	 */
	int64_t (*pci_reinit)(struct phb *phb, uint64_t scope, uint64_t data);
	int64_t (*phb_mmio_enable)(struct phb *phb, uint16_t window_type,
				   uint16_t window_num, uint16_t enable);

	int64_t (*set_phb_mem_window)(struct phb *phb, uint16_t window_type,
				      uint16_t window_num, uint64_t addr,
				      uint64_t pci_addr, uint64_t size);

	int64_t (*map_pe_mmio_window)(struct phb *phb, uint16_t pe_number,
				      uint16_t window_type, uint16_t window_num,
				      uint16_t segment_num);

	int64_t (*set_pe)(struct phb *phb, uint64_t pe_number,
			  uint64_t bus_dev_func, uint8_t bus_compare,
			  uint8_t dev_compare, uint8_t func_compare,
			  uint8_t pe_action);

	int64_t (*set_peltv)(struct phb *phb, uint32_t parent_pe,
			     uint32_t child_pe, uint8_t state);

	int64_t (*map_pe_dma_window)(struct phb *phb, uint16_t pe_number,
				     uint16_t window_id, uint16_t tce_levels,
				     uint64_t tce_table_addr,
				     uint64_t tce_table_size,
				     uint64_t tce_page_size);

	int64_t (*map_pe_dma_window_real)(struct phb *phb, uint16_t pe_number,
					  uint16_t dma_window_number,
					  uint64_t pci_start_addr,
					  uint64_t pci_mem_size);

	int64_t (*set_mve)(struct phb *phb, uint32_t mve_number,
			   uint32_t pe_number);

	int64_t (*set_mve_enable)(struct phb *phb, uint32_t mve_number,
				  uint32_t state);

	int64_t (*set_xive_pe)(struct phb *phb, uint32_t pe_number,
			       uint32_t xive_num);

	int64_t (*get_xive_source)(struct phb *phb, uint32_t xive_num,
				   int32_t *interrupt_source_number);

	int64_t (*get_msi_32)(struct phb *phb, uint32_t mve_number,
			      uint32_t xive_num, uint8_t msi_range,
			      uint32_t *msi_address, uint32_t *message_data);

	int64_t (*get_msi_64)(struct phb *phb, uint32_t mve_number,
			      uint32_t xive_num, uint8_t msi_range,
			      uint64_t *msi_address, uint32_t *message_data);

	int64_t (*ioda_reset)(struct phb *phb, bool purge);

	int64_t (*papr_errinjct_reset)(struct phb *phb);

	/*
	 * P5IOC2 only
	 */
	int64_t (*set_phb_tce_memory)(struct phb *phb, uint64_t tce_mem_addr,
				      uint64_t tce_mem_size);

	/*
	 * IODA2 PCI interfaces
	 */
	int64_t (*pci_msi_eoi)(struct phb *phb, uint32_t hwirq);

	/* TCE Kill abstraction */
	int64_t (*tce_kill)(struct phb *phb, uint32_t kill_type,
			    uint32_t pe_num, uint32_t tce_size,
			    uint64_t dma_addr, uint32_t npages);

	/* Put phb in capi mode or pcie mode */
	int64_t (*set_capi_mode)(struct phb *phb, uint64_t mode, uint64_t pe_number);

	int64_t (*set_capp_recovery)(struct phb *phb);
};

enum phb_type {
	phb_type_pci,
	phb_type_pcix_v1,
	phb_type_pcix_v2,
	phb_type_pcie_v1,
	phb_type_pcie_v2,
	phb_type_pcie_v3,
	phb_type_pcie_v4,
};

struct phb {
	struct dt_node		*dt_node;
	int			opal_id;
	uint32_t		scan_map;
	enum phb_type		phb_type;
	struct lock		lock;
	struct list_head	devices;
	const struct phb_ops	*ops;
	struct pci_lsi_state	lstate;
	uint32_t		mps;

	/* PCI-X only slot info, for PCI-E this is in the RC bridge */
	struct pci_slot		*slot;

	/* Base location code used to generate the children one */
	const char		*base_loc_code;

	/* Additional data the platform might need to attach */
	void			*platform_data;
};

static inline void phb_lock(struct phb *phb)
{
	lock(&phb->lock);
}

static inline void phb_unlock(struct phb *phb)
{
	unlock(&phb->lock);
}

/* Config space ops wrappers */
static inline int64_t pci_cfg_read8(struct phb *phb, uint32_t bdfn,
				    uint32_t offset, uint8_t *data)
{
	return phb->ops->cfg_read8(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_read16(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint16_t *data)
{
	return phb->ops->cfg_read16(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_read32(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint32_t *data)
{
	return phb->ops->cfg_read32(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write8(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint8_t data)
{
	return phb->ops->cfg_write8(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write16(struct phb *phb, uint32_t bdfn,
				      uint32_t offset, uint16_t data)
{
	return phb->ops->cfg_write16(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write32(struct phb *phb, uint32_t bdfn,
				      uint32_t offset, uint32_t data)
{
	return phb->ops->cfg_write32(phb, bdfn, offset, data);
}

/* Utilities */
extern void pci_remove_bus(struct phb *phb, struct list_head *list);
extern uint8_t pci_scan_bus(struct phb *phb, uint8_t bus, uint8_t max_bus,
			    struct list_head *list, struct pci_device *parent,
			    bool scan_downstream);
extern void pci_add_device_nodes(struct phb *phb,
				 struct list_head *list,
				 struct dt_node *parent_node,
				 struct pci_lsi_state *lstate,
				 uint8_t swizzle);
extern int64_t pci_find_cap(struct phb *phb, uint16_t bdfn, uint8_t cap);
extern int64_t pci_find_ecap(struct phb *phb, uint16_t bdfn, uint16_t cap,
			     uint8_t *version);
extern void pci_device_init(struct phb *phb, struct pci_device *pd);
extern struct pci_device *pci_walk_dev(struct phb *phb,
				       struct pci_device *pd,
				       int (*cb)(struct phb *,
						 struct pci_device *,
						 void *),
				       void *userdata);
extern struct pci_device *pci_find_dev(struct phb *phb, uint16_t bdfn);
extern void pci_restore_bridge_buses(struct phb *phb, struct pci_device *pd);
extern struct pci_cfg_reg_filter *pci_find_cfg_reg_filter(struct pci_device *pd,
					uint32_t start, uint32_t len);
extern struct pci_cfg_reg_filter *pci_add_cfg_reg_filter(struct pci_device *pd,
					uint32_t start, uint32_t len,
					uint32_t flags, pci_cfg_reg_func func);

/* Manage PHBs */
#define OPAL_DYNAMIC_PHB_ID (~0)
extern int64_t pci_register_phb(struct phb *phb, int opal_id);
extern int64_t pci_unregister_phb(struct phb *phb);
extern struct phb *pci_get_phb(uint64_t phb_id);

static inline struct phb *__pci_next_phb_idx(uint64_t *phb_id) {
	struct phb *phb = NULL;
	while (phb == NULL && *phb_id <= last_phb_id) {
		phb = pci_get_phb((*phb_id)++);
	}
	return phb;
}

#define for_each_phb(phb)					\
	for (uint64_t __phb_idx = 0;				\
	     (phb = __pci_next_phb_idx(&__phb_idx)) ; )

/* Device tree */
extern void pci_std_swizzle_irq_map(struct dt_node *dt_node,
				    struct pci_device *pd,
				    struct pci_lsi_state *lstate,
				    uint8_t swizzle);

/* Initialize all PCI slots */
extern void pci_init_slots(void);
extern void pci_reset(void);

extern void opal_pci_eeh_set_evt(uint64_t phb_id);
extern void opal_pci_eeh_clear_evt(uint64_t phb_id);

#endif /* __PCI_H */
