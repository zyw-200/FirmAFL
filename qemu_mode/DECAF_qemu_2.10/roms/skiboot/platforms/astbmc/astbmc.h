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


#ifndef __ASTBMC_H
#define __ASTBMC_H

#define ST_LOC_PHB(chip_id, phb_idx)    ((chip_id) << 16 | (phb_idx))
#define ST_LOC_DEVFN(dev, fn)	        ((dev) << 3 | (fn))
/*
 * NPU groups are used to allocate device numbers.  There is a 1 to 1
 * correlation between a NPU group and a physical GPU.  Links within a group
 * are allocated as functions within a device, so groups must be numbered
 * sequentially starting at 0.
 */
#define ST_LOC_NPU_GROUP(group_id)	(group_id << 3)

struct slot_table_entry {
	enum slot_table_etype {
		st_end,		/* End of list */
		st_phb,
		st_pluggable_slot,
		st_builtin_dev,
		st_npu_slot
	} etype;
	uint32_t location;
	const char *name;
	const struct slot_table_entry *children;
};

extern void astbmc_early_init(void);
extern int64_t astbmc_ipmi_reboot(void);
extern int64_t astbmc_ipmi_power_down(uint64_t request);
extern void astbmc_init(void);
extern void astbmc_ext_irq_serirq_cpld(unsigned int chip_id);
extern int pnor_init(void);

extern void slot_table_init(const struct slot_table_entry *top_table);
extern void slot_table_get_slot_info(struct phb *phb, struct pci_device * pd);

#endif /* __ASTBMC_H */
