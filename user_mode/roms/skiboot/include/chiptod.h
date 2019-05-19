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

#ifndef __CHIPTOD_H
#define __CHIPTOD_H

/* The ChipTOD is the HW facility that maintains a synchronized
 * time base across the fabric.
 */

enum chiptod_topology {
	chiptod_topo_unknown = -1,
	chiptod_topo_primary = 0,
	chiptod_topo_secondary = 1,
};

extern void chiptod_init(void);
extern bool chiptod_wakeup_resync(void);
extern int chiptod_recover_tb_errors(void);
extern void chiptod_reset_tb(void);
extern bool chiptod_adjust_topology(enum chiptod_topology topo, bool enable);
struct phb3;
extern bool chiptod_capp_timebase_sync(struct phb3 *p);

#endif /* __CHIPTOD_H */
