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

#ifndef __HOSTSERVICES_H
#define __HOSTSERVICES_H

bool hservices_init(void);
void hservices_lid_preload(void);
bool hservices_lid_preload_complete(void);

int host_services_occ_load(void);
int host_services_occ_start(void);
int host_services_occ_stop(void);
void host_services_occ_base_setup(void);

/* No LID can be larger than 16M, but OCC lid is less than 1 MB */

#define HBRT_LOAD_LID_SIZE     0x100000 /* 1MB */

/* TODO: Detect OCC lid size at runtime */

/* Homer and OCC area size */
#define HOMER_IMAGE_SIZE	0x400000 /* 4MB per-chip */
#define OCC_COMMON_SIZE		0x800000 /* 8MB */

int find_master_and_slave_occ(uint64_t **master, uint64_t **slave,
			      int *nr_masters, int *nr_slaves);

#endif /* __HOSTSERVICES_H */
