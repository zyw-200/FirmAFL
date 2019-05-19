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

/*
 *
 * All functions in charge of generating the associativity/affinity
 * properties in the device-tree
 */

#ifndef __AFFINITY_H
#define __AFFINITY_H

struct dt_node;
struct cpu_thread;

extern void add_associativity_ref_point(void);

extern void add_chip_dev_associativity(struct dt_node *dev);
extern void add_core_associativity(struct cpu_thread *cpu);

#endif /* __AFFINITY_H */
