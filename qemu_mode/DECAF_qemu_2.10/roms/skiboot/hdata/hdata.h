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

#ifndef __HDATA_H
#define __HDATA_H

struct dt_node;

extern void memory_parse(void);
extern int paca_parse(void);
extern bool pcia_parse(void);
extern void fsp_parse(void);
extern void io_parse(void);
extern struct dt_node *dt_add_vpd_node(const struct HDIF_common_hdr *hdr,
				       int indx_fru, int indx_vpd);
extern void vpd_parse(void);

extern struct dt_node *find_xscom_for_chip(uint32_t chip_id);
extern uint32_t pcid_to_chip_id(uint32_t proc_chip_id);

extern struct dt_node *add_core_common(struct dt_node *cpus,
				       const struct sppaca_cpu_cache *cache,
				       const struct sppaca_cpu_timebase *tb,
				       uint32_t int_server, bool okay);
extern void add_core_attr(struct dt_node *cpu, uint32_t attr);
extern uint32_t add_core_cache_info(struct dt_node *cpus,
				    const struct sppcia_cpu_cache *cache,
				    uint32_t int_server, int okay);
extern const struct slca_entry *slca_get_entry(uint16_t slca_index);
extern const char *slca_get_vpd_name(uint16_t slca_index);
extern const char *slca_get_loc_code_index(uint16_t slca_index);
extern void slca_vpd_add_loc_code(struct dt_node *node, uint16_t slca_index);
extern void slca_dt_add_sai_node(void);

extern bool hservices_from_hdat(const void *fdt, size_t size);

#endif /* __HDATA_H */

