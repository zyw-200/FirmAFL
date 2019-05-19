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

#ifndef __VPD_H
#define __VPD_H

struct machine_info {
	const char *mtm;
	const char *name;
};

const struct machine_info *machine_info_lookup(char *mtm);

const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size);

const void *vpd_find_record(const void *vpd, size_t vpd_size,
			    const char *record, size_t *sz);

const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz);

/* Add model property to dt_root */
void add_dtb_model(void);

void vpd_iohub_load(struct dt_node *hub_node);
void vpd_preload(struct dt_node *hub_node);

#define VPD_LOAD_LXRN_VINI	0xff


#endif /* __VPD_H */
