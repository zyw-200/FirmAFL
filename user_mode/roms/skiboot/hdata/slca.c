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


#include <device.h>
#include <include/opal-internal.h>
#include <fsp-leds.h>

#include "spira.h"
#include "hdata.h"

const struct slca_entry *slca_get_entry(uint16_t slca_index)
{
	struct HDIF_common_hdr *slca_hdr;
	int count;

	slca_hdr = get_hdif(&spira.ntuples.slca, SLCA_HDIF_SIG);
	if (!slca_hdr) {
		prerror("SLCA Invalid\n");
		return NULL;
	}

	count = HDIF_get_iarray_size(slca_hdr, SLCA_IDATA_ARRAY);
	if (count < 0) {
		prerror("SLCA: Can't find SLCA array size!\n");
		return NULL;
	}

	if (slca_index < count) {
		const struct slca_entry *s_entry;
		unsigned int entry_sz;
		s_entry = HDIF_get_iarray_item(slca_hdr, SLCA_IDATA_ARRAY,
					slca_index, &entry_sz);

		if (s_entry && entry_sz >= sizeof(*s_entry))
			return s_entry;
	} else
		prlog(PR_NOTICE,
		      "SLCA: Can't find slca_entry for index %d\n", slca_index);
	return NULL;
}

const char *slca_get_vpd_name(uint16_t slca_index)
{
	const struct slca_entry *s_entry;

	s_entry = slca_get_entry(slca_index);
	if (s_entry)
		return (const char *)s_entry->fru_id;
	else
		prlog(PR_NOTICE,
		      "SLCA: Can't find fru_id for index %d\n", slca_index);
	return NULL;
}

const char *slca_get_loc_code_index(uint16_t slca_index)
{
	const struct slca_entry *s_entry;

	s_entry = slca_get_entry(slca_index);
	if (s_entry)
		return s_entry->loc_code;
	else
		prlog(PR_NOTICE, "SLCA: Entry %d bad idata\n", slca_index);

	return NULL;
}

void slca_vpd_add_loc_code(struct dt_node *node, uint16_t slca_index)
{
	const char *fru_loc_code;
	char loc_code[LOC_CODE_SIZE];

	memset(loc_code, 0, sizeof(loc_code));
	fru_loc_code = slca_get_loc_code_index(slca_index);
	if (!fru_loc_code)
		return;

	strncpy(loc_code, fru_loc_code, LOC_CODE_SIZE - 1);
	dt_add_property(node, "ibm,loc-code", loc_code, strlen(loc_code) + 1);
}

/*
 * Get System Attention Indicator SLCA entry
 */
static const struct slca_entry *slca_get_sai_entry(void)
{
	int count;
	unsigned int i;
	struct HDIF_common_hdr *slca_hdr;

	slca_hdr = get_hdif(&spira.ntuples.slca, SLCA_HDIF_SIG);
	if (!slca_hdr) {
		prerror("SLCA Invalid\n");
		return NULL;
	}

	count = HDIF_get_iarray_size(slca_hdr, SLCA_IDATA_ARRAY);
	if (count < 0) {
		prerror("SLCA: Can't find SLCA array size!\n");
		return NULL;
	}

	for (i = 0; i < count; i++) {
		const struct slca_entry *s_entry;
		unsigned int entry_sz;

		s_entry = HDIF_get_iarray_item(slca_hdr, SLCA_IDATA_ARRAY,
					       i, &entry_sz);
		if (s_entry &&
		    VPD_ID(s_entry->fru_id[0],
			   s_entry->fru_id[1]) == SLCA_SAI_INDICATOR_ID) {
			prlog(PR_TRACE, "SLCA: SAI index: 0x%x\n",
			      s_entry->my_index);
			prlog(PR_TRACE, "SLCA: SAI location code: %s\n",
			      s_entry->loc_code);
			return s_entry;
		}
	}

	return NULL;
}

/*
 * SLCA structure contains System Attention Indicator location
 * code (FRU ID = SA). Add this information to device tree
 * (under '/ibm,opal/led').
 */
void slca_dt_add_sai_node(void)
{
	const struct slca_entry *s_entry;
	struct dt_node *led_node, *sai_node;

	s_entry = slca_get_sai_entry();
	if (!s_entry)
		return;

	/* Create /ibm,opal node, if its not created already */
	if (!opal_node)
		return;

	/* Crete LED parent node */
	led_node = dt_find_by_path(opal_node, DT_PROPERTY_LED_NODE);
	if (!led_node)
		return;

	if (s_entry->loc_code_len == 0 ||
	    s_entry->loc_code_len > LOC_CODE_SIZE)
		return;

	/* Create SAI node */
	sai_node = dt_new(led_node, s_entry->loc_code);
	assert(sai_node);

	dt_add_property_string(sai_node,
			       DT_PROPERTY_LED_TYPES, LED_TYPE_ATTENTION);
}
