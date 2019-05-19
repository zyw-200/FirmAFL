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

#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <fsp.h>
#include <device.h>

#define CHECK_SPACE(_p, _n, _e) (((_e) - (_p)) >= (_n))

/* Low level keyword search in a record. Can be used when we
 * need to find the next keyword of a given type, for example
 * when having multiple MF/SM keyword pairs
 */
const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size)
{
	const uint8_t *p = rec, *end = rec + rec_sz;

	while (CHECK_SPACE(p, 3, end)) {
		uint8_t k1 = *(p++);
		uint8_t k2 = *(p++);
		uint8_t sz = *(p++);

		if (k1 == kw[0] && k2 == kw[1]) {
			if (kw_size)
				*kw_size = sz;
			return p;
		}
		p += sz;
	}
	return NULL;
}

/* Locate  a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
const void *vpd_find_record(const void *vpd, size_t vpd_size,
			    const char *record, size_t *sz)
{
	const uint8_t *p = vpd, *end = vpd + vpd_size;
	bool first_start = true;
	size_t rec_sz;
	uint8_t namesz = 0;
	const char *rec_name;

	while (CHECK_SPACE(p, 4, end)) {
		/* Get header byte */
		if (*(p++) != 0x84) {
			/* Skip initial crap in VPD LIDs */
			if (first_start)
				continue;
			break;
		}
		first_start = false;
		rec_sz = *(p++);
		rec_sz |= *(p++) << 8;
		if (!CHECK_SPACE(p, rec_sz, end)) {
			prerror("VPD: Malformed or truncated VPD,"
				" record size doesn't fit\n");
			return NULL;
		}

		/* Find record name */
		rec_name = vpd_find_keyword(p, rec_sz, "RT", &namesz);
		if (rec_name && strncmp(record, rec_name, namesz) == 0) {
			*sz = rec_sz;
			return p;
		}

		p += rec_sz;
		if (*(p++) != 0x78) {
			prerror("VPD: Malformed or truncated VPD,"
				" missing final 0x78 in record %.4s\n",
				rec_name ? rec_name : "????");
			return NULL;
		}
	}
	return NULL;
}

/* Locate a keyword in a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz)
{
	size_t rec_sz;
	const uint8_t *p;

	p = vpd_find_record(vpd, vpd_size, record, &rec_sz);
	if (p)
		p = vpd_find_keyword(p, rec_sz, keyword, sz);
	return p;
}

static void *vpd;
static size_t vpd_size;
static uint32_t vpd_lid_no;

/* Helper to load a VPD LID. Pass a ptr to the corresponding LX keyword */
static void *vpd_lid_preload(const uint8_t *lx)
{
	int rc;

	/* Now this is a guess game as we don't have the info from the
	 * pHyp folks. But basically, it seems to boil down to loading
	 * a LID whose name is 0x80e000yy where yy is the last 2 digits
	 * of the LX record in hex.
	 *
	 * [ Correction: After a chat with some folks, it looks like it's
	 * actually 4 digits, though the lid number is limited to fff
	 * so we weren't far off. ]
	 *
	 * For safety, we look for a matching LX record in an LXRn
	 * (n = lxrn argument) or in VINI if lxrn=0xff
	 */
	vpd_lid_no = 0x80e00000 | ((lx[6] & 0xf) << 8) | lx[7];

	/* We don't quite know how to get to the LID directory so
	 * we don't know the size. Let's allocate 16K. All the VPD LIDs
	 * I've seen so far are much smaller.
	 */
#define VPD_LID_MAX_SIZE	0x4000
	vpd = malloc(VPD_LID_MAX_SIZE);

	if (!vpd) {
		prerror("VPD: Failed to allocate memory for LID\n");
		return NULL;
	}

	/* Adjust LID number for flash side */
	vpd_lid_no = fsp_adjust_lid_side(vpd_lid_no);
	printf("VPD: Trying to load VPD LID 0x%08x...\n", vpd_lid_no);

	vpd_size = VPD_LID_MAX_SIZE;

	/* Load it from the FSP */
	rc = fsp_preload_lid(vpd_lid_no, vpd, &vpd_size);
	if (rc) {
		prerror("VPD: Error %d loading VPD LID\n", rc);
		goto fail;
	}

	return vpd;
 fail:
	free(vpd);
	return NULL;
}

void vpd_iohub_load(struct dt_node *hub_node)
{
	char record[4] = "LXR0";
	const void *valid_lx;
	uint8_t lx_size;
	int r;
	const uint32_t *p;
	const uint8_t *lx;
	unsigned int lxrn;

	p = dt_prop_get_def(hub_node, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lxrn = p[0];
        lx = (const char *)&p[1];

	assert(vpd);
	assert(vpd_lid_no);

	r = fsp_wait_lid_loaded(vpd_lid_no);

	if (r)
		goto fail;

	/* Validate it */
	if (lxrn < 9)
		record[3] = '0' + lxrn;
	else
		memcpy(record, "VINI", 4);

	valid_lx = vpd_find(vpd, vpd_size, record, "LX", &lx_size);
	if (!valid_lx || lx_size != 8) {
		prerror("VPD: Cannot find validation LX record\n");
		goto fail;
	}
	if (memcmp(valid_lx, lx, 8) != 0) {
		prerror("VPD: LX record mismatch !\n");
		goto fail;
	}

	printf("VPD: Loaded %zu bytes\n", vpd_size);

	/* Got it ! */
	vpd = realloc(vpd, vpd_size);

	if (!vpd)
		goto fail;

	dt_add_property(hub_node, "ibm,io-vpd", vpd, vpd_size);
	free(vpd);
	return;

fail:
	free(vpd);
	vpd = NULL;
	prerror("VPD: Failed to load VPD LID\n");
	return;
}

void vpd_preload(struct dt_node *hub_node)
{
	const uint32_t *p;
	const char *lxr;

	p = dt_prop_get_def(hub_node, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lxr = (const char *)&p[1];

	vpd = vpd_lid_preload(lxr);
}
