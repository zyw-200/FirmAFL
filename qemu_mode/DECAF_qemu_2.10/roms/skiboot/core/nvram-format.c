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
#include <nvram-format.h>

/*
 * NVRAM Format as specified in PAPR
 */

struct chrp_nvram_hdr {
	uint8_t		sig;
	uint8_t		cksum;
	uint16_t	len;
	char		name[12];
};

#define NVRAM_SIG_FW_PRIV	0x51
#define NVRAM_SIG_SYSTEM	0x70
#define NVRAM_SIG_FREE		0x7f

#define NVRAM_NAME_COMMON	"common"
#define NVRAM_NAME_FW_PRIV	"ibm,skiboot"
#define NVRAM_NAME_FREE		"wwwwwwwwwwww"

/* 64k should be enough, famous last words... */
#define NVRAM_SIZE_COMMON	0x10000

/* 4k should be enough, famous last words... */
#define NVRAM_SIZE_FW_PRIV	0x1000

static uint8_t chrp_nv_cksum(struct chrp_nvram_hdr *hdr)
{
	struct chrp_nvram_hdr h_copy = *hdr;
	uint8_t b_data, i_sum, c_sum;
	uint8_t *p = (uint8_t *)&h_copy;
	unsigned int nbytes = sizeof(h_copy);

	h_copy.cksum = 0;
	for (c_sum = 0; nbytes; nbytes--) {
		b_data = *(p++);
		i_sum = c_sum + b_data;
		if (i_sum < c_sum)
			i_sum++;
		c_sum = i_sum;
	}
	return c_sum;
}

int nvram_format(void *nvram_image, uint32_t nvram_size)
{
	struct chrp_nvram_hdr *h;
	unsigned int offset = 0;

	prerror("NVRAM: Re-initializing (size: 0x%08x)\n", nvram_size);
	memset(nvram_image, 0, nvram_size);

	/* Create private partition */
	if (nvram_size - offset < NVRAM_SIZE_FW_PRIV)
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FW_PRIV;
	h->len = NVRAM_SIZE_FW_PRIV >> 4;
	strcpy(h->name, NVRAM_NAME_FW_PRIV);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x for size 0x%08x"
			" with cksum 0x%02x\n", NVRAM_NAME_FW_PRIV, offset, h->len, h->cksum);
	offset += NVRAM_SIZE_FW_PRIV;

	/* Create common partition */
	if (nvram_size - offset < NVRAM_SIZE_COMMON)
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_SYSTEM;
	h->len = NVRAM_SIZE_COMMON >> 4;
	strcpy(h->name, NVRAM_NAME_COMMON);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x for size 0x%08x"
			" with cksum 0x%02x\n", NVRAM_NAME_COMMON, offset, h->len, h->cksum);
	offset += NVRAM_SIZE_COMMON;

	/* Create free space partition */
	if (nvram_size - offset < sizeof(struct chrp_nvram_hdr))
		return -1;
	h = nvram_image + offset;
	h->sig = NVRAM_SIG_FREE;
	h->len = (nvram_size - offset) >> 4;
	/* We have the full 12 bytes here */
	memcpy(h->name, NVRAM_NAME_FREE, 12);
	h->cksum = chrp_nv_cksum(h);
	prlog(PR_DEBUG, "NVRAM: Created '%s' partition at 0x%08x for size 0x%08x"
			" with cksum 0x%02x\n", NVRAM_NAME_FREE, offset, h->len, h->cksum);
	return 0;
}

/*
 * Check that the nvram partition layout is sane and that it
 * contains our required partitions. If not, we re-format the
 * lot of it
 */
int nvram_check(void *nvram_image, const uint32_t nvram_size)
{
	unsigned int offset = 0;
	bool found_common = false;
	bool found_skiboot = false;

	while (offset + sizeof(struct chrp_nvram_hdr) < nvram_size) {
		struct chrp_nvram_hdr *h = nvram_image + offset;

		if (chrp_nv_cksum(h) != h->cksum) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has bad checksum: 0x%02x vs 0x%02x\n",
				offset, h->cksum, chrp_nv_cksum(h));
			goto failed;
		}
		if (h->len < 1) {
			prerror("NVRAM: Partition at offset 0x%x"
				" has incorrect 0 length\n", offset);
			goto failed;
		}

		if (h->sig == NVRAM_SIG_SYSTEM &&
		    strcmp(h->name, NVRAM_NAME_COMMON) == 0)
			found_common = true;

		if (h->sig == NVRAM_SIG_FW_PRIV &&
		    strcmp(h->name, NVRAM_NAME_FW_PRIV) == 0)
			found_skiboot = true;

		offset += h->len << 4;
		if (offset > nvram_size) {
			prerror("NVRAM: Partition at offset 0x%x"
				" extends beyond end of nvram !\n", offset);
			goto failed;
		}
	}
	if (!found_common) {
		prerror("NVRAM: Common partition not found !\n");
		goto failed;
	}
	if (!found_skiboot) {
		prerror("NVRAM: Skiboot private partition "
			"not found !\n");
		goto failed;
	}

	prlog(PR_INFO, "NVRAM: Layout appears sane\n");
	return 0;
 failed:
	return -1;
}
