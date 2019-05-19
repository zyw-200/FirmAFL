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

#include "hdif.h"

const void *HDIF_get_idata(const struct HDIF_common_hdr *hdif, unsigned int di,
			   unsigned int *size)
{
	const struct HDIF_common_hdr *hdr = hdif;
	const struct HDIF_idata_ptr *iptr;

	if (be16_to_cpu(hdr->d1f0) != 0xd1f0) {
		prerror("HDIF: Bad header format !\n");
		return NULL;
	}

	if (di >= be16_to_cpu(hdr->idptr_count)) {
		prerror("HDIF: idata index out of range !\n");
		return NULL;
	}

	iptr = (void *)hdif + be32_to_cpu(hdr->idptr_off)
		+ di * sizeof(struct HDIF_idata_ptr);

	if (size)
		*size = be32_to_cpu(iptr->size);

	return (void *)hdif + be32_to_cpu(iptr->offset);
}

const void *HDIF_get_iarray_item(const struct HDIF_common_hdr *hdif,
				 unsigned int di, unsigned int ai,
				 unsigned int *size)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return NULL;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		return NULL;
	}

	ahdr = arr;

	if (ai >= be32_to_cpu(ahdr->ecnt)) {
		prerror("HDIF: idata array index out of range !\n");
		return NULL;
	}

	if (size)
		*size = be32_to_cpu(ahdr->eactsz);

	return arr + be32_to_cpu(ahdr->offset) + ai * be32_to_cpu(ahdr->esize);
}

int HDIF_get_iarray_size(const struct HDIF_common_hdr *hdif, unsigned int di)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return -1;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		return -1;
	}

	ahdr = arr;
	return be32_to_cpu(ahdr->ecnt);
}

struct HDIF_child_ptr *
HDIF_child_arr(const struct HDIF_common_hdr *hdif, unsigned int idx)
{
	struct HDIF_child_ptr *children;

	children = (void *)hdif + be32_to_cpu(hdif->child_off);

	if (idx >= be16_to_cpu(hdif->child_count)) {
		prerror("HDIF: child array idx out of range!\n");
		return NULL;
	}

	return &children[idx];
}

struct HDIF_common_hdr *HDIF_child(const struct HDIF_common_hdr *hdif,
				   const struct HDIF_child_ptr *child,
				   unsigned int idx,
				   const char *eyecatcher)
{
	void *base = (void *)hdif;
	struct HDIF_common_hdr *ret;
	long child_off;

	/* child must be in hdif's child array */
	child_off = (void *)child - (base + be32_to_cpu(hdif->child_off));
	assert(child_off % sizeof(struct HDIF_child_ptr) == 0);
	assert(child_off / sizeof(struct HDIF_child_ptr)
	       < be16_to_cpu(hdif->child_count));

	assert(idx < be32_to_cpu(child->count));

	if (be32_to_cpu(child->size) < sizeof(struct HDIF_common_hdr)) {
		prerror("HDIF: %s child #%i too small: %u\n",
			eyecatcher, idx, be32_to_cpu(child->size));
		return NULL;
	}

	ret = base + be32_to_cpu(child->offset)
		+ be32_to_cpu(child->size) * idx;
	if (!HDIF_check(ret, eyecatcher)) {
		prerror("HDIF: %s child #%i bad type\n",
			eyecatcher, idx);
		return NULL;
	}

	return ret;
}
