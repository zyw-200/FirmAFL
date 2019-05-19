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

/* This is based on the hostboot ecc code */

#ifndef __ECC_H
#define __ECC_H

#include <stdint.h>
#include <ccan/endian/endian.h>

struct ecc64 {
	beint64_t data;
	uint8_t ecc;
} __attribute__((__packed__));

extern int memcpy_from_ecc(uint64_t *dst, struct ecc64 *src, uint32_t len);

extern int memcpy_to_ecc(struct ecc64 *dst, const uint64_t *src, uint32_t len);

/*
 * Calculate the size of a buffer if ECC is added
 *
 * We add 1 byte of ecc for every 8 bytes of data.  So we need to round up to 8
 * bytes length and then add 1/8
 */
#ifndef ALIGN_UP
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#endif

#define BYTES_PER_ECC 8

static inline uint32_t ecc_size(uint32_t len)
{
	return ALIGN_UP(len, BYTES_PER_ECC) >> 3;
}

static inline uint32_t ecc_buffer_size(uint32_t len)
{
	return ALIGN_UP(len, BYTES_PER_ECC) + ecc_size(len);
}

static inline int ecc_buffer_size_check(uint32_t len)
{
	return len % (BYTES_PER_ECC + 1);
}

static inline uint32_t ecc_buffer_size_minus_ecc(uint32_t len)
{
	return len * BYTES_PER_ECC / (BYTES_PER_ECC + 1);
}

#endif
