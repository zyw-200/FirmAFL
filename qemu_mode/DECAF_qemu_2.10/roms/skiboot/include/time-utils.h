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

#ifndef __TIME_UTILS_H
#define __TIME_UTILS_H

#include <stdint.h>
#include <time.h>

/* BCD conversion utilities. MSB is byte 3, LSB is byte 0 */

static inline unsigned int bcd_byte(uint32_t bcd, int byteno)
{
	bcd >>= byteno * 8;
	return (bcd >> 4 & 0xf) * 10 + (bcd & 0xf);
}

static inline uint32_t int_to_bcd2(unsigned int x)
{
	return (((x / 10) << 4) & 0xf0) | (x % 10);
}

static inline uint32_t int_to_bcd4(unsigned int x)
{
	return int_to_bcd2(x / 100) << 8 | int_to_bcd2(x % 100);
}

void tm_to_datetime(struct tm *tm, uint32_t *y_m_d, uint64_t *h_m_s_m);
void datetime_to_tm(uint32_t y_m_d, uint64_t h_m_s_m, struct tm *tm);

#endif
