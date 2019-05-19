/* Copyright 2013-2015 IBM Corp.
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#define __TEST__

#include "../time-utils.c"

int main(void)
{
	struct tm *t = malloc(sizeof(struct tm));
	uint32_t *ymd = malloc(sizeof(uint32_t));
	uint64_t *hms = malloc(sizeof(uint64_t));

	t->tm_year = 1982;
	t->tm_mon = 0;
	t->tm_mday = 29;
	t->tm_hour = 7;
	t->tm_min = 42;
	t->tm_sec = 24;

	tm_to_datetime(t, ymd, hms);

	assert(*ymd == 0x19820129);
	assert(*hms == 0x742240000000000ULL);

	memset(t, 0, sizeof(struct tm));

	*ymd = 0x19760412;

	datetime_to_tm(*ymd, *hms, t);
	assert(t->tm_year == 1976);
	assert(t->tm_mon == 03);
	assert(t->tm_mday == 12);
	assert(t->tm_hour == 7);
	assert(t->tm_min == 42);
	assert(t->tm_sec == 24);

	return 0;
}

