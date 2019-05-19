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

#ifndef __RTC_H
#define __RTC_H

#include <time-utils.h>

/*
 * Update the cache to the current time as specified by tm.
 */
void rtc_cache_update(struct tm *tm);

/*
 * Get the current time based on the cache. If the cache is valid the result
 * is returned in tm and the function returns 0. Otherwise returns -1.
 */
int rtc_cache_get(struct tm *tm);

/*
 * Same as the previous function except the result is returned as an OPAL
 * datetime.
 */
int rtc_cache_get_datetime(uint32_t *year_month_day,
			   uint64_t *hour_minute_second_millisecond);

#endif
