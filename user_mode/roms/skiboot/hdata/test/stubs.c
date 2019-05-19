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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...) __attribute__((format (printf, 2, 3)));

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        if (log_level < 7)
		vprintf(fmt, ap);
        va_end(ap);
}

/* Add any stub functions required for linking here. */
static void stub_function(void)
{
	abort();
}

#define STUB(fnname) \
	void fnname(void) __attribute__((weak, alias ("stub_function")))

STUB(op_display);
STUB(fsp_preload_lid);
STUB(fsp_wait_lid_loaded);
STUB(fsp_adjust_lid_side);
