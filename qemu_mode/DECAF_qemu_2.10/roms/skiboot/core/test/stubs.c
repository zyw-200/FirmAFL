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

STUB(fdt_begin_node);
STUB(fdt_property);
STUB(fdt_end_node);
STUB(fdt_create);
STUB(fdt_add_reservemap_entry);
STUB(fdt_finish_reservemap);
STUB(fdt_strerror);
STUB(fdt_check_header);
STUB(_fdt_check_node_offset);
STUB(fdt_next_tag);
STUB(fdt_string);
STUB(fdt_get_name);
STUB(dt_first);
STUB(dt_next);
STUB(dt_has_node_property);
STUB(dt_get_address);
STUB(add_chip_dev_associativity);
