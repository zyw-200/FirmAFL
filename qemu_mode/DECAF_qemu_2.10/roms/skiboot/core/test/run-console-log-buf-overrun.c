/* Copyright 2014-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
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
#include <compiler.h>

#define __TEST__

#define CHECK_BUF_ASSERT(buf, str)			\
	assert(memcmp(buf, str, strlen(str)) == 0)

#define CHECK_ASSERT(str)				\
	CHECK_BUF_ASSERT(console_buffer, str)

int huge_tb;

static inline unsigned long mftb(void)
{
	/*
	 * return huge value for TB that overrun tmp[16] buffer defined
	 * in print_itoa().
	 */
	if (huge_tb)
		return 1223372515963611388;
	else
		return 42;
}

#include "../../libc/include/stdio.h"
#include "../console-log.c"
#include "../../libc/stdio/snprintf.c"
#include "../../libc/stdio/vsnprintf.c"

char console_buffer[4096];
struct debug_descriptor debug_descriptor;

bool flushed_to_drivers;

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count)
{
	flushed_to_drivers = flush_to_drivers;
	memcpy(console_buffer, buf, count);
	return count;
}

int main(void)
{
	unsigned long value = 0xffffffffffffffff;
	char *ptr = console_buffer;

	debug_descriptor.console_log_levels = 0x75;

	/* Test for huge TB value. */
	huge_tb = 1;

	prlog(PR_EMERG, "Hello World");
	CHECK_ASSERT("[1223372515963611388,0] Hello World");

	memset(console_buffer, 0, sizeof(console_buffer));

	/* Test for normal TB with huge unsigned long value */
	huge_tb = 0;

	prlog(PR_EMERG, "Hello World %lu", value);
	CHECK_ASSERT("[42,0] Hello World 18446744073709551615");

	printf("Hello World %lu", value);
	CHECK_ASSERT("[42,5] Hello World 18446744073709551615");

	/*
	 * Test string of size > 320
	 *
	 * core/console-log.c:vprlog() uses buffer[320] to print message
	 * Try printing more than 320 bytes to test stack corruption.
	 * You would see Segmentation fault on stack corruption.
	 */
	prlog(PR_EMERG, "%330s", "Hello World");

	memset(console_buffer, 0, sizeof(console_buffer));

	/*
	 * Test boundary condition.
	 *
	 * Print string of exact size 320. We should see string truncated
	 * with console_buffer[319] == '\0'.
	 */
	memset(console_buffer, 0, sizeof(console_buffer));

	prlog(PR_EMERG, "%313s", "Hello World");
	assert(console_buffer[319] == 0);

	/* compare truncated string */
	ptr += 320 - strlen("Hello World");
	CHECK_BUF_ASSERT(ptr, "Hello Worl");

	return 0;
}
