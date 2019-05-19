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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#define __TEST__

#define _printf printf

static inline unsigned long mftb(void)
{
	return 42;
}

int _printf(const char* fmt, ...);

#include "../console-log.c"

struct debug_descriptor debug_descriptor;

bool flushed_to_drivers;
char console_buffer[4096];

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count)
{
	flushed_to_drivers = flush_to_drivers;
	memcpy(console_buffer, buf, count);
	return count;
}

int main(void)
{
	debug_descriptor.console_log_levels = 0x75;

	prlog(PR_EMERG, "Hello World");
	assert(memcmp(console_buffer, "[42,0] Hello World", strlen("[42,0] Hello World")) == 0);
	assert(flushed_to_drivers==true);

	memset(console_buffer, 0, sizeof(console_buffer));

	// Below log level
	prlog(PR_TRACE, "Hello World");
	assert(console_buffer[0] == 0);

	// Should not be flushed to console
	prlog(PR_DEBUG, "Hello World");
	assert(memcmp(console_buffer, "[42,7] Hello World", strlen("[42,7] Hello World")) == 0);
	assert(flushed_to_drivers==false);

	printf("Hello World");
	assert(memcmp(console_buffer, "[42,5] Hello World", strlen("[42,5] Hello World")) == 0);
	assert(flushed_to_drivers==true);

	return 0;
}
