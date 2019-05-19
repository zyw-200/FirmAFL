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

/*
 * Console Log routines
 * Wraps libc and console lower level functions
 * does fancy-schmancy things like timestamps and priorities
 * Doesn't make waffles.
 */

#include "skiboot.h"
#include "unistd.h"
#include "stdio.h"
#include "console.h"
#include "timebase.h"

static int vprlog(int log_level, const char *fmt, va_list ap)
{
	int count;
	char buffer[320];
	bool flush_to_drivers = true;

	/* It's safe to return 0 when we "did" something here
	 * as only printf cares about how much we wrote, and
	 * if you change log_level to below PR_PRINTF then you
	 * get everything you deserve.
	 * By default, only PR_DEBUG and higher are stored in memory.
	 * PR_TRACE and PR_INSANE are for those having a bad day.
	 */
	if (log_level > (debug_descriptor.console_log_levels >> 4))
		return 0;

	count = snprintf(buffer, sizeof(buffer), "[%lu,%d] ",
			 mftb(), log_level);
	count+= vsnprintf(buffer+count, sizeof(buffer)-count, fmt, ap);

	if (log_level > (debug_descriptor.console_log_levels & 0x0f))
		flush_to_drivers = false;

	console_write(flush_to_drivers, buffer, count);

	return count;
}

/* we don't return anything as what on earth are we going to do
 * if we actually fail to print a log message? Print a log message about it?
 * Callers shouldn't care, prlog and friends should do something generically
 * sane in such crazy situations.
 */
void _prlog(int log_level, const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprlog(log_level, fmt, ap);
	va_end(ap);
}

int _printf(const char* fmt, ...)
{
	int count;
	va_list ap;

	va_start(ap, fmt);
	count = vprlog(PR_PRINTF, fmt, ap);
	va_end(ap);

	return count;
}
