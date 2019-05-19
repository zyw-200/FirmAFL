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

/*
 * This file is run with the skiboot libc files rather than system libc.
 * This means we have a bit of "fun" with actually executing the tests on
 * the host.
 * Patches to make this less ugly are very welcome.
 */

#include <config.h>
#include <stdarg.h>

#include "../stdio/snprintf.c"
#include "../stdio/vsnprintf.c"

int test1(void);

int test1(void)
{
	return snprintf(NULL, 1, "Hello");
}

int skiboot_snprintf(char *buf, size_t bufsz, size_t l, const char* format, ...);

int skiboot_snprintf(char *buf, size_t bufsz, size_t l, const char* format, ...)
{
	va_list ar;
	int count;

	if (buf)
		memset(buf, 0, bufsz);

	if ((buf==NULL) || (format==NULL))
		return(-1);

	va_start(ar, format);
	count = vsnprintf(buf, l, format, ar);
	va_end(ar);

	return(count);
}
