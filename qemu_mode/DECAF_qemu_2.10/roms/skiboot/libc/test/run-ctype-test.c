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

#include "../ctype/isdigit.c"
#include "../ctype/isprint.c"
#include "../ctype/isspace.c"
#include "../ctype/isxdigit.c"
#include "../ctype/tolower.c"
#include "../ctype/toupper.c"

int skiboot_isdigit(int ch);
int skiboot_isprint(int ch);
int skiboot_isspace(int ch);
int skiboot_isxdigit(int ch);
int skiboot_tolower(int ch);
int skiboot_toupper(int ch);

int skiboot_isdigit(int ch)
{
	return isdigit(ch);
}

int skiboot_isprint(int ch)
{
	return isprint(ch);
}

int skiboot_isspace(int ch)
{
	return isspace(ch);
}

int skiboot_isxdigit(int ch)
{
	return isxdigit(ch);
}

int skiboot_tolower(int ch)
{
	return tolower(ch);
}

int skiboot_toupper(int ch)
{
	return toupper(ch);
}
