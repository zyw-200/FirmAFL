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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <linux/limits.h>

#include <libflash/libffs.h>
#include <pnor.h>

extern void dump_parts(struct ffs_handle *ffs);

void pr_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, char **argv)
{
	struct pnor pnor;
	int rc;

	if (argc != 2) {
		printf("usage: %s [pnor file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	pnor.path = strndup(argv[1], PATH_MAX);

	rc = pnor_init(&pnor);
	assert(rc);

	dump_parts(pnor.ffsh);

	pnor_close(&pnor);

	return 0;
}
