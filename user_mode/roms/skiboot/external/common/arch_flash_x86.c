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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <libflash/file.h>

#include "arch_flash.h"

int arch_flash_init(struct blocklevel_device **r_bl, const char *file, bool keep_alive)
{
	int rc;
	struct blocklevel_device *new_bl;

	/* Must have passed through a file to operate on */
	if (!file) {
		fprintf(stderr, "Cannot operate without a file\n");
		return -1;
	}

	rc = file_init_path(file, NULL, keep_alive, &new_bl);
	if (rc)
		return -1;

	*r_bl = new_bl;
	return 0;
}

void arch_flash_close(struct blocklevel_device *bl, const char *file)
{
	file_exit_close(bl);
}
