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

#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <device.h>

static const struct machine_info machine_table[] = {
	{"8247-21L", "IBM Power System S812L"},
	{"8247-22L", "IBM Power System S822L"},
	{"8247-24L", "IBM Power System S824L"},
	{"8286-41A", "IBM Power System S814"},
	{"8286-22A", "IBM Power System S822"},
	{"8286-42A", "IBM Power System S824"},
};

const struct machine_info *machine_info_lookup(char *mtm)
{
	int i;
	for(i = 0; i < ARRAY_SIZE(machine_table); i++)
		if (!strcmp(machine_table[i].mtm, mtm))
			return &machine_table[i];
	return NULL;
}
