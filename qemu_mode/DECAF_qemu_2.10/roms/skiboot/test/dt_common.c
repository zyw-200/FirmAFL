/* Copyright 2015 IBM Corp.
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
#include <stdlib.h>

#include "../include/device.h"

/* dump_dt() is used in hdata/test/hdata_to_dt.c and core/test/run-device.c
 * this file is directly #included in both
 */

static void indent_num(unsigned indent)
{
	unsigned int i;

	for (i = 0; i < indent; i++)
		putc(' ', stdout);
}

static void dump_val(unsigned indent, const void *prop, size_t size)
{
	size_t i;
	int width = 78 - indent;

	for (i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)prop)[i]);
		width -= 2;
		if(width < 2) {
			printf("\n");
			indent_num(indent);
			width = 80 - indent;
		}
	}
}

static void dump_dt(const struct dt_node *root, unsigned indent, bool show_props)
{
	const struct dt_node *i;
	const struct dt_property *p;

	indent_num(indent);
	printf("node: %s\n", root->name);

	if (show_props) {
		list_for_each(&root->properties, p, list) {
			indent_num(indent);
			printf("prop: %s size: %zu val: ", p->name, p->len);
			dump_val(indent, p->prop, p->len);
			printf("\n");
		}
	}

	list_for_each(&root->children, i, list)
		dump_dt(i, indent + 2, show_props);
}

