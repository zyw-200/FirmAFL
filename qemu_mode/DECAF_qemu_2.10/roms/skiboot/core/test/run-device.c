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
#include <stdlib.h>

/* Override this for testing. */
#define is_rodata(p) fake_is_rodata(p)

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

static inline bool fake_is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

#define zalloc(bytes) calloc((bytes), 1)

#include "../device.c"
#include "../../ccan/list/list.c" /* For list_check */
#include <assert.h>
#include "../../test/dt_common.c"

static void check_path(const struct dt_node *node, const char * expected_path)
{
	char * path;
	path = dt_get_path(node);
	if (strcmp(path, expected_path) != 0) {
		printf("check_path: expected %s, got %s\n", expected_path, path);
	}
	assert(strcmp(path, expected_path) == 0);
	free(path);
}

/* constructs a random nodes only device tree */
static void build_tree(int max_depth, int min_depth, struct dt_node *parent)
{
	char name[64];
	int i;

	for (i = 0; i < max_depth; i++) {
		struct dt_node *new;

		snprintf(name, sizeof name, "prefix@%.8x", rand());

		new = dt_new(parent, name);

		if(max_depth > min_depth)
			build_tree(max_depth - 1, min_depth, new);
	}
}

static bool is_sorted(const struct dt_node *root)
{
	struct dt_node *end = list_tail(&root->children, struct dt_node, list);
	struct dt_node *node;

	dt_for_each_child(root, node) {
		struct dt_node *next =
			list_entry(node->list.next, struct dt_node, list);

		/* current node must be "less than" the next node */
		if (node != end && dt_cmp_subnodes(node, next) != -1) {
			printf("nodes '%s' and '%s' out of order\n",
				node->name, next->name);

			return false;
		}

		if (!is_sorted(node))
			return false;
	}

	return true;
}


int main(void)
{
	struct dt_node *root, *c1, *c2, *gc1, *gc2, *gc3, *ggc1;
	struct dt_node *addrs, *addr1, *addr2;
	struct dt_node *i;
	const struct dt_property *p;
	struct dt_property *p2;
	unsigned int n;
	char *s;
	size_t sz;
	u32 phandle;

	root = dt_new_root("");
	assert(!list_top(&root->properties, struct dt_property, list));
	check_path(root, "/");

	c1 = dt_new(root, "c1");
	assert(!list_top(&c1->properties, struct dt_property, list));
	check_path(c1, "/c1");
	assert(dt_find_by_name(root, "c1") == c1);
	assert(dt_find_by_path(root, "/c1") == c1);

	c2 = dt_new(root, "c2");
	assert(!list_top(&c2->properties, struct dt_property, list));
	check_path(c2, "/c2");
	assert(dt_find_by_name(root, "c2") == c2);
	assert(dt_find_by_path(root, "/c2") == c2);

	gc1 = dt_new(c1, "gc1");
	assert(!list_top(&gc1->properties, struct dt_property, list));
	check_path(gc1, "/c1/gc1");
	assert(dt_find_by_name(root, "gc1") == gc1);
	assert(dt_find_by_path(root, "/c1/gc1") == gc1);

	gc2 = dt_new(c1, "gc2");
	assert(!list_top(&gc2->properties, struct dt_property, list));
	check_path(gc2, "/c1/gc2");
	assert(dt_find_by_name(root, "gc2") == gc2);
	assert(dt_find_by_path(root, "/c1/gc2") == gc2);

	gc3 = dt_new(c1, "gc3");
	assert(!list_top(&gc3->properties, struct dt_property, list));
	check_path(gc3, "/c1/gc3");
	assert(dt_find_by_name(root, "gc3") == gc3);
	assert(dt_find_by_path(root, "/c1/gc3") == gc3);

	ggc1 = dt_new(gc1, "ggc1");
	assert(!list_top(&ggc1->properties, struct dt_property, list));
	check_path(ggc1, "/c1/gc1/ggc1");
	assert(dt_find_by_name(root, "ggc1") == ggc1);
	assert(dt_find_by_path(root, "/c1/gc1/ggc1") == ggc1);

	addrs = dt_new(root, "addrs");
	assert(!list_top(&addrs->properties, struct dt_property, list));
	check_path(addrs, "/addrs");
	assert(dt_find_by_name(root, "addrs") == addrs);
	assert(dt_find_by_path(root, "/addrs") == addrs);

	addr1 = dt_new_addr(addrs, "addr", 0x1337);
	assert(!list_top(&addr1->properties, struct dt_property, list));
	check_path(addr1, "/addrs/addr@1337");
	assert(dt_find_by_name(root, "addr@1337") == addr1);
	assert(dt_find_by_path(root, "/addrs/addr@1337") == addr1);

	addr2 = dt_new_2addr(addrs, "2addr", 0xdead, 0xbeef);
	assert(!list_top(&addr2->properties, struct dt_property, list));
	check_path(addr2, "/addrs/2addr@dead,beef");
	assert(dt_find_by_name(root, "2addr@dead,beef") == addr2);
	assert(dt_find_by_path(root, "/addrs/2addr@dead,beef") == addr2);

	/* Test walking the tree, checking and setting values */
	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		assert(!list_top(&i->properties, struct dt_property, list));
		dt_add_property_cells(i, "visited", 1);
	}
	assert(n == 9);

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		p = list_top(&i->properties, struct dt_property, list);
		assert(strcmp(p->name, "visited") == 0);
		assert(p->len == sizeof(u32));
		assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	}
	assert(n == 9);

	/* Test cells */
	dt_add_property_cells(c1, "some-property", 1, 2, 3);
	p = dt_find_property(c1, "some-property");
	assert(p);
	assert(strcmp(p->name, "some-property") == 0);
	assert(p->len == sizeof(u32) * 3);
	assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	assert(dt_prop_get_cell(c1, "some-property", 0) == 1);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 1)) == 2);
	assert(dt_prop_get_cell(c1, "some-property", 1) == 2);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 2)) == 3);
	assert(dt_prop_get_cell_def(c1, "some-property", 2, 42) == 3);

	assert(dt_prop_get_cell_def(c1, "not-a-property", 2, 42) == 42);

	/* Test u64s */
	dt_add_property_u64s(c2, "some-property", (2LL << 33), (3LL << 33), (4LL << 33));
	p = dt_find_property(c2, "some-property");
	assert(p);
	assert(p->len == sizeof(u64) * 3);
	assert(fdt64_to_cpu(*(u64 *)p->prop) == (2LL << 33));
	assert(fdt64_to_cpu(*((u64 *)p->prop + 1)) == (3LL << 33));
	assert(fdt64_to_cpu(*((u64 *)p->prop + 2)) == (4LL << 33));

	/* Test u32/u64 get defaults */
	assert(dt_prop_get_u32_def(c1, "u32", 42) == 42);
	dt_add_property_cells(c1, "u32", 1337);
	assert(dt_prop_get_u32_def(c1, "u32", 42) == 1337);
	assert(dt_prop_get_u32(c1, "u32") == 1337);

	assert(dt_prop_get_u64_def(c1, "u64", (42LL << 42)) == (42LL << 42));
	dt_add_property_u64s(c1, "u64", (1337LL << 42));
	assert(dt_prop_get_u64_def(c1, "u64", (42LL << 42)) == (1337LL << 42));
	assert(dt_prop_get_u64(c1, "u64") == (1337LL << 42));

	/* Test freeing a single node */
	assert(!list_empty(&gc1->children));
	dt_free(ggc1);
	assert(list_empty(&gc1->children));

	/* Test rodata logic. */
	assert(!is_rodata("hello"));
	assert(is_rodata(__rodata_start));
	strcpy(__rodata_start, "name");
	ggc1 = dt_new(root, __rodata_start);
	assert(ggc1->name == __rodata_start);

	/* Test string node. */
	dt_add_property_string(ggc1, "somestring", "someval");
	assert(dt_has_node_property(ggc1, "somestring", "someval"));
	assert(!dt_has_node_property(ggc1, "somestrin", "someval"));
	assert(!dt_has_node_property(ggc1, "somestring", "someva"));
	assert(!dt_has_node_property(ggc1, "somestring", "somevale"));

	/* Test nstr, which allows for non-null-terminated inputs */
	dt_add_property_nstr(ggc1, "nstring", "somevalue_long", 7);
	assert(dt_has_node_property(ggc1, "nstring", "someval"));
	assert(!dt_has_node_property(ggc1, "nstring", "someva"));
	assert(!dt_has_node_property(ggc1, "nstring", "somevalue_long"));

	/* Test multiple strings */
	dt_add_property_strings(ggc1, "somestrings",
				"These", "are", "strings!");
	p = dt_find_property(ggc1, "somestrings");
	assert(p);
	assert(p->len == sizeof(char) * (6 + 4 + 9));
	s = (char *)p->prop;
	assert(strcmp(s, "These") == 0);
	assert(strlen(s) == 5);
	s += 6;
	assert(strcmp(s, "are") == 0);
	assert(strlen(s) == 3);
	s += 4;
	assert(strcmp(s, "strings!") == 0);
	assert(strlen(s) == 8);
	s += 9;
	assert(s == (char *)p->prop + p->len);
	assert(dt_prop_find_string(p, "These"));
	/* dt_prop_find_string is case insensitve */
	assert(dt_prop_find_string(p, "ARE"));
	assert(!dt_prop_find_string(p, "integers!"));
	/* And always returns false for NULL properties */
	assert(!dt_prop_find_string(NULL, "anything!"));

	/* Test more get/get_def varieties */
	assert(dt_prop_get_def(c1, "does-not-exist", NULL) == NULL);
	sz = 0xbad;
	assert(dt_prop_get_def_size(c1, "does-not-exist", NULL, &sz) == NULL);
	assert(sz == 0);
	dt_add_property_string(c1, "another-property", "xyzzy");
	assert(dt_prop_get_def(c1, "another-property", NULL) != NULL);
	assert(strcmp(dt_prop_get(c1, "another-property"), "xyzzy") == 0);
	n = 0xbad;
	assert(dt_prop_get_def_size(c1, "another-property", NULL, &sz) != NULL);
	assert(sz == strlen("xyzzy") + 1);

	/* Test resizing property. */
	p = p2 = __dt_find_property(c1, "some-property");
	assert(p);
	n = p2->len;
	while (p2 == p) {
		n *= 2;
		dt_resize_property(&p2, n);
	}

	assert(dt_find_property(c1, "some-property") == p2);
	list_check(&c1->properties, "properties after resizing");

	dt_del_property(c1, p2);
	list_check(&c1->properties, "properties after delete");

	/* No leaks for valgrind! */
	dt_free(root);

	/* Test compatible and chip id. */
	root = dt_new_root("");

	c1 = dt_new(root, "chip1");
	dt_add_property_cells(c1, "ibm,chip-id", 0xcafe);
	assert(dt_get_chip_id(c1) == 0xcafe);
	dt_add_property_strings(c1, "compatible",
				"specific-fake-chip",
				"generic-fake-chip");
	assert(dt_node_is_compatible(c1, "specific-fake-chip"));
	assert(dt_node_is_compatible(c1, "generic-fake-chip"));

	c2 = dt_new(root, "chip2");
	dt_add_property_cells(c2, "ibm,chip-id", 0xbeef);
	assert(dt_get_chip_id(c2) == 0xbeef);
	dt_add_property_strings(c2, "compatible",
				"specific-fake-bus",
				"generic-fake-bus");

	gc1 = dt_new(c1, "coprocessor1");
	dt_add_property_strings(gc1, "compatible",
				"specific-fake-coprocessor");

	gc2 = dt_new(c1, "node-without-compatible");
	assert(__dt_find_property(gc2, "compatible") == NULL);
	assert(!dt_node_is_compatible(gc2, "any-property"));

	assert(dt_find_compatible_node(root, NULL, "generic-fake-bus") == c2);
	assert(dt_find_compatible_node(root, c2, "generic-fake-bus") == NULL);

	/* we can find the coprocessor once on the cpu */
	assert(dt_find_compatible_node_on_chip(root,
					       NULL,
					       "specific-fake-coprocessor",
					       0xcafe) == gc1);
	assert(dt_find_compatible_node_on_chip(root,
					       gc1,
					       "specific-fake-coprocessor",
					       0xcafe) == NULL);

	/* we can't find the coprocessor on the bus */
	assert(dt_find_compatible_node_on_chip(root,
					       NULL,
					       "specific-fake-coprocessor",
					       0xbeef) == NULL);

	/* Test phandles. We override the automatically generated one. */
	phandle = 0xf00;
	dt_add_property(gc2, "phandle", (const void *)&phandle, 4);
	assert(last_phandle == 0xf00);
	assert(dt_find_by_phandle(root, 0xf00) == gc2);
	assert(dt_find_by_phandle(root, 0xf0f) == NULL);

	dt_free(root);

	/* basic sorting */
	root = dt_new_root("rewt");
	dt_new(root, "a@1");
	dt_new(root, "a@2");
	dt_new(root, "a@3");
	dt_new(root, "a@4");
	dt_new(root, "b@4");
	dt_new(root, "c@4");

	assert(is_sorted(root));

	dt_free(root);

	/* Test child node sorting */
	root = dt_new_root("test root");
	build_tree(5, 3, root);

	if (!is_sorted(root)) {
		dump_dt(root, 1, false);
	}
	assert(is_sorted(root));

	dt_free(root);

	return 0;
}

