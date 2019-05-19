/* Copyright 2014-2016 IBM Corp.
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
 * imitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "xscom.h"

static void print_usage(int code)
{
	printf("usage: getscom [-c|--chip chip-id] addr\n");
	printf("       getscom -l|--list-chips\n");
	printf("       getscom -v|--version\n");
	exit(code);
}

static void print_chip_info(uint32_t chip_id)
{
	uint64_t f000f, cfam_id;
	const char *name;
	char uname_buf[64];
	int rc;

	rc = xscom_read(chip_id, 0xf000f, &f000f);
	if (rc)
		return;

	cfam_id = f000f >> 44;

	switch(cfam_id & 0xff) {
	case 0xf9:
		name = "P7 processor";
		break;
	case 0xe8:
		name = "P7+ processor";
		break;
	case 0xef:
		name = "P8E (Murano) processor";
		break;
	case 0xea:
		name = "P8 (Venice) processor";
		break;
	case 0xd3:
		name = "P8NVL (Naples) processor";
		break;
	case 0xe9:
		name = "Centaur memory buffer";
		break;
	default:
		snprintf(uname_buf, sizeof(uname_buf), "Unknown ID 0x%02lx",
			 cfam_id & 0xff);
		name = uname_buf;
	}

	printf("%08x | DD%lx.%lx | %s\n",
	       chip_id, (cfam_id >> 16) & 0xf, (cfam_id >> 8) & 0xf, name);
	
}

extern const char version[];

int main(int argc, char *argv[])
{
	uint64_t val, addr = -1ull;
	uint32_t def_chip, chip_id = 0xffffffff;
	bool list_chips = false;
	bool no_work = false;
	int rc;

	while(1) {
		static struct option long_opts[] = {
			{"chip",	required_argument,	NULL,	'c'},
			{"list-chips",	no_argument,		NULL,	'l'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "-c:hlv", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 1:
			addr = strtoull(optarg, NULL, 16);
			break;
		case 'c':
			chip_id = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			print_usage(0);
			break;
		case 'l':
			list_chips = true;
			break;
		case 'v':
			printf("xscom utils version %s\n", version);
			exit(0);
		default:
			exit(1);
		}
	}
	
	if (addr == -1ull)
		no_work = true;
	if (no_work && !list_chips) {
		fprintf(stderr, "Invalid or missing address\n");
		print_usage(1);
	}

	def_chip = xscom_init();
	if (def_chip == 0xffffffff) {
		fprintf(stderr, "No valid XSCOM chip found\n");
		exit(1);
	}
	if (list_chips) {
		printf("Chip ID  | Rev   | Chip type\n");
		printf("---------|-------|--------\n");
		xscom_for_each_chip(print_chip_info);
	}
	if (no_work)
		return 0;
	if (chip_id == 0xffffffff)
		chip_id = def_chip;

	rc = xscom_read(chip_id, addr, &val);
	if (rc) {
		fprintf(stderr,"Error %d reading XSCOM\n", rc);
		exit(1);
	}
	printf("%016" PRIx64 "\n", val);
	return 0;
}

