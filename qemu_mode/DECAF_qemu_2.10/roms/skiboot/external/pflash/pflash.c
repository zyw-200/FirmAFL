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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <byteswap.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <arpa/inet.h>
#include <assert.h>

#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <common/arch_flash.h>
#include "progress.h"

#define __aligned(x)			__attribute__((aligned(x)))

/* Full pflash version number (possibly includes gitid). */
extern const char version[];

static bool must_confirm = true;
static bool dummy_run;
static int need_relock;
static bool bmc_flash;
static uint32_t ffs_toc = 0;
static int flash_side = 0;

#define FILE_BUF_SIZE	0x10000
static uint8_t file_buf[FILE_BUF_SIZE] __aligned(0x1000);

static struct blocklevel_device *bl;
static struct ffs_handle	*ffsh;
static uint32_t			fl_total_size, fl_erase_granule;
static const char		*fl_name;
static int32_t			ffs_index = -1;

static void check_confirm(void)
{
	char yes[8], *p;

	if (!must_confirm)
		return;

	printf("WARNING ! This will modify your %s flash chip content !\n",
	       bmc_flash ? "BMC" : "HOST");
	printf("Enter \"yes\" to confirm:");
	memset(yes, 0, sizeof(yes));
	if (!fgets(yes, 7, stdin))
		exit(1);
	p = strchr(yes, 10);
	if (p)
		*p = 0;
	p = strchr(yes, 13);
	if (p)
		*p = 0;
	if (strcmp(yes, "yes")) {
		printf("Operation cancelled !\n");
		exit(1);
	}
	must_confirm = false;
}

static void print_ffs_info(uint32_t toc_offset)
{
	struct ffs_handle *ffs_handle;
	uint32_t other_side_offset = 0;
	int rc;
	uint32_t i;

	printf("\n");
	printf("TOC@0x%08x Partitions:\n", toc_offset);
	printf("-----------\n");

	rc = ffs_init(toc_offset, fl_total_size, bl, &ffs_handle, 0);
	if (rc) {
		fprintf(stderr, "Error %d opening ffs !\n", rc);
		return;
	}

	for (i = 0;; i++) {
		uint32_t start, size, act, end;
		bool ecc;
		char *name;

		rc = ffs_part_info(ffs_handle, i, &name, &start, &size, &act, &ecc);
		if (rc == FFS_ERR_PART_NOT_FOUND)
			break;
		if (rc) {
			fprintf(stderr, "Error %d scanning partitions\n", rc);
			break;
		}
		end = start + size;
		printf("ID=%02d %15s %08x..%08x (actual=%08x) %s\n",
		       i, name, start, end, act, ecc ? "[ECC]" : "");

		if (strcmp(name, "OTHER_SIDE") == 0)
			other_side_offset = start;

		free(name);
	}

	ffs_close(ffs_handle);

	if (other_side_offset)
		print_ffs_info(other_side_offset);
}


static void print_flash_info(uint32_t toc)
{
	printf("Flash info:\n");
	printf("-----------\n");
	printf("Name          = %s\n", fl_name);
	printf("Total size    = %dMB \n", fl_total_size >> 20);
	printf("Erase granule = %dKB \n", fl_erase_granule >> 10);

	if (bmc_flash)
		return;

	print_ffs_info(toc);
}

static int open_partition(const char *name)
{
	uint32_t index;
	int rc;

	/* Open libffs if needed */
	if (!ffsh) {
		rc = ffs_init(ffs_toc, fl_total_size, bl, &ffsh, 0);
		if (rc) {
			fprintf(stderr, "Error %d opening ffs !\n", rc);
			if (ffs_toc)
				fprintf(stderr, "You specified 0x%08x as the libffs TOC"
						" looks like it doesn't exist\n", ffs_toc);
			return rc;
		}
	}

	/* Find partition */
	rc = ffs_lookup_part(ffsh, name, &index);
	if (rc == FFS_ERR_PART_NOT_FOUND) {
		fprintf(stderr, "Partition '%s' not found !\n", name);
		return rc;
	}
	if (rc) {
		fprintf(stderr, "Error %d looking for partition '%s' !\n",
			rc, name);
		return rc;
	}

	ffs_index = index;
	return 0;
}

static void lookup_partition(const char *name)
{
	int rc;

	if (flash_side == 1) {
		uint32_t other_side_offset;

		rc = open_partition("OTHER_SIDE");
		if (rc == FFS_ERR_PART_NOT_FOUND)
			fprintf(stderr, "side 1 was specified but there doesn't appear"
					" to be a second side to this flash\n");
		if (rc)
			exit(1);

		/* Just need to know where it starts */
		rc = ffs_part_info(ffsh, ffs_index, NULL, &other_side_offset, NULL, NULL, NULL);
		if (rc)
			exit(1);

		ffs_close(ffsh);
		ffsh = NULL;

		ffs_toc = other_side_offset;
	}

	rc = open_partition(name);
	if (rc)
		exit(1);
}

static void erase_chip(void)
{
	int rc;

	printf("About to erase chip !\n");
	check_confirm();

	printf("Erasing... (may take a while !) ");
	fflush(stdout);

	if (dummy_run) {
		printf("skipped (dummy)\n");
		return;
	}

	rc = arch_flash_erase_chip(bl);
	if (rc) {
		fprintf(stderr, "Error %d erasing chip\n", rc);
		exit(1);
	}

	printf("done !\n");
}

static void erase_range(uint32_t start, uint32_t size, bool will_program)
{
	uint32_t done = 0;
	int rc;

	printf("About to erase 0x%08x..0x%08x !\n", start, start + size);
	check_confirm();

	if (dummy_run) {
		printf("skipped (dummy)\n");
		return;
	}

	printf("Erasing...\n");
	progress_init(size >> 8);
	while(size) {
		/* If aligned to 64k and at least 64k, use 64k erase */
		if ((start & 0xffff) == 0 && size >= 0x10000) {
			rc = blocklevel_erase(bl, start, 0x10000);
			if (rc) {
				fprintf(stderr, "Error %d erasing 0x%08x\n",
					rc, start);
				exit(1);
			}
			start += 0x10000;
			size -= 0x10000;
			done += 0x10000;
		} else {
			rc = blocklevel_erase(bl, start, 0x1000);
			if (rc) {
				fprintf(stderr, "Error %d erasing 0x%08x\n",
					rc, start);
				exit(1);
			}
			start += 0x1000;
			size -= 0x1000;
			done += 0x1000;
		}
		progress_tick(done >> 8);
	}
	progress_end();

	/* If this is a flash partition, mark it empty if we aren't
	 * going to program over it as well
	 */
	if (ffsh && ffs_index >= 0 && !will_program) {
		printf("Updating actual size in partition header...\n");
		ffs_update_act_size(ffsh, ffs_index, 0);
	}
}

static void set_ecc(uint32_t start, uint32_t size)
{
	uint32_t i = start + 8;
	uint8_t ecc = 0;

	printf("About to erase and set ECC bits in region 0x%08x to 0x%08x\n", start, start + size);
	check_confirm();
	erase_range(start, size, true);

	printf("Programming ECC bits...\n");
	progress_init(size);
	while (i < start + size) {
		blocklevel_write(bl, i, &ecc, sizeof(ecc));
		i += 9;
		progress_tick(i - start);
	}
	progress_end();
}

static void program_file(const char *file, uint32_t start, uint32_t size)
{
	int fd, rc;
	ssize_t len;
	uint32_t actual_size = 0;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("Failed to open file");
		exit(1);
	}
	printf("About to program \"%s\" at 0x%08x..0x%08x !\n",
	       file, start, start + size);
	check_confirm();

	if (dummy_run) {
		printf("skipped (dummy)\n");
		close(fd);
		return;
	}

	printf("Programming & Verifying...\n");
	progress_init(size >> 8);
	while(size) {
		len = read(fd, file_buf, FILE_BUF_SIZE);
		if (len < 0) {
			perror("Error reading file");
			exit(1);
		}
		if (len == 0)
			break;
		if (len > size)
			len = size;
		size -= len;
		actual_size += len;
		rc = blocklevel_write(bl, start, file_buf, len);
		if (rc) {
			if (rc == FLASH_ERR_VERIFY_FAILURE)
				fprintf(stderr, "Verification failed for"
					" chunk at 0x%08x\n", start);
			else
				fprintf(stderr, "Flash write error %d for"
					" chunk at 0x%08x\n", rc, start);
			exit(1);
		}
		start += len;
		progress_tick(actual_size >> 8);
	}
	progress_end();
	close(fd);

	/* If this is a flash partition, adjust its size */
	if (ffsh && ffs_index >= 0) {
		printf("Updating actual size in partition header...\n");
		ffs_update_act_size(ffsh, ffs_index, actual_size);
	}
}

static void do_read_file(const char *file, uint32_t start, uint32_t size)
{
	int fd, rc;
	ssize_t len;
	uint32_t done = 0;

	fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 00666);
	if (fd == -1) {
		perror("Failed to open file");
		exit(1);
	}
	printf("Reading to \"%s\" from 0x%08x..0x%08x !\n",
	       file, start, start + size);

	progress_init(size >> 8);
	while(size) {
		len = size > FILE_BUF_SIZE ? FILE_BUF_SIZE : size;
		rc = blocklevel_read(bl, start, file_buf, len);
		if (rc) {
			fprintf(stderr, "Flash read error %d for"
				" chunk at 0x%08x\n", rc, start);
			exit(1);
		}
		rc = write(fd, file_buf, len);
		if (rc < 0) {
			perror("Error writing file");
			exit(1);
		}
		start += len;
		size -= len;
		done += len;
		progress_tick(done >> 8);
	}
	progress_end();
	close(fd);
}

static void enable_4B_addresses(void)
{
	int rc;

	printf("Switching to 4-bytes address mode\n");

	rc = arch_flash_4b_mode(bl, true);
	if (rc) {
		if (rc == -1) {
			fprintf(stderr, "Switching address mode not available on this architecture\n");
		} else {
			fprintf(stderr, "Error %d enabling 4b mode\n", rc);
		}
		exit(1);
	}
}

static void disable_4B_addresses(void)
{
	int rc;

	printf("Switching to 3-bytes address mode\n");

	rc = arch_flash_4b_mode(bl, false);
	if (rc) {
		if (rc == -1) {
			fprintf(stderr, "Switching address mode not available on this architecture\n");
		} else {
			fprintf(stderr, "Error %d enabling 4b mode\n", rc);
		}
		exit(1);
	}
}

static void print_version(void)
{
	printf("Open-Power Flash tool %s\n", version);
}

static void print_help(const char *pname)
{
	printf("Usage: %s [options] commands...\n\n", pname);
	printf(" Options:\n");
	printf("\t-a address, --address=address\n");
	printf("\t\tSpecify the start address for erasing, reading\n");
	printf("\t\tor flashing\n\n");
	printf("\t-s size, --size=size\n");
	printf("\t\tSpecify the size in bytes for erasing, reading\n");
	printf("\t\tor flashing\n\n");
	printf("\t-P part_name, --partition=part_name\n");
	printf("\t\tSpecify the partition whose content is to be erased\n");
	printf("\t\tprogrammed or read. This is an alternative to -a and -s\n");
	printf("\t\tif both -P and -s are specified, the smallest of the\n");
	printf("\t\ttwo will be used\n\n");
	printf("\t-f, --force\n");
	printf("\t\tDon't ask for confirmation before erasing or flashing\n\n");
	printf("\t-d, --dummy\n");
	printf("\t\tDon't write to flash\n\n");
	printf("\t-m, --mtd\n");
	printf("\t\tAvoid accessing the flash directly if the BMC supports it.\n");
	printf("\t\tThis will access the flash through the kernel MTD layer and\n");
	printf("\t\tnot the flash directly\n");
	printf("\t-b, --bmc\n");
	printf("\t\tTarget BMC flash instead of host flash.\n");
	printf("\t\tNote: This carries a high chance of bricking your BMC if you\n");
	printf("\t\tdon't know what you're doing. Consider --mtd to be safe(r)\n\n");
	printf("\t-F filename, --flash-file filename\n");
	printf("\t\tTarget filename instead of actual flash.\n\n");
	printf("\t-S, --side\n");
	printf("\t\tSide of the flash on which to operate, 0 (default) or 1\n\n");
	printf("\t-T, --toc\n");
	printf("\t\tlibffs TOC on which to operate, defaults to 0.\n");
	printf("\t\tleading 0x is required for interpretation of a hex value\n\n");
	printf(" Commands:\n");
	printf("\t-4, --enable-4B\n");
	printf("\t\tSwitch the flash and controller to 4-bytes address\n");
	printf("\t\tmode (no confirmation needed).\n\n");
	printf("\t-3, --disable-4B\n");
	printf("\t\tSwitch the flash and controller to 3-bytes address\n");
	printf("\t\tmode (no confirmation needed).\n\n");
	printf("\t-r file, --read=file\n");
	printf("\t\tRead flash content from address into file, use -s\n");
	printf("\t\tto specify the size to read (or it will use the source\n");
	printf("\t\tfile size if used in conjunction with -p and -s is not\n");
	printf("\t\tspecified). When using -r together with -e or -p, the\n");
	printf("\t\tread will be performed first\n\n");
	printf("\t-E, --erase-all\n");
	printf("\t\tErase entire flash chip\n");
	printf("\t\t(Not supported on all chips/controllers)\n\n");
	printf("\t-e, --erase\n");
	printf("\t\tErase the specified region. If size or address are not\n");
	printf("\t\tspecified, but \'--program\' is used, then the file\n");
	printf("\t\tsize will be used (rounded to an erase block) and the\n");
	printf("\t\taddress defaults to 0.\n\n");
	printf("\t-p file, --program=file\n");
	printf("\t\tWill program the file to flash. If the address is not\n");
	printf("\t\tspecified, it will use 0. If the size is not specified\n");
	printf("\t\tit will use the file size. Otherwise it will limit to\n");
	printf("\t\tthe specified size (whatever is smaller). If used in\n");
	printf("\t\tconjunction with any erase command, the erase will\n");
	printf("\t\ttake place first.\n\n");
	printf("\t-t, --tune\n");
	printf("\t\tJust tune the flash controller & access size\n");
	printf("\t\t(Implicit for all other operations)\n\n");
	printf("\t-c --clear\n");
	printf("\t\tUsed to ECC clear a partition of the flash\n");
	printf("\t\tMust be used in conjunction with -P. Will erase the\n");
	printf("\t\tpartition and then set all the ECC bits as they should be\n\n");
	printf("\t-i, --info\n");
	printf("\t\tDisplay some information about the flash.\n\n");
	printf("\t-h, --help\n");
	printf("\t\tThis message.\n\n");
}

void exiting(void)
{
	if (need_relock)
		arch_flash_set_wrprotect(bl, 1);
	arch_flash_close(bl, NULL);
}

int main(int argc, char *argv[])
{
	const char *pname = argv[0];
	uint32_t address = 0, read_size = 0, write_size = 0;
	uint32_t erase_start = 0, erase_size = 0;
	bool erase = false, do_clear = false;
	bool program = false, erase_all = false, info = false, do_read = false;
	bool enable_4B = false, disable_4B = false;
	bool show_help = false, show_version = false;
	bool no_action = false, tune = false;
	char *write_file = NULL, *read_file = NULL, *part_name = NULL;
	bool ffs_toc_seen = false, mtd = false;
	int rc;
	const char *flashfilename = NULL;

	while(1) {
		struct option long_opts[] = {
			{"address",	required_argument,	NULL,	'a'},
			{"size",	required_argument,	NULL,	's'},
			{"partition",	required_argument,	NULL,	'P'},
			{"bmc",		no_argument,		NULL,	'b'},
			{"mtd",		no_argument,		NULL,	'm'},
			{"enable-4B",	no_argument,		NULL,	'4'},
			{"disable-4B",	no_argument,		NULL,	'3'},
			{"read",	required_argument,	NULL,	'r'},
			{"erase-all",	no_argument,		NULL,	'E'},
			{"erase",	no_argument,		NULL,	'e'},
			{"program",	required_argument,	NULL,	'p'},
			{"force",	no_argument,		NULL,	'f'},
			{"flash-file",	required_argument,	NULL,	'F'},
			{"info",	no_argument,		NULL,	'i'},
			{"tune",	no_argument,		NULL,	't'},
			{"dummy",	no_argument,		NULL,	'd'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
			{"debug",	no_argument,		NULL,	'g'},
			{"side",	required_argument,	NULL,	'S'},
			{"toc",		required_argument,	NULL,	'T'},
			{"clear",   no_argument,        NULL,   'c'},
			{NULL,	    0,                  NULL,    0 }
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "+:a:s:P:r:43Eemp:fdihvbtgS:T:cF:",
				long_opts, &oidx);
		if (c == -1)
			break;
		switch(c) {
		case 'a':
			address = strtoul(optarg, NULL, 0);
			break;
		case 's':
			read_size = write_size = strtoul(optarg, NULL, 0);
			break;
		case 'P':
			part_name = strdup(optarg);
			break;
		case '4':
			enable_4B = true;
			break;
		case '3':
			disable_4B = true;
			break;
		case 'r':
			do_read = true;
			read_file = strdup(optarg);
			break;
		case 'E':
			erase_all = erase = true;
			break;
		case 'e':
			erase = true;
			break;
		case 'm':
			mtd = true;
			break;
		case 'p':
			program = true;
			write_file = strdup(optarg);
			break;
		case 'f':
			must_confirm = false;
			break;
		case 'F':
			flashfilename = optarg;
			break;
		case 'd':
			must_confirm = false;
			dummy_run = true;
			break;
		case 'i':
			info = true;
			break;
		case 'b':
			bmc_flash = true;
			break;
		case 't':
			tune = true;
			break;
		case 'v':
			show_version = true;
			break;
		case 'h':
			show_help = show_version = true;
			break;
		case 'g':
			libflash_debug = true;
			break;
		case 'S':
			flash_side = atoi(optarg);
			break;
		case 'T':
			ffs_toc_seen = true;
			ffs_toc = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			do_clear = true;
			break;
		case ':':
			fprintf(stderr, "Unrecognised option \"%s\" to '%c'\n", optarg, optopt);
			no_action = true;
			break;
		case '?':
			fprintf(stderr, "Unrecognised option '%c'\n", optopt);
			no_action = true;
			break;
		default:
			fprintf(stderr , "Encountered unknown error parsing options\n");
			no_action = true;
		}
	}

	if (optind < argc) {
		/*
		 * It appears not everything passed to pflash was an option, best to
		 * not continue
		 */
		while (optind < argc)
			fprintf(stderr, "Unrecognised option or argument \"%s\"\n", argv[optind++]);

		no_action = true;
	}

	/* Check if we need to access the flash at all (which will
	 * also tune them as a side effect
	 */
	no_action = no_action || (!erase && !program && !info && !do_read &&
		!enable_4B && !disable_4B && !tune && !do_clear);

	/* Nothing to do, if we didn't already, print usage */
	if (no_action && !show_version)
		show_help = show_version = true;

	if (show_version)
		print_version();
	if (show_help)
		print_help(pname);

	if (no_action)
		return 0;

	/* --enable-4B and --disable-4B are mutually exclusive */
	if (enable_4B && disable_4B) {
		fprintf(stderr, "--enable-4B and --disable-4B are mutually"
			" exclusive !\n");
		exit(1);
	}

	/* 4B not supported on BMC flash */
	if (enable_4B && bmc_flash) {
		fprintf(stderr, "--enable-4B not supported on BMC flash !\n");
		exit(1);
	}

	/* partitions not supported on BMC flash */
	if (part_name && bmc_flash) {
		fprintf(stderr, "--partition not supported on BMC flash !\n");
		exit(1);
	}

	/* part-name and erase-all make no sense together */
	if (part_name && erase_all) {
		fprintf(stderr, "--partition and --erase-all are mutually"
			" exclusive !\n");
		exit(1);
	}

	/* Read command should always come with a file */
	if (do_read && !read_file) {
		fprintf(stderr, "Read with no file specified !\n");
		exit(1);
	}

	/* Program command should always come with a file */
	if (program && !write_file) {
		fprintf(stderr, "Program with no file specified !\n");
		exit(1);
	}

	/* If both partition and address specified, error out */
	if (address && part_name) {
		fprintf(stderr, "Specify partition or address, not both !\n");
		exit(1);
	}

	if (do_clear && !part_name) {
		fprintf(stderr, "--clear only supported on a partition name\n");
		exit(1);
	}

	/* Explicitly only support two sides */
	if (flash_side != 0 && flash_side != 1) {
		fprintf(stderr, "Unexpected value for --side '%d'\n", flash_side);
		exit(1);
	}

	if (ffs_toc_seen && flash_side) {
		fprintf(stderr, "--toc and --side are exclusive");
		exit(1);
	}

	/* If file specified but not size, get size from file
	 */
	if (write_file && !write_size) {
		struct stat stbuf;

		if (stat(write_file, &stbuf)) {
			perror("Failed to get file size");
			exit(1);
		}
		write_size = stbuf.st_size;
	}

	if (bmc_flash) {
		/*
		 * Try to see if we can access BMC flash on this arch at all...
		 * even if what we really want to do is use MTD.
		 * This helps give a more meaningful error messages.
		 */

		if (arch_flash_bmc(NULL, BMC_DIRECT) == ACCESS_INVAL) {
			fprintf(stderr, "Can't access BMC flash on this architecture\n");
			exit(1);
		}
	}

	if (mtd) {
		if (arch_flash_bmc(NULL, bmc_flash ? BMC_MTD : PNOR_MTD) == ACCESS_INVAL) {
			fprintf(stderr, "Can't access %s flash through MTD on this architecture\n",
			        bmc_flash ? "BMC" : "PNOR");
			exit(1);
		}
	}

	if (arch_flash_init(&bl, flashfilename, true)) {
		fprintf(stderr, "Couldn't initialise architecture flash structures\n");
		exit(1);
	}

	atexit(exiting);

	rc = blocklevel_get_info(bl, &fl_name,
			    &fl_total_size, &fl_erase_granule);
	if (rc) {
		fprintf(stderr, "Error %d getting flash info\n", rc);
		exit(1);
	}

	/* If -t is passed, then print a nice message */
	if (tune)
		printf("Flash and controller tuned\n");

	/* If read specified and no read_size, use flash size */
	if (do_read && !read_size && !part_name)
		read_size = fl_total_size;

	/* We have a partition specified, grab the details */
	if (part_name)
		lookup_partition(part_name);

	/* We have a partition, adjust read/write size if needed */
	if (ffsh && ffs_index >= 0) {
		uint32_t pstart, pmaxsz, pactsize;
		bool ecc;
		int rc;

		rc = ffs_part_info(ffsh, ffs_index, NULL,
				   &pstart, &pmaxsz, &pactsize, &ecc);
		if (rc) {
			fprintf(stderr,"Failed to get partition info\n");
			exit(1);
		}

		if (!ecc && do_clear) {
			fprintf(stderr, "The partition on which to do --clear "
					"does not have ECC, are you sure?\n");
			check_confirm();
			/* Still confirm later on */
			must_confirm = true;
		}

		/* Read size is obtained from partition "actual" size */
		if (!read_size)
			read_size = pactsize;

		/* Write size is max size of partition */
		if (!write_size)
			write_size = pmaxsz;

		/* Crop write size to partition size */
		if (write_size > pmaxsz) {
			printf("WARNING: Size (%d bytes) larger than partition"
			       " (%d bytes), cropping to fit\n",
			       write_size, pmaxsz);
			write_size = pmaxsz;
		}

		/* If erasing, check partition alignment */
		if (erase && ((pstart | pmaxsz) & 0xfff)) {
			fprintf(stderr,"Partition not aligned properly\n");
			exit(1);
		}

		/* Set address */
		address = pstart;
	}

	/* Align erase boundaries */
	if (erase && !erase_all) {
		uint32_t mask = 0xfff;
		uint32_t erase_end;

		/* Dummy size for erase, will be adjusted later */
		if (!write_size)
			write_size = 1;
		erase_start = address & ~mask;
		erase_end = ((address + write_size) + mask) & ~mask;
		erase_size = erase_end - erase_start;

		if (erase_start != address || erase_size != write_size)
			fprintf(stderr, "WARNING: Erase region adjusted"
				" to 0x%08x..0x%08x\n",
				erase_start, erase_end);
	}

	/* Process commands */
	if (enable_4B)
		enable_4B_addresses();
	if (disable_4B)
		disable_4B_addresses();
	if (info) {
		/*
		 * Don't pass through modfied TOC value if the modification was done
		 * because of --size, but still respect if it came from --toc (we
		 * assume the user knows what they're doing in that case)
		 */
		print_flash_info(flash_side ? 0 : ffs_toc);
	}

	/* Unlock flash (PNOR only) */
	if ((erase || program || do_clear) && !bmc_flash) {
		need_relock = arch_flash_set_wrprotect(bl, false);
		if (need_relock == -1) {
			fprintf(stderr, "Architecture doesn't support write protection on flash\n");
			need_relock = 0;
			exit (1);
		}
	}
	if (do_read)
		do_read_file(read_file, address, read_size);
	if (erase_all)
		erase_chip();
	else if (erase)
		erase_range(erase_start, erase_size, program);
	if (program)
		program_file(write_file, address, write_size);
	if (do_clear)
		set_ecc(address, write_size);
	return 0;
}
