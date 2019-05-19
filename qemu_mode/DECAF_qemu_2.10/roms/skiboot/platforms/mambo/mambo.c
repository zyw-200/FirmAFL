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
#include <device.h>
#include <console.h>
#include <chip.h>
#include <opal-api.h>
#include <opal-internal.h>
#include <time-utils.h>
#include <time.h>

extern int64_t mambo_get_time(void);

static bool mambo_probe(void)
{
	if (!dt_find_by_path(dt_root, "/mambo"))
		return false;

	return true;
}

static int64_t mambo_rtc_read(uint32_t *ymd, uint64_t *hmsm)
{
	int64_t mambo_time;
	struct tm t;
	time_t mt;

	if (!ymd || !hmsm)
		return OPAL_PARAMETER;

	mambo_time = mambo_get_time();
	mt = mambo_time >> 32;
	gmtime_r(&mt, &t);
	tm_to_datetime(&t, ymd, hmsm);

	return OPAL_SUCCESS;
}

static void mambo_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, mambo_rtc_read, 2);
}

static inline int callthru2(int command, unsigned long arg1, unsigned long arg2)
{
	register int c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2));
	return (c);
}

static inline int callthru3(int command, unsigned long arg1, unsigned long arg2,
			    unsigned long arg3)
{
	register int c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	register unsigned long a3 asm("r6") = arg3;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2),
		      "r"(a3));
	return (c);
}

#define BD_INFO_SYNC		0
#define BD_INFO_STATUS		1
#define BD_INFO_BLKSZ		2
#define BD_INFO_DEVSZ		3
#define BD_INFO_CHANGE		4

#define BD_SECT_SZ		512

#define BOGUS_DISK_READ		116
#define BOGUS_DISK_WRITE	117
#define BOGUS_DISK_INFO		118

static inline int callthru_disk_read(int id, void *buf, unsigned long sect,
				     unsigned long nrsect)
{
	return callthru3(BOGUS_DISK_READ, (unsigned long)buf, sect,
			 (nrsect << 16) | id);
}

static inline int callthru_disk_write(int id, void *buf, unsigned long sect,
				      unsigned long nrsect)
{
	return callthru3(BOGUS_DISK_WRITE, (unsigned long)buf, sect,
			 (nrsect << 16) | id);
}

static inline unsigned long callthru_disk_info(int op, int id)
{
	return callthru2(BOGUS_DISK_INFO, (unsigned long)op,
			 (unsigned long)id);
}

struct bogus_disk_info {
	unsigned long size;
	int id;
};

static int bogus_disk_read(struct blocklevel_device *bl, uint32_t pos, void *buf,
			  uint32_t len)
{
	struct bogus_disk_info *bdi = bl->priv;
	int rc;
	char b[BD_SECT_SZ];

	if ((len % BD_SECT_SZ) == 0)
		return callthru_disk_read(bdi->id, buf, pos/BD_SECT_SZ,
					  len/BD_SECT_SZ);

	/* We don't support block reads > BD_SECT_SZ */
	if (len > BD_SECT_SZ)
		return OPAL_PARAMETER;

	/* Skiboot does small reads for system flash header checking */
	rc =  callthru_disk_read(bdi->id, b, pos/BD_SECT_SZ, 1);
	if (rc)
		return rc;
	memcpy(buf, &b[pos % BD_SECT_SZ], len);
	return rc;
}

static int bogus_disk_write(struct blocklevel_device *bl, uint32_t pos,
			    const void *buf, uint32_t len)
{
	struct bogus_disk_info *bdi = bl->priv;

	if ((len % BD_SECT_SZ) != 0)
		return OPAL_PARAMETER;

	return callthru_disk_write(bdi->id, (void *)buf, pos/BD_SECT_SZ,
				   len/BD_SECT_SZ);

}

static int bogus_disk_erase(struct blocklevel_device *bl __unused,
			   uint32_t pos __unused, uint32_t len __unused)
{
	return 0; /* NOP */
}

static int bogus_disk_get_info(struct blocklevel_device *bl, const char **name,
			      uint32_t *total_size, uint32_t *erase_granule)
{
	struct bogus_disk_info *bdi = bl->priv;

	if (total_size)
		*total_size = bdi->size;

	if (erase_granule)
		*erase_granule = BD_SECT_SZ;

	if (name)
		*name = "mambobogus";

	return 0;
}

static void bogus_disk_flash_init(void)
{
	struct blocklevel_device *bl;
	struct bogus_disk_info *bdi;
	unsigned long id = 0, size;
	int rc;

	if (!chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

	while (1) {

		rc = callthru_disk_info(BD_INFO_STATUS, id);
		if (rc < 0)
			return;

		size = callthru_disk_info(BD_INFO_DEVSZ, id) * 1024;
		prlog(PR_NOTICE, "mambo: Found bogus disk size: 0x%lx\n", size);

		bl = zalloc(sizeof(struct blocklevel_device));
		bdi = zalloc(sizeof(struct bogus_disk_info));
		if (!bl || !bdi) {
			free(bl);
			free(bdi);
			prerror("mambo: Failed to start bogus disk, ENOMEM\n");
			return;
		}

		bl->read = &bogus_disk_read;
		bl->write = &bogus_disk_write;
		bl->erase = &bogus_disk_erase;
		bl->get_info = &bogus_disk_get_info;
		bdi->id = id;
		bdi->size = size;
		bl->priv = bdi;
		bl->erase_mask = BD_SECT_SZ - 1;

		rc = flash_register(bl, true);
		if (rc)
			prerror("mambo: Failed to register bogus disk: %li\n",
				id);
		id++;
	}
}

static void mambo_platform_init(void)
{
	force_dummy_console();
	mambo_rtc_init();
	bogus_disk_flash_init();
}

static int64_t mambo_cec_power_down(uint64_t request __unused)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		mambo_sim_exit();

	return OPAL_UNSUPPORTED;
}

static void __attribute__((noreturn)) mambo_terminate(const char *msg __unused)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		mambo_sim_exit();

	for (;;) ;
}

static int mambo_nvram_info(uint32_t *total_size)
{
	*total_size = 0x100000;
	return OPAL_SUCCESS;
}

static int mambo_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	memset(dst+src, 0, len);

	nvram_read_complete(true);

	return OPAL_SUCCESS;
}

static int mambo_heartbeat_time(void)
{
	/*
	 * Mambo is slow and has no console input interrupt, so faster
	 * polling is needed to ensure its responsiveness.
	 */
	return 100;
}

DECLARE_PLATFORM(mambo) = {
	.name			= "Mambo",
	.probe			= mambo_probe,
	.init		= mambo_platform_init,
	.cec_power_down = mambo_cec_power_down,
	.terminate	= mambo_terminate,
	.nvram_info		= mambo_nvram_info,
	.nvram_start_read	= mambo_nvram_start_read,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.heartbeat_time		= mambo_heartbeat_time,
};
