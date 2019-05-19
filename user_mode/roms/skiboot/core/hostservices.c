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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <lock.h>
#include <device.h>
#include <compiler.h>
#include <hostservices.h>
#include <mem_region.h>
#include <xscom.h>
#include <fsp.h>
#include <chip.h>
#include <console.h>
#include <mem-map.h>
#include <timebase.h>

#define HOSTBOOT_RUNTIME_INTERFACE_VERSION 1

struct host_interfaces {
	/** Interface version. */
	uint64_t interface_version;

	/** Put a string to the console. */
	void (*puts)(const char*);
	/** Critical failure in runtime execution. */
	void (*assert)(void);

	/** OPTIONAL. Hint to environment that the page may be executed. */
	int (*set_page_execute)(void*);

	/** malloc */
	void *(*malloc)(size_t);
	/** free */
	void (*free)(void*);
	/** realloc */
	void *(*realloc)(void*, size_t);

	/** sendErrorLog
	 * @param[in] plid Platform Log identifier
	 * @param[in] data size in bytes
	 * @param[in] pointer to data
	 * @return 0 on success else error code
	 */
	int (*send_error_log)(uint32_t,uint32_t,void *);

	/** Scan communication read
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 */
	int (*scom_read)(uint64_t, uint64_t, void*);

	/** Scan communication write
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 */
	int (*scom_write)(uint64_t, uint64_t, const void *);

	/** lid_load
	 *  Load a LID from PNOR, FSP, etc.
	 *
	 *  @param[in] LID number.
	 *  @param[out] Allocated buffer for LID.
	 *  @param[out] Size of LID (in bytes).
	 *
	 *  @return 0 on success, else RC.
	 */
	int (*lid_load)(uint32_t lid, void **buf, size_t *len);

	/** lid_unload
	 *  Release memory from previously loaded LID.
	 *
	 *  @param[in] Allocated buffer for LID to release.
	 *
	 *  @return 0 on success, else RC.
	 */
	int (*lid_unload)(void *buf);

	/** Get the address of a reserved memory region by its devtree name.
	 *
	 *  @param[in] Devtree name (ex. "ibm,hbrt-vpd-image")
	 *  @return physical address of region (or NULL).
	 **/
	uint64_t (*get_reserved_mem)(const char*);

	/**
	 * @brief  Force a core to be awake, or clear the force
	 * @param[in] i_core  Core to wake up (pid)
	 * @param[in] i_mode  0=force awake
	 *                1=clear force
	 *                2=clear all previous forces
	 * @return rc  non-zero on error
	 */
	int (*wakeup)( uint32_t i_core, uint32_t i_mode );

	/**
	 * @brief Delay/sleep for at least the time given
	 * @param[in] seconds
	 * @param[in] nano seconds
	 */
	void (*nanosleep)(uint64_t i_seconds, uint64_t i_nano_seconds);

	// Reserve some space for future growth.
	void (*reserved[32])(void);
};

struct runtime_interfaces {
	/** Interface version. */
	uint64_t interface_version;

	/** Execute CxxTests that may be contained in the image.
	 *
	 * @param[in] - Pointer to CxxTestStats structure for results reporting.
	 */
	void (*cxxtestExecute)(void *);
	/** Get a list of lids numbers of the lids known to HostBoot
	 *
	 * @param[out] o_num - the number of lids in the list
	 * @return a pointer to the list
	 */
	const uint32_t * (*get_lid_list)(size_t * o_num);

	/** Load OCC Image and common data into mainstore, also setup OCC BARSs
	 *
	 * @param[in] i_homer_addr_phys - The physical mainstore address of the
	 *                                start of the HOMER image
	 * @param[in] i_homer_addr_va - Virtual memory address of the HOMER image
	 * @param[in] i_common_addr_phys - The physical mainstore address of the
	 *                                 OCC common area.
	 * @param[in] i_common_addr_va - Virtual memory address of the common area
	 * @param[in] i_chip - The HW chip id (XSCOM chip ID)
	 * @return 0 on success else return code
	 */
	int(*loadOCC)(uint64_t i_homer_addr_phys,
			uint64_t i_homer_addr_va,
			uint64_t i_common_addr_phys,
			uint64_t i_common_addr_va,
			uint64_t i_chip);

	/** Start OCC on all chips, by module
	 *
	 *  @param[in] i_chip - Array of functional HW chip ids
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 */
	int (*startOCCs)(uint64_t* i_chip,
			size_t i_num_chips);

	/** Stop OCC hold OCCs in reset
	 *
	 *  @param[in] i_chip - Array of functional HW chip ids
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 */
	int (*stopOCCs)(uint64_t* i_chip,
			size_t i_num_chips);

	/* Reserve some space for future growth. */
	void (*reserved[32])(void);
};

static struct runtime_interfaces *hservice_runtime;

static char *hbrt_con_buf = (char *)HBRT_CON_START;
static size_t hbrt_con_pos;
static bool hbrt_con_wrapped;

#define HBRT_CON_IN_LEN		0
#define HBRT_CON_OUT_LEN	(HBRT_CON_LEN - HBRT_CON_IN_LEN)

static struct memcons hbrt_memcons __section(".data.memcons") = {
	.magic		= MEMCONS_MAGIC,
	.obuf_phys	= HBRT_CON_START,
	.ibuf_phys	= HBRT_CON_START + HBRT_CON_OUT_LEN,
	.obuf_size	= HBRT_CON_OUT_LEN,
	.ibuf_size	= HBRT_CON_IN_LEN,
};

static void hservice_putc(char c)
{
	uint32_t opos;

	hbrt_con_buf[hbrt_con_pos++] = c;
	if (hbrt_con_pos >= HBRT_CON_OUT_LEN) {
		hbrt_con_pos = 0;
		hbrt_con_wrapped = true;
	}

	/*
	 * We must always re-generate memcons.out_pos because
	 * under some circumstances, the console script will
	 * use a broken putmemproc that does RMW on the full
	 * 8 bytes containing out_pos and in_prod, thus corrupting
	 * out_pos
	 */
	opos = hbrt_con_pos;
	if (hbrt_con_wrapped)
		opos |= MEMCONS_OUT_POS_WRAP;
	lwsync();
	hbrt_memcons.out_pos = opos;
}

static void hservice_puts(const char *str)
{
	char c;

	while((c = *(str++)) != 0)
		hservice_putc(c);
	hservice_putc(10);
}

static void hservice_mark(void)
{
	hservice_puts("--------------------------------------------------"
		      "--------------------------------------------------\n");
}

static void hservice_assert(void)
{
	/**
	 * @fwts-label HBRTassert
	 * @fwts-advice HBRT triggered assert: you need to debug HBRT
	 */
	prlog(PR_EMERG, "HBRT: Assertion from hostservices\n");
	abort();
}

static void *hservice_malloc(size_t size)
{
	return malloc(size);
}

static void hservice_free(void *ptr)
{
	free(ptr);
}


static void *hservice_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

struct hbrt_elog_ent {
	void *buf;
	unsigned int size;
	unsigned int plid;
	struct list_node link;
};
static LIST_HEAD(hbrt_elogs);
static struct lock hbrt_elog_lock = LOCK_UNLOCKED;
static bool hbrt_elog_sending;
static void hservice_start_elog_send(void);

static void hservice_elog_write_complete(struct fsp_msg *msg)
{
	struct hbrt_elog_ent *ent = msg->user_data;

	lock(&hbrt_elog_lock);
	prlog(PR_DEBUG, "HBRT: Completed send of PLID 0x%08x\n", ent->plid);
	hbrt_elog_sending = false;
	fsp_tce_unmap(PSI_DMA_HBRT_LOG_WRITE_BUF,
		      PSI_DMA_HBRT_LOG_WRITE_BUF_SZ);
	free(ent->buf);
	free(ent);
	fsp_freemsg(msg);
	hservice_start_elog_send();
	unlock(&hbrt_elog_lock);
}

static void hservice_start_elog_send(void)
{
	struct fsp_msg *msg;
	struct hbrt_elog_ent *ent;

 again:
	if (list_empty(&hbrt_elogs))
		return;
	ent = list_pop(&hbrt_elogs, struct hbrt_elog_ent, link);

	hbrt_elog_sending = true;

	prlog(PR_DEBUG, "HBRT: Starting send of PLID 0x%08x\n", ent->plid);

	fsp_tce_map(PSI_DMA_HBRT_LOG_WRITE_BUF, ent->buf,
		    PSI_DMA_HBRT_LOG_WRITE_BUF_SZ);

	msg = fsp_mkmsg(FSP_CMD_WRITE_SP_DATA, 6, FSP_DATASET_HBRT_BLOB,
			0, 0, 0, PSI_DMA_HBRT_LOG_WRITE_BUF,
			ent->size);

	if (!msg) {
		prerror("HBRT: Failed to create error msg log to FSP\n");
		goto error;
	}
	msg->user_data = ent;
	if (!fsp_queue_msg(msg, hservice_elog_write_complete))
		return;
	prerror("FSP: Error queueing elog update\n");
 error:
	if (msg)
		fsp_freemsg(msg);
	fsp_tce_unmap(PSI_DMA_HBRT_LOG_WRITE_BUF,
		      PSI_DMA_HBRT_LOG_WRITE_BUF_SZ);
	free(ent->buf);
	free(ent);
	hbrt_elog_sending = false;
	goto again;
}

static int hservice_send_error_log(uint32_t plid, uint32_t dsize, void *data)
{
	struct hbrt_elog_ent *ent;
	void *abuf;

	prlog(PR_ERR, "HBRT: Error log generated with plid 0x%08x\n", plid);

	/* We only know how to send error logs to FSP */
	if (!fsp_present()) {
		prerror("HBRT: Warning, error log from HBRT discarded !\n");
		return OPAL_UNSUPPORTED;
	}
	if (dsize > PSI_DMA_HBRT_LOG_WRITE_BUF_SZ) {
		prerror("HBRT: Warning, error log from HBRT too big (%d) !\n",
			dsize);
		dsize = PSI_DMA_HBRT_LOG_WRITE_BUF_SZ;
	}

	lock(&hbrt_elog_lock);

	/* Create and populate a tracking structure */
	ent = zalloc(sizeof(struct hbrt_elog_ent));
	if (!ent) {
		unlock(&hbrt_elog_lock);
		return OPAL_NO_MEM;
	}

	/* Grab a 4k aligned page */
	abuf = memalign(0x1000, PSI_DMA_HBRT_LOG_WRITE_BUF_SZ);
	if (!abuf) {
		free(ent);
		unlock(&hbrt_elog_lock);
		return OPAL_NO_MEM;
	}
	memset(abuf, 0, PSI_DMA_HBRT_LOG_WRITE_BUF_SZ);
	memcpy(abuf, data, dsize);
	ent->buf = abuf;
	ent->size = dsize;
	ent->plid = plid;
	list_add_tail(&hbrt_elogs, &ent->link);
	if (!hbrt_elog_sending)
		hservice_start_elog_send();
	unlock(&hbrt_elog_lock);

	return 0;
}

static int hservice_scom_read(uint64_t chip_id, uint64_t addr, void *buf)
{
	return xscom_read(chip_id, addr, buf);
}

static int hservice_scom_write(uint64_t chip_id, uint64_t addr,
			       const void *buf)
{
	uint64_t val;

	memcpy(&val, buf, sizeof(val));
	return xscom_write(chip_id, addr, val);
}

struct hbrt_lid {
	void *load_addr;
	size_t len;
	uint32_t id;
	struct list_node link;
};
static LIST_HEAD(hbrt_lid_list);

static bool hbrt_lid_preload_complete = false;

bool hservices_lid_preload_complete(void)
{
	return hbrt_lid_preload_complete;
}

/* TODO: Few of the following routines can be generalized */
static int __hservice_lid_load(uint32_t lid, void **buf, size_t *len)
{
	int rc;

	/* Adjust LID side first or we get a cache mismatch */
	lid = fsp_adjust_lid_side(lid);

	/*
	 * Allocate a new buffer and load the LID into it
	 * XXX: We currently use the same size for each HBRT lid.
	 */
	*buf = malloc(HBRT_LOAD_LID_SIZE);
	*len = HBRT_LOAD_LID_SIZE;
	rc = fsp_preload_lid(lid, *buf, len);
	rc = fsp_wait_lid_loaded(lid);
	if (rc != 0)
		/* Take advantage of realloc corner case here. */
		*len = 0;
	*buf = realloc(*buf, *len);

	prlog(PR_DEBUG, "HBRT: LID 0x%08x successfully loaded, len=0x%lx\n",
			lid, (unsigned long)len);

	return rc;
}

static int __hservice_lid_preload(const uint32_t lid)
{
	struct hbrt_lid *hlid;
	void *buf;
	size_t len;
	int rc;

	hlid = zalloc(sizeof(struct hbrt_lid));
	if (!hlid) {
		prerror("HBRT: Could not allocate struct hbrt_lid\n");
		return OPAL_NO_MEM;
	}

	rc = __hservice_lid_load(lid, &buf, &len);
	if (rc) {
		free(hlid);
		return rc;
	}

	hlid->load_addr = buf;
	hlid->len = len;
	hlid->id = lid;
	list_add_tail(&hbrt_lid_list, &hlid->link);

	return 0;
}

/* Find and preload all lids needed by hostservices */
void hservices_lid_preload(void)
{
	const uint32_t *lid_list = NULL;
	size_t num_lids;
	int i;

	if (!hservice_runtime)
		return;

	lid_list = (const uint32_t *)hservice_runtime->get_lid_list(&num_lids);
	if (!lid_list) {
		prerror("HBRT: get_lid_list() returned NULL\n");
		return;
	}

	prlog(PR_INFO, "HBRT: %d lids to load\n", (int)num_lids);

	/* Currently HBRT needs only one (OCC) lid */
	for (i = 0; i < num_lids; i++)
		__hservice_lid_preload(lid_list[i]);

	hbrt_lid_preload_complete = true;
	occ_poke_load_queue();
}

static int hservice_lid_load(uint32_t lid, void **buf, size_t *len)
{
	struct hbrt_lid *hlid;

	prlog(PR_INFO, "HBRT: Lid load request for 0x%08x\n", lid);

	if (list_empty(&hbrt_lid_list))	{ /* Should not happen */
		/**
		 * @fwts-label HBRTlidLoadFail
		 * @fwts-advice Firmware should have aborted boot
		 */
		prlog(PR_CRIT, "HBRT: LID Load failed\n");
		abort();
	}

	list_for_each(&hbrt_lid_list, hlid, link) {
		if (hlid->id == lid) {
			*buf = hlid->load_addr;
			*len = hlid->len;
			prlog(PR_DEBUG, "HBRT: LID Serviced from cache,"
			      " %x, len=0x%lx\n", hlid->id, hlid->len);
			return 0;
		}
	}
	return -ENOENT;
}

static int hservice_lid_unload(void *buf __unused)
{
	/* We do nothing as the LID is held in cache */
	return 0;
}

static uint64_t hservice_get_reserved_mem(const char *name)
{
	struct mem_region *region;
	uint64_t ret;

	/* We assume it doesn't change after we've unlocked it, but
	 * lock ensures list is safe to walk. */
	lock(&mem_region_lock);
	region = find_mem_region(name);
	ret = region ? region->start : 0;
	unlock(&mem_region_lock);

	if (!ret)
		prlog(PR_WARNING, "HBRT: Mem region '%s' not found !\n", name);

	return ret;
}

static void hservice_nanosleep(uint64_t i_seconds, uint64_t i_nano_seconds)
{
	struct timespec ts;

	ts.tv_sec = i_seconds;
	ts.tv_nsec = i_nano_seconds;
	nanosleep_nopoll(&ts, NULL);
}

static int hservice_set_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val, core_id, poll_target, stamp;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP),
			 PPC_BIT(0));
	if (rc) {
		prerror("HBRT: XSCOM error %d asserting special"
			" wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * HWP uses the history for Perf register here, dunno why it uses
	 * that one instead of the pHyp one, maybe to avoid clobbering it...
	 *
	 * In any case, it does that to check for run/nap vs.sleep/winkle/other
	 * to decide whether to poll on checkstop or not. Since we don't deal
	 * with checkstop conditions here, we ignore that part.
	 */

	/*
	 * Now poll for completion of special wakeup. The HWP is nasty here,
	 * it will poll at 5ms intervals for up to 200ms. This is not quite
	 * acceptable for us at runtime, at least not until we have the
	 * ability to "context switch" HBRT. In practice, because we don't
	 * winkle, it will never take that long, so we increase the polling
	 * frequency to 1us per poll. However we do have to keep the same
	 * timeout.
	 *
	 * We don't use time_wait_ms() either for now as we don't want to
	 * poll the FSP here.
	 */
	stamp = mftb();
	poll_target = stamp + msecs_to_tb(200);
	val = 0;
	while (!(val & EX_PM_GP0_SPECIAL_WAKEUP_DONE)) {
		/* Wait 1 us */
		hservice_nanosleep(0, 1000);

		/* Read PM state */
		rc = xscom_read(cpu->chip_id,
				XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_GP0),
				&val);
		if (rc) {
			prerror("HBRT: XSCOM error %d reading PM state on"
				" 0x%x\n", rc, cpu->pir);
			return rc;
		}
		/* Check timeout */
		if (mftb() > poll_target)
			break;
	}

	/* Success ? */
	if (val & EX_PM_GP0_SPECIAL_WAKEUP_DONE) {
		uint64_t now = mftb();
		prlog(PR_TRACE, "HBRT: Special wakeup complete after %ld us\n",
		      tb_to_usecs(now - stamp));
		return 0;
	}

	/*
	 * We timed out ...
	 *
	 * HWP has a complex workaround for HW255321 which affects
	 * Murano DD1 and Venice DD1. Ignore that for now
	 *
	 * Instead we just dump some XSCOMs for error logging
	 */
	prerror("HBRT: Timeout on special wakeup of 0x%0x\n", cpu->pir);
	prerror("HBRT:      PM0 = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);
	prerror("HBRT: SPC_WKUP = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id,
					  EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &val);
	prerror("HBRT:  HISTORY = 0x%016llx\n", val);

	return OPAL_HARDWARE;
}

static int hservice_clr_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val, core_id;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP), 0);
	if (rc) {
		prerror("HBRT: XSCOM error %d deasserting"
			" special wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * The original HWp reads the XSCOM again with the comment
	 * "This puts an inherent delay in the propagation of the reset
	 * transition"
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	return 0;
}

static int hservice_wakeup(uint32_t i_core, uint32_t i_mode)
{
	struct cpu_thread *cpu;
	int rc = OPAL_SUCCESS;

	/*
	 * Mask out the top nibble of i_core since it may contain
	 * 0x4 (which we use for XSCOM targeting)
	 */
	i_core &= 0x0fffffff;

	/* What do we need to do ? */
	switch(i_mode) {
	case 0: /* Assert special wakeup */
		/* XXX Assume P8 */
		cpu = find_cpu_by_pir(i_core << 3);
		if (!cpu)
			return OPAL_PARAMETER;
		prlog(PR_DEBUG, "HBRT: Special wakeup assert for core 0x%x,"
		      " count=%d\n", i_core, cpu->hbrt_spec_wakeup);
		if (cpu->hbrt_spec_wakeup == 0)
			rc = hservice_set_special_wakeup(cpu);
		if (rc == 0)
			cpu->hbrt_spec_wakeup++;
		return rc;
	case 1: /* Deassert special wakeup */
		/* XXX Assume P8 */
		cpu = find_cpu_by_pir(i_core << 3);
		if (!cpu)
			return OPAL_PARAMETER;
		prlog(PR_DEBUG, "HBRT: Special wakeup release for core"
		      " 0x%x, count=%d\n", i_core, cpu->hbrt_spec_wakeup);
		if (cpu->hbrt_spec_wakeup == 0) {
			prerror("HBRT: Special wakeup clear"
				" on core 0x%x with count=0\n",
				i_core);
			return OPAL_WRONG_STATE;
		}
		/* What to do with count on errors ? */
		cpu->hbrt_spec_wakeup--;
		if (cpu->hbrt_spec_wakeup == 0)
			rc = hservice_clr_special_wakeup(cpu);
		return rc;
	case 2: /* Clear all special wakeups */
		prlog(PR_DEBUG, "HBRT: Special wakeup release for all cores\n");
		for_each_cpu(cpu) {
			if (cpu->hbrt_spec_wakeup) {
				cpu->hbrt_spec_wakeup = 0;
				/* What to do on errors ? */
				hservice_clr_special_wakeup(cpu);
			}
		}
		return OPAL_SUCCESS;
	default:
		return OPAL_PARAMETER;
	}
}

static struct host_interfaces hinterface = {
	.interface_version = HOSTBOOT_RUNTIME_INTERFACE_VERSION,
	.puts = hservice_puts,
	.assert = hservice_assert,
	.malloc = hservice_malloc,
	.free = hservice_free,
	.realloc = hservice_realloc,
	.send_error_log = hservice_send_error_log,
	.scom_read = hservice_scom_read,
	.scom_write = hservice_scom_write,
	.lid_load = hservice_lid_load,
	.lid_unload = hservice_lid_unload,
	.get_reserved_mem = hservice_get_reserved_mem,
	.wakeup = hservice_wakeup,
	.nanosleep = hservice_nanosleep,
};

int host_services_occ_load(void)
{
	struct proc_chip *chip;
	int rc = 0;

	prlog(PR_DEBUG, "HBRT: OCC Load requested\n");

	if (!(hservice_runtime && hservice_runtime->loadOCC)) {
		prerror("HBRT: No hservice_runtime->loadOCC\n");
		return -ENOENT;
	}

	for_each_chip(chip) {

		prlog(PR_DEBUG, "HBRT: Calling loadOCC() homer"
		      " %016llx, occ_common_area %016llx, chip %04x\n",
		      chip->homer_base,
		      chip->occ_common_base,
		      chip->id);

		rc = hservice_runtime->loadOCC(chip->homer_base,
						chip->homer_base,
						chip->occ_common_base,
						chip->occ_common_base,
						chip->id);

		hservice_mark();
		prlog(PR_DEBUG, "HBRT: -> rc = %d\n", rc);
	}
	return rc;
}

int host_services_occ_start(void)
{
	struct proc_chip *chip;
	int i, rc = 0, nr_chips=0;
	uint64_t chipids[MAX_CHIPS];

	prlog(PR_INFO, "HBRT: OCC Start requested\n");

	if (!(hservice_runtime && hservice_runtime->startOCCs)) {
		prerror("HBRT: No hservice_runtime->startOCCs\n");
		return -ENOENT;
	}

	for_each_chip(chip) {
		chipids[nr_chips++] = chip->id;
	}

	for (i = 0; i < nr_chips; i++)
		prlog(PR_TRACE, "HBRT: Calling startOCC() for %04llx\n",
		      chipids[i]);

	/* Lets start all OCC */
	rc = hservice_runtime->startOCCs(chipids, nr_chips);
	hservice_mark();
	prlog(PR_DEBUG, "HBRT: startOCCs() rc  = %d\n", rc);
	return rc;
}

int host_services_occ_stop(void)
{
	int i, rc = 0, nr_slaves = 0, nr_masters = 0;
	uint64_t *master_chipids = NULL, *slave_chipids = NULL;

	prlog(PR_INFO, "HBRT: OCC Stop requested\n");

	if (!(hservice_runtime && hservice_runtime->stopOCCs)) {
		prerror("HBRT: No hservice_runtime->stopOCCs\n");
		return -ENOENT;
	}

	rc = find_master_and_slave_occ(&master_chipids, &slave_chipids,
				       &nr_masters, &nr_slaves);
	if (rc)
		goto out;

	for (i = 0; i < nr_slaves; i++)
		prlog(PR_TRACE, "HBRT: Calling stopOCC() for %04llx ",
		      slave_chipids[i]);

	if (!nr_slaves)
		goto master;

	/* Lets STOP all the slave OCC */
	rc = hservice_runtime->stopOCCs(slave_chipids, nr_slaves);
	prlog(PR_DEBUG, "HBRT: stopOCCs() slave rc  = %d\n", rc);

master:
	for (i = 0; i < nr_masters; i++)
		prlog(PR_TRACE, "HBRT: Calling stopOCC() for %04llx ",
		      master_chipids[i]);

	/* Lets STOP all the master OCC */
	rc = hservice_runtime->stopOCCs(master_chipids, nr_masters);

	hservice_mark();
	prlog(PR_DEBUG, "HBRT: stopOCCs() master rc  = %d\n", rc);

out:
	free(master_chipids);
	free(slave_chipids);
	return rc;
}

void host_services_occ_base_setup(void)
{
	struct proc_chip *chip;
	uint64_t occ_common;

	chip = next_chip(NULL); /* Frist chip */
	occ_common = (uint64_t) local_alloc(chip->id, OCC_COMMON_SIZE, OCC_COMMON_SIZE);

	for_each_chip(chip) {
		chip->occ_common_base = occ_common;
		chip->occ_common_size = OCC_COMMON_SIZE;

		chip->homer_base = (uint64_t) local_alloc(chip->id, HOMER_IMAGE_SIZE,
							HOMER_IMAGE_SIZE);
		chip->homer_size = HOMER_IMAGE_SIZE;
		memset((void *)chip->homer_base, 0, chip->homer_size);

		prlog(PR_DEBUG, "HBRT: Chip %d HOMER base %016llx : %08llx\n",
		      chip->id, chip->homer_base, chip->homer_size);
		prlog(PR_DEBUG, "HBRT: OCC common base %016llx : %08llx\n",
		      chip->occ_common_base, chip->occ_common_size);
	}
}

bool hservices_init(void)
{
	void *code = NULL;
	struct runtime_interfaces *(*hbrt_init)(struct host_interfaces *);

	struct function_descriptor {
		void *addr;
		void *toc;
	} fdesc;

	code = (void *)hservice_get_reserved_mem("ibm,hbrt-code-image");
	if (!code) {
		prerror("HBRT: No ibm,hbrt-code-image found.\n");
		return false;
	}

	if (memcmp(code, "HBRTVERS", 8) != 0) {
		prerror("HBRT: Bad eyecatcher for ibm,hbrt-code-image!\n");
		return false;
	}

	prlog(PR_INFO, "HBRT: Found HostBoot Runtime version %llu\n",
	      ((u64 *)code)[1]);

	/* We enter at 0x100 into the image. */
	fdesc.addr = code + 0x100;
	/* It doesn't care about TOC */
	fdesc.toc = NULL;

	hbrt_init = (void *)&fdesc;

	hservice_runtime = hbrt_init(&hinterface);
	hservice_mark();
	if (!hservice_runtime) {
		prerror("HBRT: Host services init failed\n");
		return false;
	}

	prlog(PR_INFO, "HBRT: Interface version %llu\n",
	      hservice_runtime->interface_version);

	return true;
}		
