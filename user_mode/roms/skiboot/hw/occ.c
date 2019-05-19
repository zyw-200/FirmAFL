/* Copyright 2013-2016 IBM Corp.
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
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <fsp.h>
#include <timebase.h>
#include <hostservices.h>
#include <errorlog.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <timer.h>

/* OCC Communication Area for PStates */

#define P8_HOMER_SAPPHIRE_DATA_OFFSET	0x1F8000

#define MAX_PSTATES 256

#define chip_occ_data(chip) \
		((struct occ_pstate_table *)(chip->homer_base + \
				P8_HOMER_SAPPHIRE_DATA_OFFSET))

static bool occ_reset;
static struct lock occ_lock = LOCK_UNLOCKED;

struct occ_pstate_entry {
	s8 id;
	u8 flags;
	u8 vdd;
	u8 vcs;
	u32 freq_khz;
} __packed;

/*
 * OCC-OPAL Shared Memory Region Version 2
 * https://github.com/open-power/occ/blob/master/src/occ/proc/proc_pstate.h
 * Interface defined in 'sapphire_table_t'
 */
struct occ_pstate_table {
	u8 valid;
	u8 version;
	u8 throttle;
	s8 pstate_min;
	s8 pstate_nom;
	s8 pstate_turbo;
	s8 pstate_ultra_turbo;
	u8 spare;
	u64 reserved;
	struct occ_pstate_entry pstates[MAX_PSTATES];
	s8 core_max[16];
} __packed;

DEFINE_LOG_ENTRY(OPAL_RC_OCC_LOAD, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_RESET, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_PSTATE_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_INFO,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_TIMEOUT, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_UNRECOVERABLE_ERR_GENERAL,
		OPAL_NA);

/* Check each chip's HOMER/Sapphire area for PState valid bit */
static bool wait_for_all_occ_init(void)
{
	struct proc_chip *chip;
	uint64_t occ_data_area;
	struct occ_pstate_table *occ_data;
	int tries;
	uint64_t start_time, end_time;
	uint32_t timeout = 0;

	if (platform.occ_timeout)
		timeout = platform.occ_timeout();

	start_time = mftb();
	for_each_chip(chip) {
		/* Check for valid homer address */
		if (!chip->homer_base) {
			/**
			 * @fwts-label OCCInvalidHomerBase
			 * @fwts-advice The HOMER base address for a chip
			 * was not valid. This means that OCC (On Chip
			 * Controller) will be non-functional and CPU
			 * frequency scaling will not be functional. CPU may
			 * be set to a safe, low frequency. Power savings in
			 * CPU idle or CPU hotplug may be impacted.
			 */
			prlog(PR_ERR,"OCC: Chip: %x homer_base is not valid\n",
				chip->id);
			return false;
		}

		if (!chip->occ_functional) {
			prlog(PR_WARNING, "OCC: Chip: %x occ not functional\n",
			      chip->id);
			continue;
		}

		/* Get PState table address */
		occ_data_area = chip->homer_base + P8_HOMER_SAPPHIRE_DATA_OFFSET;
		occ_data = (struct occ_pstate_table *)occ_data_area;

		/*
		 * Checking for occ_data->valid == 1 is ok because we clear all
		 * homer_base+size before passing memory to host services.
		 * This ensures occ_data->valid == 0 before OCC load
		 */
		tries = timeout * 10;
		while((occ_data->valid != 1) && tries--) {
			time_wait_ms(100);
		}
		if (occ_data->valid != 1) {
			/**
			 * @fwts-label OCCInvalidPStateTable
			 * @fwts-advice The pstate table for a chip
			 * was not valid. This means that OCC (On Chip
			 * Controller) will be non-functional and CPU
			 * frequency scaling will not be functional. CPU may
			 * be set to a low, safe frequency. This means
			 * that CPU idle states and CPU frequency scaling
			 * may not be functional.
			 */
			prlog(PR_ERR, "OCC: Chip: %x PState table is not valid\n",
				chip->id);
			return false;
		}
		prlog(PR_DEBUG, "OCC: Chip %02x Data (%016llx) = %016llx\n",
		      chip->id, occ_data_area,
		      *(uint64_t *)occ_data_area);
	}
	end_time = mftb();
	prlog(PR_NOTICE, "OCC: All Chip Rdy after %lld ms\n",
	      (end_time - start_time) / 512 / 1000);
	return true;
}

/* Add device tree properties to describe pstates states */
/* Retrun nominal pstate to set in each core */
static bool add_cpu_pstate_properties(s8 *pstate_nom)
{
	struct proc_chip *chip;
	uint64_t occ_data_area;
	struct occ_pstate_table *occ_data;
	struct dt_node *power_mgt;
	u8 nr_pstates, nr_cores = 0;
	s8 pmax;
	/* Arrays for device tree */
	u32 *dt_id, *dt_freq;
	u8 *dt_vdd, *dt_vcs;
	s8 *dt_core_max = NULL;
	bool rc, ultra_turbo_en;
	int i, j;

	prlog(PR_DEBUG, "OCC: CPU pstate state device tree init\n");

	/* Find first chip and core */
	chip = next_chip(NULL);

	/* Extract PState information from OCC */

	/* Dump state table */
	occ_data_area = chip->homer_base + P8_HOMER_SAPPHIRE_DATA_OFFSET;

	prlog(PR_DEBUG, "OCC: Data (%16llx) = %16llx %16llx\n",
	      occ_data_area,
	      *(uint64_t *)occ_data_area,
	      *(uint64_t *)(occ_data_area+8));
	
	occ_data = (struct occ_pstate_table *)occ_data_area;

	if (!occ_data->valid) {
		/**
		 * @fwts-label OCCInvalidPStateTableDT
		 * @fwts-advice The pstate table for the first chip
		 * was not valid. This means that OCC (On Chip
		 * Controller) will be non-functional. This means
		 * that CPU idle states and CPU frequency scaling
		 * will not be functional as OPAL doesn't populate
		 * the device tree with pstates in this case.
		 */
		prlog(PR_ERR, "OCC: PState table is not valid\n");
		return false;
	}

	if (occ_data->version > 1 &&
	    occ_data->pstate_ultra_turbo > occ_data->pstate_turbo)
		ultra_turbo_en = true;
	else
		ultra_turbo_en = false;

	pmax = ultra_turbo_en ? occ_data->pstate_ultra_turbo :
				occ_data->pstate_turbo;
	nr_pstates = pmax - occ_data->pstate_min + 1;
	prlog(PR_DEBUG, "OCC: Min %d Nom %d Max %d Nr States %d\n", 
	      occ_data->pstate_min, occ_data->pstate_nom,
	      pmax, nr_pstates);

	if (nr_pstates <= 1 || nr_pstates > 128) {
		/**
		 * @fwts-label OCCInvalidPStateRange
		 * @fwts-advice The number of pstates is outside the valid
		 * range (currently <=1 or > 128), so OPAL has not added
		 * pstates to the device tree. This means that OCC (On Chip
		 * Controller) will be non-functional. This means
		 * that CPU idle states and CPU frequency scaling
		 * will not be functional.
		 */
		prlog(PR_ERR, "OCC: OCC range is not valid\n");
		return false;
	}

	power_mgt = dt_find_by_path(dt_root, "/ibm,opal/power-mgt");
	if (!power_mgt) {
		/**
		 * @fwts-label OCCDTNodeNotFound
		 * @fwts-advice Device tree node /ibm,opal/power-mgt not
		 * found. OPAL didn't add pstate information to device tree.
		 * Probably a firmware bug.
		 */
		prlog(PR_ERR, "OCC: dt node /ibm,opal/power-mgt not found\n");
		return false;
	}

	rc = false;

	/* Setup arrays for device-tree */
	/* Allocate memory */
	dt_id = malloc(nr_pstates * sizeof(u32));
	if (!dt_id) {
		/**
		 * @fwts-label OCCdt_idENOMEM
		 * @fwts-advice Out of memory when allocating pstates array.
		 * No Pstates added to device tree, pstates not functional.
		 */
		prlog(PR_ERR, "OCC: dt_id array alloc failure\n");
		goto out;
	}

	dt_freq = malloc(nr_pstates * sizeof(u32));
	if (!dt_freq) {
		/**
		 * @fwts-label OCCdt_freqENOMEM
		 * @fwts-advice Out of memory when allocating pstates array.
		 * No Pstates added to device tree, pstates not functional.
		 */
		prlog(PR_ERR, "OCC: dt_freq array alloc failure\n");
		goto out_free_id;
	}

	dt_vdd = malloc(nr_pstates * sizeof(u8));
	if (!dt_vdd) {
		/**
		 * @fwts-label OCCdt_vddENOMEM
		 * @fwts-advice Out of memory when allocating pstates array.
		 * No Pstates added to device tree, pstates not functional.
		 */
		prlog(PR_ERR, "OCC: dt_vdd array alloc failure\n");
		goto out_free_freq;
	}

	dt_vcs = malloc(nr_pstates * sizeof(u8));
	if (!dt_vcs) {
		/**
		 * @fwts-label OCCdt_vcsENOMEM
		 * @fwts-advice Out of memory when allocating pstates array.
		 * No Pstates added to device tree, pstates not functional.
		 */
		prlog(PR_ERR, "OCC: dt_vcs array alloc failure\n");
		goto out_free_vdd;
	}

	if (ultra_turbo_en) {
		nr_cores = get_available_nr_cores_in_chip(chip->id);
		dt_core_max = malloc(nr_cores * sizeof(s8));
		if (!dt_core_max) {
			/**
			 * @fwts-label OCCdt_core_maxENOMEM
			 * @fwts-advice Out of memory allocating dt_core_max
			 * array. No PStates in Device Tree: non-functional
			 * power/frequency management.
			 */
			prlog(PR_ERR, "OCC: dt_core_max alloc failure\n");
			goto out_free_vcs;
		}

		for (i = 0; i < nr_cores; i++)
			dt_core_max[i] = occ_data->core_max[i];
	}

	for (i = 0, j = 0; i < MAX_PSTATES && j < nr_pstates; i++) {
		if (occ_data->pstates[i].id > pmax ||
		    occ_data->pstates[i].id < occ_data->pstate_min)
			continue;
		dt_id[j] = occ_data->pstates[i].id;
		dt_freq[j] = occ_data->pstates[i].freq_khz / 1000;
		dt_vdd[j] = occ_data->pstates[i].vdd;
		dt_vcs[j] = occ_data->pstates[i].vcs;
		j++;
	}

	/* Add the device-tree entries */
	dt_add_property(power_mgt, "ibm,pstate-ids", dt_id,
			nr_pstates * sizeof(u32));
	dt_add_property(power_mgt, "ibm,pstate-frequencies-mhz", dt_freq,
			nr_pstates * sizeof(u32));
	dt_add_property(power_mgt, "ibm,pstate-vdds", dt_vdd, nr_pstates);
	dt_add_property(power_mgt, "ibm,pstate-vcss", dt_vcs, nr_pstates);
	dt_add_property_cells(power_mgt, "ibm,pstate-min", occ_data->pstate_min);
	dt_add_property_cells(power_mgt, "ibm,pstate-nominal", occ_data->pstate_nom);
	dt_add_property_cells(power_mgt, "ibm,pstate-max", pmax);

	if (ultra_turbo_en) {
		dt_add_property_cells(power_mgt, "ibm,pstate-turbo",
				      occ_data->pstate_turbo);
		dt_add_property_cells(power_mgt, "ibm,pstate-ultra-turbo",
				      occ_data->pstate_ultra_turbo);
		dt_add_property(power_mgt, "ibm,pstate-core-max", dt_core_max,
				nr_cores);
		free(dt_core_max);
	}

	/* Return pstate to set for each core */
	*pstate_nom = occ_data->pstate_nom;
	rc = true;

out_free_vcs:
	free(dt_vcs);
out_free_vdd:
	free(dt_vdd);
out_free_id:
	free(dt_id);
out_free_freq:
	free(dt_freq);
out:
	return rc;
}

/*
 * Prepare chip for pstate transitions
 */

static bool cpu_pstates_prepare_core(struct proc_chip *chip, struct cpu_thread *c, s8 pstate_nom)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp, pstate;
	int rc;

	/*
	 * Currently Fastsleep init clears EX_PM_SPR_OVERRIDE_EN.
	 * Need to ensure only relevant bits are inited
	 */

	/* Init PM GP1 for SCOM based PSTATE control to set nominal freq
	 *
	 * Use the OR SCOM to set the required bits in PM_GP1 register
	 * since the OCC might be mainpulating the PM_GP1 register as well.
	 */ 
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SET_GP1),
			 EX_PM_SETUP_GP1_PM_SPR_OVERRIDE_EN);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}

	/* Set new pstate to core */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMCR), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to read from OCC in pstates init\n");
		return false;
	}
	tmp = tmp & ~0xFFFF000000000000ULL;
	pstate = ((uint64_t) pstate_nom) & 0xFF;
	tmp = tmp | (pstate << 56) | (pstate << 48);
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMCR), tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}
	time_wait_ms(1); /* Wait for PState to change */
	/*
	 * Init PM GP1 for SPR based PSTATE control.
	 * Once OCC is active EX_PM_SETUP_GP1_DPLL_FREQ_OVERRIDE_EN will be
	 * cleared by OCC.  Sapphire need not clear.
	 * However wait for DVFS state machine to become idle after min->nominal
	 * transition initiated above.  If not switch over to SPR control could fail.
	 *
	 * Use the AND SCOM to clear the required bits in PM_GP1 register
	 * since the OCC might be mainpulating the PM_GP1 register as well.
	 */
	tmp = ~EX_PM_SETUP_GP1_PM_SPR_OVERRIDE_EN;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_CLEAR_GP1),
			tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}

	/* Just debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMSR), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to read back setting from OCC"
				 "in pstates init\n");
		return false;
	}
	prlog(PR_DEBUG, "OCC: Chip %x Core %x PPMSR %016llx\n",
	      chip->id, core, tmp);

	/*
	 * If PMSR is still in transition at this point due to PState change
	 * initiated above, then the switchover to SPR may not work.
	 * ToDo: Check for DVFS state machine idle before change.
	 */

	return true;
}

static bool occ_opal_msg_outstanding = false;
static void occ_msg_consumed(void *data __unused)
{
	lock(&occ_lock);
	occ_opal_msg_outstanding = false;
	unlock(&occ_lock);
}

static void occ_throttle_poll(void *data __unused)
{
	struct proc_chip *chip;
	struct occ_pstate_table *occ_data;
	struct opal_occ_msg occ_msg;
	int rc;

	if (!try_lock(&occ_lock))
		return;
	if (occ_reset) {
		int inactive = 0;

		for_each_chip(chip) {
			occ_data = chip_occ_data(chip);
			if (occ_data->valid != 1) {
				inactive = 1;
				break;
			}
		}
		if (!inactive) {
			/*
			 * Queue OCC_THROTTLE with throttle status as 0 to
			 * indicate all OCCs are active after a reset.
			 */
			occ_msg.type = cpu_to_be64(OCC_THROTTLE);
			occ_msg.chip = 0;
			occ_msg.throttle_status = 0;
			rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
					     (uint64_t *)&occ_msg);
			if (!rc)
				occ_reset = false;
		}
	} else {
		if (occ_opal_msg_outstanding)
			goto done;
		for_each_chip(chip) {
			occ_data = chip_occ_data(chip);
			if ((occ_data->valid == 1) &&
			    (chip->throttle != occ_data->throttle) &&
			    (occ_data->throttle <= OCC_MAX_THROTTLE_STATUS)) {
				occ_msg.type = cpu_to_be64(OCC_THROTTLE);
				occ_msg.chip = cpu_to_be64(chip->id);
				occ_msg.throttle_status = cpu_to_be64(occ_data->throttle);
				rc = _opal_queue_msg(OPAL_MSG_OCC, NULL,
						     occ_msg_consumed,
						     3, (uint64_t *)&occ_msg);
				if (!rc) {
					chip->throttle = occ_data->throttle;
					occ_opal_msg_outstanding = true;
					break;
				}
			}
		}
	}
done:
	unlock(&occ_lock);
}

/* CPU-OCC PState init */
/* Called after OCC init on P8 */
void occ_pstates_init(void)
{
	struct proc_chip *chip;
	struct cpu_thread *c;
	s8 pstate_nom;

	/* OCC is P8 only */
	if (proc_gen != proc_gen_p8)
		return;

	chip = next_chip(NULL);
	if (!chip->homer_base) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: No HOMER detected, assuming no pstates\n");
		return;
	}

	/* Wait for all OCC to boot up */
	if(!wait_for_all_occ_init()) {
		log_simple_error(&e_info(OPAL_RC_OCC_TIMEOUT),
			 "OCC: Initialization on all chips did not complete"
			 "(timed out)\n");
		return;
	}

	/*
	 * Check boundary conditions and add device tree nodes
	 * and return nominal pstate to set for the core
	 */
	if (!add_cpu_pstate_properties(&pstate_nom)) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"Skiping core cpufreq init due to OCC error\n");
		return;
	}

	/* Setup host based pstates and set nominal frequency */
	for_each_chip(chip) {
		for_each_available_core_in_chip(c, chip->id) {
			cpu_pstates_prepare_core(chip, c, pstate_nom);
		}
	}

	/* Add opal_poller to poll OCC throttle status of each chip */
	for_each_chip(chip)
		chip->throttle = 0;
	opal_add_poller(occ_throttle_poll, NULL);
}

struct occ_load_req {
	u8 scope;
	u32 dbob_id;
	u32 seq_id;
	struct list_node link;
};
static LIST_HEAD(occ_load_req_list);

int find_master_and_slave_occ(uint64_t **master, uint64_t **slave,
			      int *nr_masters, int *nr_slaves)
{
	struct proc_chip *chip;
	int nr_chips = 0, i;
	uint64_t chipids[MAX_CHIPS];

	for_each_chip(chip) {
		chipids[nr_chips++] = chip->id;
	}

	chip = next_chip(NULL);
	/*
	 * Proc0 is the master OCC for Tuleta/Alpine boxes.
	 * Hostboot expects the pair of chips for MURANO, so pass the sibling
	 * chip id along with proc0 to hostboot.
	 */
	*nr_masters = (chip->type == PROC_CHIP_P8_MURANO) ? 2 : 1;
	*master = (uint64_t *)malloc(*nr_masters * sizeof(uint64_t));

	if (!*master) {
		printf("OCC: master array alloc failure\n");
		return -ENOMEM;
	}

	if (nr_chips - *nr_masters > 0) {
		*nr_slaves = nr_chips - *nr_masters;
		*slave = (uint64_t *)malloc(*nr_slaves * sizeof(uint64_t));
		if (!*slave) {
			printf("OCC: slave array alloc failure\n");
			return -ENOMEM;
		}
	}

	for (i = 0; i < nr_chips; i++) {
		if (i < *nr_masters) {
			*(*master + i) = chipids[i];
			continue;
		}
		*(*slave + i - *nr_masters) = chipids[i];
	}
	return 0;
}

static void occ_queue_load(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct occ_load_req *occ_req;

	occ_req = zalloc(sizeof(struct occ_load_req));
	if (!occ_req) {
		/**
		 * @fwts-label OCCload_reqENOMEM
		 * @fwts-advice ENOMEM while allocating OCC load message.
		 * OCCs not started, consequently no power/frequency scaling
		 * will be functional.
		 */
		prlog(PR_ERR, "OCC: Could not allocate occ_load_req\n");
		return;
	}

	occ_req->scope = scope;
	occ_req->dbob_id = dbob_id;
	occ_req->seq_id = seq_id;
	list_add_tail(&occ_load_req_list, &occ_req->link);
}

static void __occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *stat;
	int rc = -ENOMEM;
	int status_word = 0;
	struct proc_chip *chip = next_chip(NULL);

	/* Call HBRT... */
	rc = host_services_occ_load();

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Load: Fallback to preloaded image\n");
		rc = 0;
	} else if (!rc) {
		struct opal_occ_msg occ_msg = { CPU_TO_BE64(OCC_LOAD), 0, 0 };

		rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
				     (uint64_t *)&occ_msg);
		if (rc)
			prlog(PR_INFO, "OCC: Failed to queue message %d\n",
			      OCC_LOAD);

		/* Success, start OCC */
		rc = host_services_occ_start();
	}
	if (rc) {
		/* If either of hostservices call fail, send fail to FSP */
		/* Find a chip ID to send failure */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			status_word = 0xB500 | (chip->pcid & 0xff);
			break;
		}
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d in load/start OCC\n", rc);
	}

	/* Send a single response for all chips */
	stat = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, status_word, seq_id);
	if (stat)
		rc = fsp_queue_msg(stat, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD STATUS msg", rc);
		fsp_freemsg(stat);
	}
}

void occ_poke_load_queue(void)
{
	struct occ_load_req *occ_req, *next;

	if (list_empty(&occ_load_req_list))
		return;

	list_for_each_safe(&occ_load_req_list, occ_req, next, link) {
		__occ_do_load(occ_req->scope, occ_req->dbob_id,
				occ_req->seq_id);
		list_del(&occ_req->link);
		free(occ_req);
	}
}

static void occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *rsp;
	int rc = -ENOMEM;
	u8 err = 0;

	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCLoadInvalidScope
		 * @fwts-advice Invalid request for loading OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Load message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the load message itself */
	rsp = fsp_mkmsg(FSP_RSP_LOAD_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD reply\n", rc);
		fsp_freemsg(rsp);
		return;
	}

	if (err)
		return;

	/*
	 * Check if hostservices lid caching is complete. If not, queue
	 * the load request.
	 */
	if (!hservices_lid_preload_complete()) {
		occ_queue_load(scope, dbob_id, seq_id);
		return;
	}

	__occ_do_load(scope, dbob_id, seq_id);
}

int occ_msg_queue_occ_reset(void)
{
	struct opal_occ_msg occ_msg = { OCC_RESET, 0, 0 };
	struct proc_chip *chip;
	int rc;

	lock(&occ_lock);
	rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
			     (uint64_t *)&occ_msg);
	if (rc) {
		prlog(PR_INFO, "OCC: Failed to queue OCC_RESET message\n");
		goto out;
	}
	/*
	 * Set 'valid' byte of chip_occ_data to 0 since OCC
	 * may not clear this byte on a reset.
	 * OCC will set the 'valid' byte to 1 when it becomes
	 * active again.
	 */
	for_each_chip(chip) {
		struct occ_pstate_table *occ_data;

		occ_data = chip_occ_data(chip);
		occ_data->valid = 0;
		chip->throttle = 0;
	}
	occ_reset = true;
out:
	unlock(&occ_lock);
	return rc;
}

static void occ_do_reset(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct fsp_msg *rsp, *stat;
	struct proc_chip *chip = next_chip(NULL);
	int rc = -ENOMEM;
	u8 err = 0;

	/* Check arguments */
	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCResetInvalidScope
		 * @fwts-advice Invalid request for resetting OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Reset message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the reset message itself */
	rsp = fsp_mkmsg(FSP_RSP_RESET_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		fsp_freemsg(rsp);
		log_simple_error(&e_info(OPAL_RC_OCC_RESET),
			"OCC: Error %d queueing FSP OCC RESET reply\n", rc);
		return;
	}

	/* If we had an error, return */
	if (err)
		return;

	/*
	 * Call HBRT to stop OCC and leave it stopped.  FSP will send load/start
	 * request subsequently.  Also after few runtime restarts (currently 3),
	 * FSP will request OCC to left in stopped state.
	 */

	rc = host_services_occ_stop();

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Reset: Fallback to preloaded image\n");
		rc = 0;
	}
	if (!rc) {
		/* Send a single success response for all chips */
		stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2, 0, seq_id);
		if (stat)
			rc = fsp_queue_msg(stat, fsp_freemsg);
		if (rc) {
			fsp_freemsg(stat);
			log_simple_error(&e_info(OPAL_RC_OCC_RESET),
				"OCC: Error %d queueing FSP OCC RESET"
					" STATUS message\n", rc);
		}
		occ_msg_queue_occ_reset();
	} else {

		/*
		 * Then send a matching OCC Reset Status message with an 0xFE
		 * (fail) response code as well to the first matching chip
		 */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			rc = -ENOMEM;
			stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2,
					 0xfe00 | (chip->pcid & 0xff), seq_id);
			if (stat)
				rc = fsp_queue_msg(stat, fsp_freemsg);
			if (rc) {
				fsp_freemsg(stat);
				log_simple_error(&e_info(OPAL_RC_OCC_RESET),
					"OCC: Error %d queueing FSP OCC RESET"
						" STATUS message\n", rc);
			}
			break;
		}
	}
}

#define PV_OCC_GP0		0x01000000
#define PV_OCC_GP0_AND		0x01000004
#define PV_OCC_GP0_OR		0x01000005
#define PV_OCC_GP0_PNOR_OWNER	PPC_BIT(18) /* 1 = OCC / Host, 0 = BMC */

static void occ_pnor_set_one_owner(uint32_t chip_id, enum pnor_owner owner)
{
	uint64_t reg, mask;

	if (owner == PNOR_OWNER_HOST) {
		reg = PV_OCC_GP0_OR;
		mask = PV_OCC_GP0_PNOR_OWNER;
	} else {
		reg = PV_OCC_GP0_AND;
		mask = ~PV_OCC_GP0_PNOR_OWNER;
	}

	xscom_write(chip_id, reg, mask);
}

void occ_pnor_set_owner(enum pnor_owner owner)
{
	struct proc_chip *chip;

	for_each_chip(chip)
		occ_pnor_set_one_owner(chip->id, owner);
}

static bool fsp_occ_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 dbob_id, seq_id;
	u8 scope;

	switch (cmd_sub_mod) {
	case FSP_CMD_LOAD_OCC:
		/*
		 * We get the "Load OCC" command at boot. We don't currently
		 * support loading it ourselves (we don't have the procedures,
		 * they will come with Host Services). For now HostBoot will
		 * have loaded a OCC firmware for us, but we still need to
		 * be nice and respond to OCC.
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		prlog(PR_INFO, "OCC: Got OCC Load message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_load(scope, dbob_id, seq_id);
		return true;

	case FSP_CMD_RESET_OCC:
		/*
		 * We shouldn't be getting this one, but if we do, we have
		 * to reply something sensible or the FSP will get upset
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		prlog(PR_INFO, "OCC: Got OCC Reset message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_reset(scope, dbob_id, seq_id);
		return true;
	}
	return false;
}

static struct fsp_client fsp_occ_client = {
	.message = fsp_occ_msg,
};

#define OCB_OCI_OCCMISC		0x6a020
#define OCB_OCI_OCCMISC_AND	0x6a021
#define OCB_OCI_OCCMISC_OR	0x6a022
#define OCB_OCI_OCIMISC_IRQ		PPC_BIT(0)
#define OCB_OCI_OCIMISC_IRQ_TMGT	PPC_BIT(1)
#define OCB_OCI_OCIMISC_IRQ_SLW_TMR	PPC_BIT(14)
#define OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY	PPC_BIT(15)
#define OCB_OCI_OCIMISC_MASK		(OCB_OCI_OCIMISC_IRQ_TMGT | \
					 OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY | \
					 OCB_OCI_OCIMISC_IRQ_SLW_TMR)

void occ_send_dummy_interrupt(void)
{
	struct psi *psi;
	struct proc_chip *chip = get_chip(this_cpu()->chip_id);

	/* Emulators and P7 doesn't do this */
	if (proc_gen != proc_gen_p8 || chip_quirk(QUIRK_NO_OCC_IRQ))
		return;

	/* Find a functional PSI. This ensures an interrupt even if
	 * the psihb on the current chip is not configured */
	if (chip->psi)
		psi = chip->psi;
	else
		psi = psi_find_functional_chip();

	if (!psi) {
		prlog_once(PR_WARNING, "PSI: no functional PSI HB found, "
				       "no self interrupts delivered\n");
		return;
	}

	xscom_write(psi->chip_id, OCB_OCI_OCCMISC_OR,
		    OCB_OCI_OCIMISC_IRQ | OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY);
}

void occ_interrupt(uint32_t chip_id)
{
	uint64_t ireg;
	int64_t rc;

	/* The OCC interrupt is used to mux up to 15 different sources */
	rc = xscom_read(chip_id, OCB_OCI_OCCMISC, &ireg);
	if (rc) {
		prerror("OCC: Failed to read interrupt status !\n");
		/* Should we mask it in the XIVR ? */
		return;
	}
	prlog(PR_TRACE, "OCC: IRQ received: %04llx\n", ireg >> 48);

	/* Clear the bits */
	xscom_write(chip_id, OCB_OCI_OCCMISC_AND, ~ireg);

	/* Dispatch */
	if (ireg & OCB_OCI_OCIMISC_IRQ_TMGT)
		prd_tmgt_interrupt(chip_id);
	if (ireg & OCB_OCI_OCIMISC_IRQ_SLW_TMR)
		check_timers(true);

	/* We may have masked-out OCB_OCI_OCIMISC_IRQ in the previous
	 * OCCMISC_AND write. Check if there are any new source bits set,
	 * and trigger another interrupt if so.
	 */
	rc = xscom_read(chip_id, OCB_OCI_OCCMISC, &ireg);
	if (!rc && (ireg & OCB_OCI_OCIMISC_MASK))
		xscom_write(chip_id, OCB_OCI_OCCMISC_OR, OCB_OCI_OCIMISC_IRQ);
}

void occ_fsp_init(void)
{
	/* OCC is P8 only */
	if (proc_gen != proc_gen_p8)
		return;

	/* If we have an FSP, register for notifications */
	if (fsp_present())
		fsp_register_client(&fsp_occ_client, FSP_MCLASS_OCC);
}


