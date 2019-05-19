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

/*
 * Handle ChipTOD chip & configure core timebases
 */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <chiptod.h>
#include <interrupts.h>
#include <timebase.h>
#include <errorlog.h>
#include <libfdt/libfdt.h>
#include <opal-api.h>

#ifdef __HAVE_LIBPORE__
#include <p8_pore_table_gen_api.H>
#include <sbe_xip_image.h>

#define MAX_RESET_PATCH_SIZE	64

static uint32_t slw_saved_reset[MAX_RESET_PATCH_SIZE];

static bool slw_current_le = false;
#endif /* __HAVE_LIBPORE__ */

/* SLW timer related stuff */
static bool slw_has_timer;
static uint64_t slw_timer_inc;
static uint64_t slw_timer_target;
static uint32_t slw_timer_chip;
static uint64_t slw_last_gen;
static uint64_t slw_last_gen_stamp;

/* Assembly in head.S */
extern void enter_rvwinkle(void);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_SET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_GET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_REG, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

#ifdef __HAVE_LIBPORE__
static void slw_do_rvwinkle(void *data)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_thread *master = data;
	uint64_t lpcr = mfspr(SPR_LPCR);
	struct proc_chip *chip;

	/* Setup our ICP to receive IPIs */
	icp_prep_for_rvwinkle();

	/* Setup LPCR to wakeup on external interrupts only */
	mtspr(SPR_LPCR, ((lpcr & ~SPR_LPCR_P8_PECE) | SPR_LPCR_P8_PECE2));

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x goint to rvwinkle...\n",
	      cpu->pir);

	/* Tell that we got it */
	cpu->state = cpu_state_rvwinkle;

	enter_rvwinkle();

	/* Ok, it's ours again */
	cpu->state = cpu_state_active;

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x woken up !\n", cpu->pir);

	/* Cleanup our ICP */
	reset_cpu_icp();

	/* Resync timebase */
	chiptod_wakeup_resync();

	/* Restore LPCR */
	mtspr(SPR_LPCR, lpcr);

	/* If we are passed a master pointer we are the designated
	 * waker, let's proceed. If not, return, we are finished.
	 */
	if (!master)
		return;

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x waiting for master...\n",
	      cpu->pir);

	/* Allriiiight... now wait for master to go down */
	while(master->state != cpu_state_rvwinkle)
		sync();

	/* XXX Wait one second ! (should check xscom state ? ) */
	time_wait_ms(1000);

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							EX_PM_IDLE_STATE_HISTORY_PHYP),
				   &tmp);	
			prlog(PR_TRACE, "SLW: core %x:%x"
			      " history: 0x%016llx (mid2)\n",
			      chip->id, pir_to_core_id(c->pir),
			      tmp);
		}
	}

	prlog(PR_DEBUG, "SLW: Waking master (PIR 0x%04x)...\n", master->pir);

	/* Now poke all the secondary threads on the master's core */
	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, master) || (cpu == master))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Now poke the master and be gone */
	icp_kick_cpu(master);
}

static void slw_patch_reset(void)
{
	extern uint32_t rvwinkle_patch_start;
	extern uint32_t rvwinkle_patch_end;
	uint32_t *src, *dst, *sav;

	BUILD_ASSERT((&rvwinkle_patch_end - &rvwinkle_patch_start) <=
		     MAX_RESET_PATCH_SIZE);

	src = &rvwinkle_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &rvwinkle_patch_end) {
		*(sav++) = *(dst);
		*(dst++) = *(src++);
	}
	sync_icache();
}

static void slw_unpatch_reset(void)
{
	extern uint32_t rvwinkle_patch_start;
	extern uint32_t rvwinkle_patch_end;
	uint32_t *src, *dst, *sav;

	src = &rvwinkle_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &rvwinkle_patch_end) {
		*(dst++) = *(sav++);
		src++;
	}
	sync_icache();
}
#endif /* __HAVE_LIBPORE__ */

static bool slw_general_init(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* PowerManagement GP0 clear PM_DISABLE */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to read PM_GP0\n");
		return false;
	}
	tmp = tmp & ~0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to write PM_GP0\n");
		return false;
	}
	prlog(PR_TRACE, "SLW: PMGP0 set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc)
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				 "SLW: Failed to re-read PM_GP0. Continuing...\n");

	prlog(PR_TRACE, "SLW: PMGP0 read   0x%016llx\n", tmp);

	return true;
}

static bool slw_set_overrides(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/*
	 * Set ENABLE_IGNORE_RECOV_ERRORS in OHA_MODE_REG
	 *
	 * XXX FIXME: This should be only done for "forced" winkle such as
	 * when doing repairs or LE transition, and we should restore the
	 * original value when done
	 */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
				"SLW: Failed to read PM_OHA_MODE_REG\n");
		return false;
	}
	tmp = tmp | 0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),
			 tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
				"SLW: Failed to write PM_OHA_MODE_REG\n");
		return false;
	}
	prlog(PR_TRACE, "SLW: PM_OHA_MODE_REG set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),&tmp);
	prlog(PR_TRACE, "SLW: PM_OHA_MODE_REG read   0x%016llx\n", tmp);

	/*
	 * Clear special wakeup bits that could hold power mgt
	 *
	 * XXX FIXME: See above
	 */
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SPECIAL_WAKEUP_FSP),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write PM_SPECIAL_WAKEUP_FSP\n");
		return false;
	}
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SPECIAL_WAKEUP_OCC),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write PM_SPECIAL_WAKEUP_OCC\n");
		return false;
	}
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SPECIAL_WAKEUP_PHYP),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write PM_SPECIAL_WAKEUP_PHYP\n");
		return false;
	}

	return true;
}

#ifdef __HAVE_LIBPORE__
static bool slw_unset_overrides(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);

	/* XXX FIXME: Save and restore the overrides */
	prlog(PR_DEBUG, "SLW: slw_unset_overrides %x:%x\n", chip->id, core);
	return true;
}
#endif /* __HAVE_LIBPORE__ */

static bool slw_set_idle_mode(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/*
	 * PM GP1 allows fast/deep mode to be selected independently for sleep
	 * and winkle. Init PM GP1 so that sleep happens in fast mode and
	 * winkle happens in deep mode.
	 * Make use of the OR XSCOM for this since the OCC might be manipulating
	 * the PM_GP1 register as well. Before doing this ensure that the bits
	 * managing idle states are cleared so as to override any bits set at
	 * init time.
	 */

	tmp = ~EX_PM_GP1_SLEEP_WINKLE_MASK;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_CLEAR_GP1),
			 tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SET_GP1),
			 EX_PM_SETUP_GP1_FAST_SLEEP_DEEP_WINKLE);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	/* Read back for debug */
	xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP1), &tmp);
	prlog(PR_TRACE, "SLW: PMGP1 read   0x%016llx\n", tmp);
	return true;
}

static bool slw_get_idle_state_history(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* Cleanup history */
	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old1)\n",
	    chip->id, core, tmp);

	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old2)\n",
	    chip->id, core, tmp);

	return true;
}

static bool idle_prepare_core(struct proc_chip *chip, struct cpu_thread *c)
{
	prlog(PR_TRACE, "FASTSLEEP: Prepare core %x:%x\n",
	    chip->id, pir_to_core_id(c->pir));

	if(!slw_general_init(chip, c))
		return false;
	if(!slw_set_overrides(chip, c))
		return false;
	if(!slw_set_idle_mode(chip, c))
		return false;
	if(!slw_get_idle_state_history(chip, c))
		return false;

	return true;

}

/* Define device-tree fields */
#define MAX_NAME_LEN	16
struct cpu_idle_states {
	char name[MAX_NAME_LEN];
	u32 latency_ns;
	u32 residency_ns;
	/*
	 * Register value/mask used to select different idle states.
	 * PMICR in POWER8 and PSSCR in POWER9
	 */
	u64 pm_ctrl_reg_val;
	u64 pm_ctrl_reg_mask;
	u32 flags;
};

static struct cpu_idle_states power7_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_PM_SLEEP_ENABLED \
		       | 0*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

static struct cpu_idle_states power8_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
	{ /* fast sleep (with workaround) */
		.name = "fastsleep_",
		.latency_ns = 40000,
		.residency_ns = 300000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_SLEEP_ENABLED_ER1 \
		       | 0*OPAL_USE_PMICR, /* Not enabled until deep
						states are available */
		.pm_ctrl_reg_val = OPAL_PM_FASTSLEEP_PMICR,
		.pm_ctrl_reg_mask = OPAL_PM_SLEEP_PMICR_MASK },
	{ /* Winkle */
		.name = "winkle",
		.latency_ns = 10000000,
		.residency_ns = 1000000000, /* Educated guess (not measured).
					     * Winkle is not currently used by 
					     * linux cpuidle subsystem so we
					     * don't have real world user.
					     * However, this should be roughly
					     * accurate for when linux does
					     * use it. */
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR, /* Currently choosing deep vs
						fast via EX_PM_GP1 reg */
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

/*
 * cpu_idle_states for key idle states of POWER9 that we want to
 * exploit.
 * Note latency_ns and residency_ns are estimated values for now.
 */
static struct cpu_idle_states power9_cpu_idle_states[] = {
	{
		.name = "stop0",
		.latency_ns = 300,
		.residency_ns = 3000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0xF },
	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = 1,
		.pm_ctrl_reg_mask = 0xF },
	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = 2,
		.pm_ctrl_reg_mask = 0xF },

	{
		.name = "stop4",
		.latency_ns = 100000,
		.residency_ns = 1000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = 4,
		.pm_ctrl_reg_mask = 0xF },

	{
		.name = "stop8",
		.latency_ns = 2000000,
		.residency_ns = 20000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = 0x8,
		.pm_ctrl_reg_mask = 0xF },


	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = 0xB,
		.pm_ctrl_reg_mask = 0xF },

};
/* Add device tree properties to describe idle states */
void add_cpu_idle_state_properties(void)
{
	struct dt_node *power_mgt;
	struct cpu_idle_states *states;
	struct proc_chip *chip;
	int nr_states;

	bool can_sleep = true;
	bool has_slw = true;
	bool has_stop_inst = false;
	u8 i;

	u64 *pm_ctrl_reg_val_buf;
	u64 *pm_ctrl_reg_mask_buf;
	u32 supported_states_mask;

	/* Variables to track buffer length */
	u8 name_buf_len;
	u8 num_supported_idle_states;

	/* Buffers to hold idle state properties */
	char *name_buf, *alloced_name_buf;
	u32 *latency_ns_buf;
	u32 *residency_ns_buf;
	u32 *flags_buf;


	prlog(PR_DEBUG, "CPU idle state device tree init\n");

	/* Create /ibm,opal/power-mgt */
	power_mgt = dt_new(opal_node, "power-mgt");
	if (!power_mgt) {
		/**
		 * @fwts-label CreateDTPowerMgtNodeFail
		 * @fwts-advice OPAL failed to add the power-mgt device tree
		 * node. This could mean that firmware ran out of memory,
		 * or there's a bug somewhere.
		 */
		prlog(PR_ERR, "creating dt node /ibm,opal/power-mgt failed\n");
		return;
	}

	/*
	 * Chose the right state table for the chip
	 *
	 * XXX We use the first chip version, we should probably look
	 * for the smaller of all chips instead..
	 */
	chip = next_chip(NULL);
	assert(chip);
	if (chip->type == PROC_CHIP_P9_NIMBUS ||
	    chip->type == PROC_CHIP_P9_CUMULUS) {
		states = power9_cpu_idle_states;
		nr_states = ARRAY_SIZE(power9_cpu_idle_states);
		has_stop_inst = true;
	} else if (chip->type == PROC_CHIP_P8_MURANO ||
	    chip->type == PROC_CHIP_P8_VENICE ||
	    chip->type == PROC_CHIP_P8_NAPLES) {
		const struct dt_property *p;

		p = dt_find_property(dt_root, "ibm,enabled-idle-states");
		if (p)
			prlog(PR_WARNING,
			      "SLW: HB-provided idle states property found\n");
		states = power8_cpu_idle_states;
		nr_states = ARRAY_SIZE(power8_cpu_idle_states);

		/* Check if hostboot say we can sleep */
		if (!p || !dt_prop_find_string(p, "fast-sleep")) {
			prlog(PR_NOTICE, "SLW: Sleep not enabled by HB"
			      " on this platform\n");
			can_sleep = false;
		}

		/* Clip to NAP only on Murano and Venice DD1.x */
		if ((chip->type == PROC_CHIP_P8_MURANO ||
		     chip->type == PROC_CHIP_P8_VENICE) &&
		    chip->ec_level < 0x20) {
			prlog(PR_NOTICE, "SLW: Sleep not enabled on P8 DD1.x\n");
			can_sleep = false;
		}

	} else {
		states = power7_cpu_idle_states;
		nr_states = ARRAY_SIZE(power7_cpu_idle_states);
	}

	/* Enable deep idle states only if slw image is intact */
	has_slw = (chip->slw_base && chip->slw_bar_size &&
			chip->slw_image_size);

	/*
	 * Currently we can't append strings and cells to dt properties.
	 * So create buffers to which you can append values, then create
	 * dt properties with this buffer content.
	 */

	/* Allocate memory to idle state property buffers. */
	alloced_name_buf= malloc(nr_states * sizeof(char) * MAX_NAME_LEN);
	name_buf = alloced_name_buf;
	latency_ns_buf	= malloc(nr_states * sizeof(u32));
	residency_ns_buf= malloc(nr_states * sizeof(u32));
	flags_buf	= malloc(nr_states * sizeof(u32));
	pm_ctrl_reg_val_buf	= malloc(nr_states * sizeof(u64));
	pm_ctrl_reg_mask_buf	= malloc(nr_states * sizeof(u64));

	name_buf_len = 0;
	num_supported_idle_states = 0;

	/*
	 * Create a mask with the flags of all supported idle states
	 * set. Use this to only add supported idle states to the
	 * device-tree
	 */
	if (has_stop_inst) {
		/* Power 9 / POWER ISA 3.0 */
		supported_states_mask = OPAL_PM_STOP_INST_FAST;
		if (has_slw)
			supported_states_mask |= OPAL_PM_STOP_INST_DEEP;
	} else {
		/* Power 7 and Power 8 */
		supported_states_mask = OPAL_PM_NAP_ENABLED;
		if (can_sleep)
			supported_states_mask |= OPAL_PM_SLEEP_ENABLED |
						OPAL_PM_SLEEP_ENABLED_ER1;
		if (has_slw)
			supported_states_mask |= OPAL_PM_WINKLE_ENABLED;
	}
	for (i = 0; i < nr_states; i++) {
		/* For each state, check if it is one of the supported states. */
		if (!(states[i].flags & supported_states_mask))
			continue;

		/*
		 * If a state is supported add each of its property
		 * to its corresponding property buffer.
		 */
		strncpy(name_buf, states[i].name, MAX_NAME_LEN);
		name_buf = name_buf + strlen(states[i].name) + 1;

		*latency_ns_buf = cpu_to_fdt32(states[i].latency_ns);
		latency_ns_buf++;

		*residency_ns_buf = cpu_to_fdt32(states[i].residency_ns);
		residency_ns_buf++;

		*flags_buf = cpu_to_fdt32(states[i].flags);
		flags_buf++;

		*pm_ctrl_reg_val_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_val);
		pm_ctrl_reg_val_buf++;

		*pm_ctrl_reg_mask_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_mask);
		pm_ctrl_reg_mask_buf++;

		/* Increment buffer length trackers */
		name_buf_len += strlen(states[i].name) + 1;
		num_supported_idle_states++;

	}

	/* Point buffer pointers back to beginning of the buffer */
	name_buf -= name_buf_len;
	latency_ns_buf -= num_supported_idle_states;
	residency_ns_buf -= num_supported_idle_states;
	flags_buf -= num_supported_idle_states;
	pm_ctrl_reg_val_buf -= num_supported_idle_states;
	pm_ctrl_reg_mask_buf -= num_supported_idle_states;
	/* Create dt properties with the buffer content */
	dt_add_property(power_mgt, "ibm,cpu-idle-state-names", name_buf,
			name_buf_len* sizeof(char));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-latencies-ns",
			latency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-residency-ns",
			residency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-flags", flags_buf,
			num_supported_idle_states * sizeof(u32));

	if (has_stop_inst) {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	} else {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	}
	assert(alloced_name_buf == name_buf);
	free(alloced_name_buf);
	free(latency_ns_buf);
	free(residency_ns_buf);
	free(flags_buf);
	free(pm_ctrl_reg_val_buf);
	free(pm_ctrl_reg_mask_buf);
}

#ifdef __HAVE_LIBPORE__
static void slw_cleanup_core(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;

	/* Display history to check transition */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       EX_PM_IDLE_STATE_HISTORY_PHYP),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	prlog(PR_DEBUG, "SLW: core %x:%x history: 0x%016llx (new1)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       EX_PM_IDLE_STATE_HISTORY_PHYP),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	prlog(PR_DEBUG, "SLW: core %x:%x history: 0x%016llx (new2)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	/*
	 * XXX FIXME: Error out if the transition didn't reach rvwinkle ?
	 */

	/*
	 * XXX FIXME: We should restore a bunch of the EX bits we
	 * overwrite to sane values here
	 */
	slw_unset_overrides(chip, c);
}

static void slw_cleanup_chip(struct proc_chip *chip)
{
	struct cpu_thread *c;

	for_each_available_core_in_chip(c, chip->id)
		slw_cleanup_core(chip, c);
}

static void slw_patch_scans(struct proc_chip *chip, bool le_mode)
{
	int64_t rc;
	uint64_t old_val, new_val;

	rc = sbe_xip_get_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", &old_val);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to read scan override on chip %d\n",
			chip->id);
		return;
	}

	new_val = le_mode ? 0 : 1;

	prlog(PR_TRACE, "SLW: Chip %d, LE value was: %lld, setting to %lld\n",
	    chip->id, old_val, new_val);

	rc = sbe_xip_set_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", new_val);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set LE mode on chip %d\n", chip->id);
		return;
	}
}
#else
static inline void slw_patch_scans(struct proc_chip *chip __unused,
				   bool le_mode __unused ) { }
#endif /* __HAVE_LIBPORE__ */

#ifndef __HAVE_LIBPORE__
int64_t __attrconst slw_reinit(uint64_t flags)
{
	(void)flags;
	return OPAL_UNSUPPORTED;
}
#else
int64_t slw_reinit(uint64_t flags)
{
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	bool has_waker = false;
	bool target_le = slw_current_le;

	if (proc_gen < proc_gen_p8)
		return OPAL_UNSUPPORTED;

	if (flags & OPAL_REINIT_CPUS_HILE_BE)
		target_le = false;
	if (flags & OPAL_REINIT_CPUS_HILE_LE)
		target_le = true;

	prlog(PR_TRACE, "SLW Reinit from CPU PIR 0x%04x,"
	      " HILE set to %s endian...\n",
	      this_cpu()->pir,
	      target_le ? "little" : "big");

	/* Prepare chips/cores for rvwinkle */
	for_each_chip(chip) {
		if (!chip->slw_base) {
			log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Not found on chip %d\n", chip->id);
			return OPAL_HARDWARE;
		}

		slw_patch_scans(chip, target_le);
	}
	slw_current_le = target_le;

	/* XXX Save HIDs ? Or do that in head.S ... */

	slw_patch_reset();

	/* rvwinkle everybody and pick one to wake me once I rvwinkle myself */
	for_each_available_cpu(cpu) {
		struct cpu_thread *master = NULL;

		if (cpu == this_cpu())
			continue;

		/* Pick up a waker for myself: it must not be a sibling of
		 * the current CPU and must be a thread 0 (so it gets to
		 * sync its timebase before doing time_wait_ms()
		 */
		if (!has_waker && !cpu_is_sibling(cpu, this_cpu()) &&
		    cpu_is_thread0(cpu)) {
			has_waker = true;
			master = this_cpu();
		}
		__cpu_queue_job(cpu, "slw_do_rvwinkle",
				slw_do_rvwinkle, master, true);

		/* Wait for it to claim to be down */
		while(cpu->state != cpu_state_rvwinkle)
			sync();		
	}

	/* XXX Wait one second ! (should check xscom state ? ) */
	prlog(PR_TRACE, "SLW: Waiting one second...\n");
	time_wait_ms(1000);
	prlog(PR_TRACE, "SLW: Done.\n");

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							EX_PM_IDLE_STATE_HISTORY_PHYP),
				   &tmp);
			prlog(PR_DEBUG, "SLW: core %x:%x"
			      " history: 0x%016llx (mid)\n",
			      chip->id, pir_to_core_id(c->pir), tmp);
		}
	}


	/* Wake everybody except on my core */
	for_each_cpu(cpu) {
		if (cpu->state != cpu_state_rvwinkle ||
		    cpu_is_sibling(cpu, this_cpu()))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Did we find a waker ? If we didn't, that means we had no
	 * other core in the system, we can't do it
	 */
	if (!has_waker) {
		prlog(PR_TRACE, "SLW: No candidate waker, giving up !\n");
		return OPAL_HARDWARE;
	}

	/* Our siblings are rvwinkling, and our waker is waiting for us
	 * so let's just go down now
	 */
	slw_do_rvwinkle(NULL);

	slw_unpatch_reset();

	for_each_chip(chip)
		slw_cleanup_chip(chip);

	prlog(PR_TRACE, "SLW Reinit complete !\n");

	return OPAL_SUCCESS;
}
#endif /* __HAVE_LIBPORE__ */

#ifdef __HAVE_LIBPORE__
static void slw_patch_regs(struct proc_chip *chip)
{
	struct cpu_thread *c;
	void *image = (void *)chip->slw_base;
	int rc;

	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
	
		/* Clear HRMOR */
		rc =  p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM,
					       P8_SPR_HRMOR, 0,
					       cpu_get_core_index(c),
					       cpu_get_thread_index(c));
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
				"SLW: Failed to set HRMOR for CPU %x\n",
				c->pir);
		}

		/* XXX Add HIDs etc... */
	}
}
#endif /* __HAVE_LIBPORE__ */

static void slw_init_chip(struct proc_chip *chip)
{
	int64_t rc;
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);

	if (!chip->slw_base) {
		prerror("SLW: No image found !\n");
		return;
	}

#ifdef __HAVE_LIBPORE__
	/* Check actual image size */
	rc = sbe_xip_get_scalar((void *)chip->slw_base, "image_size",
				&chip->slw_image_size);
	if (rc != 0) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Error %lld reading SLW image size\n", rc);
		/* XXX Panic ? */
		chip->slw_base = 0;
		chip->slw_bar_size = 0;
		chip->slw_image_size = 0;
		return;
	}
	prlog(PR_DEBUG, "SLW: Image size from image: 0x%llx\n",
	      chip->slw_image_size);

	if (chip->slw_image_size > chip->slw_bar_size) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Built-in image size larger than BAR size !\n");
		/* XXX Panic ? */
	}

	/* Patch SLW image */
        slw_patch_regs(chip);
#endif /* __HAVE_LIBPORE__ */

	/* At power ON setup inits for fast-sleep */
	for_each_available_core_in_chip(c, chip->id) {
		idle_prepare_core(chip, c);
	}
}

/* Workarounds while entering fast-sleep */

static void fast_sleep_enter(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	uint64_t tmp;
	int rc;

	primary_thread = this_cpu()->primary;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(1):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

	primary_thread->save_l2_fir_action1 = tmp;
	tmp = tmp & ~0x0200000000000000ULL;
	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			 tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(2):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(3):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

}

/* Workarounds while exiting fast-sleep */

static void fast_sleep_exit(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	int rc;

	primary_thread = this_cpu()->primary;

	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			primary_thread->save_l2_fir_action1);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_exit XSCOM failed:"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
}

/*
 * Setup and cleanup method for fast-sleep workarounds
 * state = 1 fast-sleep
 * enter = 1 Enter state
 * exit  = 0 Exit state
 */

static int64_t opal_config_cpu_idle_state(uint64_t state, uint64_t enter)
{
	/* Only fast-sleep for now */
	if (state != 1)
		return OPAL_PARAMETER;	

	switch(enter) {
	case 1:
		fast_sleep_enter();
		break;
	case 0:
		fast_sleep_exit();
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

opal_call(OPAL_CONFIG_CPU_IDLE_STATE, opal_config_cpu_idle_state, 2);

#ifdef __HAVE_LIBPORE__
static int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val)
{

	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	struct proc_chip *chip = get_chip(c->chip_id);
	void *image = (void *) chip->slw_base;
	int rc;
	int i;
	int spr_is_supported = 0;
	/* Check of the SPR is supported by libpore */
	for ( i=0; i < SLW_SPR_REGS_SIZE ; i++)  {
		if (sprn == SLW_SPR_REGS[i].value)  {
			spr_is_supported = 1;
			break;
		}
	}
	if (!spr_is_supported) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Trying to set unsupported spr for CPU %x\n",
			c->pir);
		return OPAL_UNSUPPORTED;
	}

	rc = p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM, sprn,
						val, cpu_get_core_index(c),
						cpu_get_thread_index(c));

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set spr for CPU %x\n",
			c->pir);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_SUCCESS;

}

opal_call(OPAL_SLW_SET_REG, opal_slw_set_reg, 3);
#endif /* __HAVE_LIBPORE__ */

static void slw_dump_timer_ffdc(void)
{
	uint64_t i, val;
	int64_t rc;

	static const uint32_t dump_regs[] = {
		0xe0000, 0xe0001, 0xe0002, 0xe0003,
		0xe0004, 0xe0005, 0xe0006, 0xe0007,
		0xe0008, 0xe0009, 0xe000a, 0xe000b,
		0xe000c, 0xe000d, 0xe000e, 0xe000f,
		0xe0010, 0xe0011, 0xe0012, 0xe0013,
		0xe0014, 0xe0015, 0xe0016, 0xe0017,
		0xe0018, 0xe0019,
		0x5001c,
		0x50038, 0x50039, 0x5003a, 0x5003b
	};

	/**
	 * @fwts-label SLWRegisterDump
	 * @fwts-advice An error condition occured in sleep/winkle
	 * engines timer state machine. Dumping debug information to
	 * root-cause. OPAL/skiboot may be stuck on some operation that
	 * requires SLW timer state machine (e.g. core powersaving)
	 */
	prlog(PR_DEBUG, "SLW: Register state:\n");

	for (i = 0; i < ARRAY_SIZE(dump_regs); i++) {
		uint32_t reg = dump_regs[i];
		rc = xscom_read(slw_timer_chip, reg, &val);
		if (rc) {
			prlog(PR_DEBUG, "SLW: XSCOM error %lld reading"
			      " reg 0x%x\n", rc, reg);
			break;
		}
		prlog(PR_DEBUG, "SLW:  %5x = %016llx\n", reg, val);
	}
}

/* This is called with the timer lock held, so there is no
 * issue with re-entrancy or concurrence
 */
void slw_update_timer_expiry(uint64_t new_target)
{
	uint64_t count, gen, gen2, req, now = mftb();
	int64_t rc;

	if (!slw_has_timer || new_target == slw_timer_target)
		return;

	slw_timer_target = new_target;

	/* Calculate how many increments from now, rounded up */
	if (now < new_target)
		count = (new_target - now + slw_timer_inc - 1) / slw_timer_inc;
	else
		count = 1;

	/* Max counter is 24-bit */
	if (count > 0xffffff)
		count = 0xffffff;
	/* Fabricate update request */
	req = (1ull << 63) | (count << 32);

	prlog(PR_TRACE, "SLW: TMR expiry: 0x%llx, req: %016llx\n", count, req);

	do {
		/* Grab generation and spin if odd */
		for (;;) {
			rc = xscom_read(slw_timer_chip, 0xE0006, &gen);
			if (rc) {
				prerror("SLW: Error %lld reading tmr gen "
					" count\n", rc);
				return;
			}
			if (!(gen & 1))
				break;
			if (tb_compare(now + msecs_to_tb(1), mftb()) == TB_ABEFOREB) {
				/**
				 * @fwts-label SLWTimerStuck
				 * @fwts-advice The SLeep/Winkle Engine (SLW)
				 * failed to increment the generation number
				 * within our timeout period (it *should* have
				 * done so within ~10us, not >1ms. OPAL uses
				 * the SLW timer to schedule some operations,
				 * but can fall back to the (much less frequent
				 * OPAL poller, which although does not affect
				 * functionality, runs *much* less frequently.
				 * This could have the effect of slow I2C
				 * operations (for example). It may also mean
				 * that you *had* an increase in jitter, due
				 * to slow interactions with SLW.
				 * This error may also occur if the machine
				 * is connected to via soft FSI.
				 */
				prerror("SLW: timer stuck, falling back to OPAL pollers. You will likely have slower I2C and may have experienced increased jitter.\n");
				prlog(PR_DEBUG, "SLW: Stuck with odd generation !\n");
				slw_has_timer = false;
				slw_dump_timer_ffdc();
				return;
			}
		}

		rc = xscom_write(slw_timer_chip, 0x5003A, req);
		if (rc) {
			prerror("SLW: Error %lld writing tmr request\n", rc);
			return;
		}

		/* Re-check gen count */
		rc = xscom_read(slw_timer_chip, 0xE0006, &gen2);
		if (rc) {
			prerror("SLW: Error %lld re-reading tmr gen "
				" count\n", rc);
			return;
		}
	} while(gen != gen2);

	/* Check if the timer is working. If at least 1ms has elapsed
	 * since the last call to this function, check that the gen
	 * count has changed
	 */
	if (tb_compare(slw_last_gen_stamp + msecs_to_tb(1), now)
	    == TB_ABEFOREB) {
		if (slw_last_gen == gen) {
			prlog(PR_ERR,
			      "SLW: Timer appears to not be running !\n");
			slw_has_timer = false;
			slw_dump_timer_ffdc();
		}
		slw_last_gen = gen;
		slw_last_gen_stamp = mftb();
	}

	prlog(PR_TRACE, "SLW: gen: %llx\n", gen);
}

bool slw_timer_ok(void)
{
	return slw_has_timer;
}

static void slw_init_timer(void)
{
	struct dt_node *np;
	int64_t rc;
	uint32_t tick_us;

	np = dt_find_compatible_node(dt_root, NULL, "ibm,power8-sbe-timer");
	if (!np)
		return;

	slw_timer_chip = dt_get_chip_id(np);
	tick_us = dt_prop_get_u32(np, "tick-time-us");
	slw_timer_inc = usecs_to_tb(tick_us);
	slw_timer_target = ~0ull;

	rc = xscom_read(slw_timer_chip, 0xE0006, &slw_last_gen);
	if (rc) {
		prerror("SLW: Error %lld reading tmr gen count\n", rc);
		return;
	}
	slw_last_gen_stamp = mftb();

	prlog(PR_INFO, "SLW: Timer facility on chip %d, resolution %dus\n",
	      slw_timer_chip, tick_us);
	slw_has_timer = true;
}

void slw_init(void)
{
	struct proc_chip *chip;

	if (proc_gen != proc_gen_p8)
		return;

	for_each_chip(chip)
		slw_init_chip(chip);

	slw_init_timer();
}
