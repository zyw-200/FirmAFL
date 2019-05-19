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
#include <opal.h>
#include <opal-msg.h>
#include <processor.h>
#include <chiptod.h>
#include <xscom.h>
#include <capp.h>
#include <pci.h>
#include <cpu.h>
#include <chip.h>
#include <npu-regs.h>
#include <npu.h>

/*
 * HMER register layout:
 * +===+==========+============================+========+===================+
 * |Bit|Name      |Description                 |PowerKVM|Action             |
 * |   |          |                            |HMI     |                   |
 * |   |          |                            |enabled |                   |
 * |   |          |                            |for this|                   |
 * |   |          |                            |bit ?   |                   |
 * +===+==========+============================+========+===================+
 * |0  |malfunctio|A processor core in the     |Yes     |Raise attn from    |
 * |   |n_allert  |system has checkstopped     |        |sapphire resulting |
 * |   |          |(failed recovery) and has   |        |xstop              |
 * |   |          |requested a CP Sparing      |        |                   |
 * |   |          |to occur. This is           |        |                   |
 * |   |          |broadcasted to every        |        |                   |
 * |   |          |processor in the system     |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |1  |Reserved  |reserved                    |n/a     |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |2  |proc_recv_|Processor recovery occurred |Yes     |Log message and    |
 * |   |done      |error-bit in fir not masked |        |continue working.  |
 * |   |          |(see bit 11)                |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |3  |proc_recv_|Processor went through      |Yes     |Log message and    |
 * |   |error_mask|recovery for an error which |        |continue working.  |
 * |   |ed        |is actually masked for      |        |                   |
 * |   |          |reporting                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |4  |          |Timer facility experienced  |Yes     |Raise attn from    |
 * |   |tfac_error|an error.                   |        |sapphire resulting |
 * |   |          |TB, DEC, HDEC, PURR or SPURR|        |xstop              |
 * |   |          |may be corrupted (details in|        |                   |
 * |   |          |TFMR)                       |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |5  |          |TFMR SPR itself is          |Yes     |Raise attn from    |
 * |   |tfmr_parit|corrupted.                  |        |sapphire resulting |
 * |   |y_error   |Entire timing facility may  |        |xstop              |
 * |   |          |be compromised.             |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |6  |ha_overflo| UPS (Uniterrupted Power    |No      |N/A                |
 * |   |w_warning |System) Overflow indication |        |                   |
 * |   |          |indicating that the UPS     |        |                   |
 * |   |          |DirtyAddrTable has          |        |                   |
 * |   |          |reached a limit where it    |        |                   |
 * |   |          |requires PHYP unload support|        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |7  |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |8  |xscom_fail|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread failed. A  |        |HMER register.     |
 * |   |          |trap register is            |        |                   |
 * |   |          |available.                  |        |                   |
 * |   |          |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |9  |xscom_done|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread completed. |        |HMER register.     |
 * |   |          |If hypervisor               |        |                   |
 * |   |          |intends to use this bit, it |        |                   |
 * |   |          |is responsible for clearing |        |                   |
 * |   |          |it before performing the    |        |                   |
 * |   |          |xscom operation.            |        |                   |
 * |   |          |NOTE: this bit should always|        |                   |
 * |   |          |be masked in HMEER          |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |10 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |11 |proc_recv_|Processor recovery occurred |y       |Log message and    |
 * |   |again     |again before bit2 or bit3   |        |continue working.  |
 * |   |          |was cleared                 |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |12-|reserved  |was temperature sensor      |n/a     |n/a                |
 * |15 |          |passed the critical point on|        |                   |
 * |   |          |the way up                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |16 |          |SCOM has set a reserved FIR |No      |n/a                |
 * |   |scom_fir_h|bit to cause recovery       |        |                   |
 * |   |m         |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |17 |trig_fir_h|Debug trigger has set a     |No      |n/a                |
 * |   |mi        |reserved FIR bit to cause   |        |                   |
 * |   |          |recovery                    |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |18 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |19 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |20 |hyp_resour|A hypervisor resource error |y       |Raise attn from    |
 * |   |ce_err    |occurred: data parity error |        |sapphire resulting |
 * |   |          |on, SPRC0:3; SPR_Modereg or |        |xstop.             |
 * |   |          |HMEER.                      |        |                   |
 * |   |          |Note: this bit will cause an|        |                   |
 * |   |          |check_stop when (HV=1, PR=0 |        |                   |
 * |   |          |and EE=0)                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |21-|          |if bit 8 is active, the     |No      |We handle it by    |
 * |23 |xscom_stat|reason will be detailed in  |        |Manually reading   |
 * |   |us        |these bits. see chapter 11.1|        |HMER register.     |
 * |   |          |This bits are information   |        |                   |
 * |   |          |only and always masked      |        |                   |
 * |   |          |(mask = '0')                |        |                   |
 * |   |          |If hypervisor intends to use|        |                   |
 * |   |          |this bit, it is responsible |        |                   |
 * |   |          |for clearing it before      |        |                   |
 * |   |          |performing the xscom        |        |                   |
 * |   |          |operation.                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |24-|Not       |Not implemented             |n/a     |n/a                |
 * |63 |implemente|                            |        |                   |
 * |   |d         |                            |        |                   |
 * +-- +----------+----------------------------+--------+-------------------+
 *
 * Above HMER bits can be enabled/disabled by modifying
 * SPR_HMEER_HMI_ENABLE_MASK #define in include/processor.h
 * If you modify support for any of the bits listed above, please make sure
 * you change the above table to refelct that.
 *
 * NOTE: Per Dave Larson, never enable 8,9,21-23
 */

/* Used for tracking cpu threads inside hmi handling. */
#define HMI_STATE_CLEANUP_DONE	0x100
#define CORE_THREAD_MASK	0x0ff
#define SUBCORE_THREAD_MASK(s_id, t_count) \
		((((1UL) << (t_count)) - 1) << ((s_id) * (t_count)))

/* xscom addresses for core FIR (Fault Isolation Register) */
#define CORE_FIR		0x10013100
#define NX_STATUS_REG		0x02013040 /* NX status register */
#define NX_DMA_ENGINE_FIR	0x02013100 /* DMA & Engine FIR Data Register */
#define NX_PBI_FIR		0x02013080 /* PowerBus Interface FIR Register */

/*
 * Bit 54 from NX status register is set to 1 when HMI interrupt is triggered
 * due to NX checksop.
 */
#define NX_HMI_ACTIVE		PPC_BIT(54)

/* Number of iterations for the various timeouts */
#define TIMEOUT_LOOPS		20000000

static const struct core_xstop_bit_info {
	uint8_t bit;		/* CORE FIR bit number */
	enum OpalHMI_CoreXstopReason reason;
} xstop_bits[] = {
	{ 3, CORE_CHECKSTOP_IFU_REGFILE },
	{ 5, CORE_CHECKSTOP_IFU_LOGIC },
	{ 8, CORE_CHECKSTOP_PC_DURING_RECOV },
	{ 10, CORE_CHECKSTOP_ISU_REGFILE },
	{ 12, CORE_CHECKSTOP_ISU_LOGIC },
	{ 21, CORE_CHECKSTOP_FXU_LOGIC },
	{ 25, CORE_CHECKSTOP_VSU_LOGIC },
	{ 26, CORE_CHECKSTOP_PC_RECOV_IN_MAINT_MODE },
	{ 32, CORE_CHECKSTOP_LSU_REGFILE },
	{ 36, CORE_CHECKSTOP_PC_FWD_PROGRESS },
	{ 38, CORE_CHECKSTOP_LSU_LOGIC },
	{ 45, CORE_CHECKSTOP_PC_LOGIC },
	{ 48, CORE_CHECKSTOP_PC_HYP_RESOURCE },
	{ 52, CORE_CHECKSTOP_PC_HANG_RECOV_FAILED },
	{ 54, CORE_CHECKSTOP_PC_AMBI_HANG_DETECTED },
	{ 60, CORE_CHECKSTOP_PC_DEBUG_TRIG_ERR_INJ },
	{ 63, CORE_CHECKSTOP_PC_SPRD_HYP_ERR_INJ },
};

static const struct nx_xstop_bit_info {
	uint8_t bit;		/* NX FIR bit number */
	enum OpalHMI_NestAccelXstopReason reason;
} nx_dma_xstop_bits[] = {
	{ 1, NX_CHECKSTOP_SHM_INVAL_STATE_ERR },
	{ 15, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_1 },
	{ 16, NX_CHECKSTOP_DMA_INVAL_STATE_ERR_2 },
	{ 20, NX_CHECKSTOP_DMA_CH0_INVAL_STATE_ERR },
	{ 21, NX_CHECKSTOP_DMA_CH1_INVAL_STATE_ERR },
	{ 22, NX_CHECKSTOP_DMA_CH2_INVAL_STATE_ERR },
	{ 23, NX_CHECKSTOP_DMA_CH3_INVAL_STATE_ERR },
	{ 24, NX_CHECKSTOP_DMA_CH4_INVAL_STATE_ERR },
	{ 25, NX_CHECKSTOP_DMA_CH5_INVAL_STATE_ERR },
	{ 26, NX_CHECKSTOP_DMA_CH6_INVAL_STATE_ERR },
	{ 27, NX_CHECKSTOP_DMA_CH7_INVAL_STATE_ERR },
	{ 31, NX_CHECKSTOP_DMA_CRB_UE },
	{ 32, NX_CHECKSTOP_DMA_CRB_SUE },
};

static const struct nx_xstop_bit_info nx_pbi_xstop_bits[] = {
	{ 12, NX_CHECKSTOP_PBI_ISN_UE },
};

static struct lock hmi_lock = LOCK_UNLOCKED;

static int queue_hmi_event(struct OpalHMIEvent *hmi_evt, int recover)
{
	size_t num_params;

	/* Don't queue up event if recover == -1 */
	if (recover == -1)
		return 0;

	/* set disposition */
	if (recover == 1)
		hmi_evt->disposition = OpalHMI_DISPOSITION_RECOVERED;
	else if (recover == 0)
		hmi_evt->disposition = OpalHMI_DISPOSITION_NOT_RECOVERED;

	/*
	 * V2 of struct OpalHMIEvent is of (5 * 64 bits) size and well packed
	 * structure. Hence use uint64_t pointer to pass entire structure
	 * using 5 params in generic message format. Instead of hard coding
	 * num_params divide the struct size by 8 bytes to get exact
	 * num_params value.
	 */
	num_params = ALIGN_UP(sizeof(*hmi_evt), sizeof(u64)) / sizeof(u64);

	/* queue up for delivery to host. */
	return _opal_queue_msg(OPAL_MSG_HMI_EVT, NULL, NULL,
				num_params, (uint64_t *)hmi_evt);
}

static int is_capp_recoverable(int chip_id, int capp_index)
{
	uint64_t reg;
	uint32_t reg_offset = capp_index ? CAPP1_REG_OFFSET : 0x0;

	xscom_read(chip_id, CAPP_ERR_STATUS_CTRL + reg_offset, &reg);
	return (reg & PPC_BIT(0)) != 0;
}

#define CAPP_PHB3_ATTACHED(chip, phb_index) \
	((chip)->capp_phb3_attached_mask & (1 << (phb_index)))

#define CHIP_IS_NAPLES(chip) ((chip)->type == PROC_CHIP_P8_NAPLES)

static int handle_capp_recoverable(int chip_id, int capp_index)
{
	struct dt_node *np;
	u64 phb_id;
	u32 dt_chip_id;
	struct phb *phb;
	u32 phb_index;
	struct proc_chip *chip = get_chip(chip_id);

	dt_for_each_compatible(dt_root, np, "ibm,power8-pciex") {
		dt_chip_id = dt_prop_get_u32(np, "ibm,chip-id");
		phb_index = dt_prop_get_u32(np, "ibm,phb-index");
		phb_id = dt_prop_get_u64(np, "ibm,opal-phbid");

		/*
		 * Murano/Venice have a single capp (capp0) per chip,
		 * that can be attached to phb0, phb1 or phb2.
		 * The capp is identified as being attached to the chip,
		 * regardless of the phb index.
		 *
		 * Naples has two capps per chip: capp0 attached to phb0,
		 * and capp1 attached to phb1.
		 * Once we know that the capp is attached to the chip,
		 * we must also check that capp/phb indices are equal.
		 */
		if ((chip_id == dt_chip_id) &&
		    CAPP_PHB3_ATTACHED(chip, phb_index) &&
		    (!CHIP_IS_NAPLES(chip) || phb_index == capp_index)) {
			phb = pci_get_phb(phb_id);
			phb_lock(phb);
			phb->ops->set_capp_recovery(phb);
			phb_unlock(phb);
			return 1;
		}
	}
	return 0;
}

static int decode_one_malfunction(int flat_chip_id, struct OpalHMIEvent *hmi_evt)
{
	int capp_index;
	struct proc_chip *chip = get_chip(flat_chip_id);
	int capp_num = CHIP_IS_NAPLES(chip) ? 2 : 1;

	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;

	for (capp_index = 0; capp_index < capp_num; capp_index++)
		if (is_capp_recoverable(flat_chip_id, capp_index))
			if (handle_capp_recoverable(flat_chip_id, capp_index)) {
				hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
				hmi_evt->type = OpalHMI_ERROR_CAPP_RECOVERY;
				return 1;
			}

	/* TODO check other FIRs */
	return 0;
}

static bool decode_core_fir(struct cpu_thread *cpu,
				struct OpalHMIEvent *hmi_evt)
{
	uint64_t core_fir;
	uint32_t core_id;
	int i;
	bool found = false;
	int64_t ret;

	/* Sanity check */
	if (!cpu || !hmi_evt)
		return false;

	core_id = pir_to_core_id(cpu->pir);

	/* Get CORE FIR register value. */
	ret = xscom_read(cpu->chip_id, XSCOM_ADDR_P8_EX(core_id, CORE_FIR),
			 &core_fir);

	if (ret == OPAL_HARDWARE) {
		prerror("HMI: XSCOM error reading CORE FIR\n");
		/* If the FIR can't be read, we should checkstop. */
		return true;
	} else if (ret == OPAL_WRONG_STATE) {
		/*
		 * CPU is asleep, so it probably didn't cause the checkstop.
		 * If no other HMI cause is found a "catchall" checkstop
		 * will be raised, so if this CPU should've been awake the
		 * error will be handled appropriately.
		 */
		prlog(PR_DEBUG,
		      "HMI: FIR read failed, chip %d core %d asleep\n",
		      cpu->chip_id, core_id);
		return false;
	}

	prlog(PR_INFO, "HMI: CHIP ID: %x, CORE ID: %x, FIR: %016llx\n",
			cpu->chip_id, core_id, core_fir);

	/* Check CORE FIR bits and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(xstop_bits); i++) {
		if (core_fir & PPC_BIT(xstop_bits[i].bit)) {
			found = true;
			hmi_evt->u.xstop_error.xstop_reason
						|= xstop_bits[i].reason;
		}
	}
	return found;
}

static void find_core_checkstop_reason(struct OpalHMIEvent *hmi_evt,
					int *event_generated)
{
	struct cpu_thread *cpu;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_CORE;

	/*
	 * Check CORE FIRs and find the reason for core checkstop.
	 * Send a separate HMI event for each core that has checkstopped.
	 */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		/* Only check on primaries (ie. core), not threads */
		if (cpu->is_secondary)
			continue;

		/* Initialize xstop_error fields. */
		hmi_evt->u.xstop_error.xstop_reason = 0;
		hmi_evt->u.xstop_error.u.pir = cpu->pir;

		if (decode_core_fir(cpu, hmi_evt)) {
			queue_hmi_event(hmi_evt, 0);
			*event_generated = 1;
		}
	}
}

static void find_nx_checkstop_reason(int flat_chip_id,
			struct OpalHMIEvent *hmi_evt, int *event_generated)
{
	uint64_t nx_status;
	uint64_t nx_dma_fir;
	uint64_t nx_pbi_fir;
	int i;

	/* Get NX status register value. */
	if (xscom_read(flat_chip_id, NX_STATUS_REG, &nx_status) != 0) {
		prerror("HMI: XSCOM error reading NX_STATUS_REG\n");
		return;
	}

	/* Check if NX has driven an HMI interrupt. */
	if (!(nx_status & NX_HMI_ACTIVE))
		return;

	/* Initialize HMI event */
	hmi_evt->severity = OpalHMI_SEV_FATAL;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NX;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* Get DMA & Engine FIR data register value. */
	if (xscom_read(flat_chip_id, NX_DMA_ENGINE_FIR, &nx_dma_fir) != 0) {
		prerror("HMI: XSCOM error reading NX_DMA_ENGINE_FIR\n");
		return;
	}

	/* Get PowerBus Interface FIR data register value. */
	if (xscom_read(flat_chip_id, NX_PBI_FIR, &nx_pbi_fir) != 0) {
		prerror("HMI: XSCOM error reading NX_PBI_FIR\n");
		return;
	}

	/* Find NX checkstop reason and populate HMI event with error info. */
	for (i = 0; i < ARRAY_SIZE(nx_dma_xstop_bits); i++)
		if (nx_dma_fir & PPC_BIT(nx_dma_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_dma_xstop_bits[i].reason;

	for (i = 0; i < ARRAY_SIZE(nx_pbi_xstop_bits); i++)
		if (nx_pbi_fir & PPC_BIT(nx_pbi_xstop_bits[i].bit))
			hmi_evt->u.xstop_error.xstop_reason
						|= nx_pbi_xstop_bits[i].reason;

	/*
	 * Set NXDMAENGFIR[38] to signal PRD that service action is required.
	 * Without this inject, PRD will not be able to do NX unit checkstop
	 * error analysis. NXDMAENGFIR[38] is a spare bit and used to report
	 * a software initiated attention.
	 *
	 * The behavior of this bit and all FIR bits are documented in
	 * RAS spreadsheet.
	 */
	xscom_write(flat_chip_id, NX_DMA_ENGINE_FIR, PPC_BIT(38));

	/* Send an HMI event. */
	queue_hmi_event(hmi_evt, 0);
	*event_generated = 1;
}

static void find_npu_checkstop_reason(int flat_chip_id,
				      struct OpalHMIEvent *hmi_evt,
				      int *event_generated)
{
	struct phb *phb;
	struct npu *p = NULL;

	uint64_t npu_fir;
	uint64_t npu_fir_mask;
	uint64_t npu_fir_action0;
	uint64_t npu_fir_action1;
	uint64_t fatal_errors;

	/* Only check for NPU errors if the chip has a NPU */
	if (PVR_TYPE(mfspr(SPR_PVR)) != PVR_TYPE_P8NVL)
		return;

	/* Find the NPU on the chip associated with the HMI. */
	for_each_phb(phb) {
		/* NOTE: if a chip ever has >1 NPU this will need adjusting */
		if (dt_node_is_compatible(phb->dt_node, "ibm,power8-npu-pciex") &&
		    (dt_get_chip_id(phb->dt_node) == flat_chip_id)) {
			p = phb_to_npu(phb);
			break;
		}
	}

	/* If we didn't find a NPU on the chip, it's not our checkstop. */
	if (p == NULL)
		return;

	/* Read all the registers necessary to find a checkstop condition. */
	if (xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR, &npu_fir) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_MASK, &npu_fir_mask) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION0, &npu_fir_action0) ||
	    xscom_read(flat_chip_id,
		       p->at_xscom + NX_FIR_ACTION1, &npu_fir_action1)) {
		prerror("HMI: Couldn't read NPU registers with XSCOM\n");
		return;
	}

	fatal_errors = npu_fir & ~npu_fir_mask & npu_fir_action0 & npu_fir_action1;

	/* If there's no errors, we don't need to do anything. */
	if (!fatal_errors)
		return;

	prlog(PR_DEBUG, "NPU: FIR 0x%016llx mask 0x%016llx\n",
	      npu_fir, npu_fir_mask);
	prlog(PR_DEBUG, "NPU: ACTION0 0x%016llx, ACTION1 0x%016llx\n",
	      npu_fir_action0, npu_fir_action1);

	/* Set the NPU to fenced since it can't recover. */
	npu_set_fence_state(p, true);

	/* Set up the HMI event */
	hmi_evt->severity = OpalHMI_SEV_WARNING;
	hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
	hmi_evt->u.xstop_error.xstop_type = CHECKSTOP_TYPE_NPU;
	hmi_evt->u.xstop_error.u.chip_id = flat_chip_id;

	/* The HMI is "recoverable" because it shouldn't crash the system */
	queue_hmi_event(hmi_evt, 1);
	*event_generated = 1;
}

static void decode_malfunction(struct OpalHMIEvent *hmi_evt)
{
	int i;
	int recover = -1;
	uint64_t malf_alert;
	int event_generated = 0;

	xscom_read(this_cpu()->chip_id, 0x2020011, &malf_alert);

	for (i = 0; i < 64; i++)
		if (malf_alert & PPC_BIT(i)) {
			recover = decode_one_malfunction(i, hmi_evt);
			xscom_write(this_cpu()->chip_id, 0x02020011, ~PPC_BIT(i));
			if (recover) {
				queue_hmi_event(hmi_evt, recover);
				event_generated = 1;
			}
			find_nx_checkstop_reason(i, hmi_evt, &event_generated);
			find_npu_checkstop_reason(i, hmi_evt, &event_generated);
		}

	if (recover != -1) {
		find_core_checkstop_reason(hmi_evt, &event_generated);

		/*
		 * In case, if we fail to find checkstop reason send an
		 * unknown HMI event.
		 */
		if (!event_generated) {
			hmi_evt->u.xstop_error.xstop_type =
						CHECKSTOP_TYPE_UNKNOWN;
			hmi_evt->u.xstop_error.xstop_reason = 0;
			queue_hmi_event(hmi_evt, recover);
		}
	}
}

static void wait_for_subcore_threads(void)
{
	uint64_t timeout = 0;

	while (!(*(this_cpu()->core_hmi_state_ptr) & HMI_STATE_CLEANUP_DONE)) {
		/*
		 * We use a fixed number of TIMEOUT_LOOPS rather
		 * than using the timebase to do a pseudo-wall time
		 * timeout due to the fact that timebase may not actually
		 * work at this point in time.
		 */
		if (++timeout >= (TIMEOUT_LOOPS*3)) {
			/*
			 * Break out the loop here and fall through
			 * recovery code. If recovery fails, kernel will get
			 * informed about the failure. This way we can avoid
			 * looping here if other threads are stuck.
			 */
			prlog(PR_DEBUG, "HMI: TB pre-recovery timeout\n");
			break;
		}
		cpu_relax();
	}
}

/*
 * For successful recovery of TB residue error, remove dirty data
 * from TB/HDEC register in each active partition (subcore). Writing
 * zero's to TB/HDEC will achieve the same.
 */
static void timer_facility_do_cleanup(uint64_t tfmr)
{
	if (tfmr & SPR_TFMR_TB_RESIDUE_ERR) {
		/* Reset the TB register to clear the dirty data. */
		mtspr(SPR_TBWU, 0);
		mtspr(SPR_TBWL, 0);
	}

	if (tfmr & SPR_TFMR_HDEC_PARITY_ERROR) {
		/* Reset HDEC register */
		mtspr(SPR_HDEC, 0);
	}
}

static int get_split_core_mode(void)
{
	uint64_t hid0;

	hid0 = mfspr(SPR_HID0);
	if (hid0 & SPR_HID0_POWER8_2LPARMODE)
		return 2;
	else if (hid0 & SPR_HID0_POWER8_4LPARMODE)
		return 4;

	return 1;
}


/*
 * Certain TB/HDEC errors leaves dirty data in timebase and hdec register
 * which need to cleared before we initiate clear_tb_errors through TFMR[24].
 * The cleanup has to be done by once by any one thread from core or subcore.
 *
 * In split core mode, it is required to clear the dirty data from TB/HDEC
 * register by all subcores (active partitions) before we clear tb errors
 * through TFMR[24]. The HMI recovery would fail even if one subcore do
 * not cleanup the respective TB/HDEC register.
 *
 * For un-split core, any one thread can do the cleanup.
 * For split core, any one thread from each subcore can do the cleanup.
 *
 * Errors that required pre-recovery cleanup:
 *	- SPR_TFMR_TB_RESIDUE_ERR
 *	- SPR_TFMR_HDEC_PARITY_ERROR
 */
static void pre_recovery_cleanup(void)
{
	uint64_t hmer;
	uint64_t tfmr;
	uint32_t sibling_thread_mask;
	int split_core_mode, subcore_id, thread_id, threads_per_core;
	int i;

	hmer = mfspr(SPR_HMER);

	/* exit if it is not Time facility error. */
	if (!(hmer & SPR_HMER_TFAC_ERROR))
		return;

	/*
	 * Exit if it is not the error that leaves dirty data in timebase
	 * or HDEC register. OR this may be the thread which came in very
	 * late and recovery is been already done.
	 *
	 * TFMR is per [sub]core register. If any one thread on the [sub]core
	 * does the recovery it reflects in TFMR register and applicable to
	 * all threads in that [sub]core. Hence take a lock before checking
	 * TFMR errors. Once a thread from a [sub]core completes the
	 * recovery, all other threads on that [sub]core will return from
	 * here.
	 *
	 * If TFMR does not show error that we are looking for, return
	 * from here. We would just fall through recovery code which would
	 * check for other errors on TFMR and fix them.
	 */
	lock(&hmi_lock);
	tfmr = mfspr(SPR_TFMR);
	if (!(tfmr & (SPR_TFMR_TB_RESIDUE_ERR | SPR_TFMR_HDEC_PARITY_ERROR))) {
		unlock(&hmi_lock);
		return;
	}

	/* Gather split core information. */
	split_core_mode = get_split_core_mode();
	threads_per_core = cpu_thread_count / split_core_mode;

	/* Prepare core/subcore sibling mask */
	thread_id = cpu_get_thread_index(this_cpu());
	subcore_id = thread_id / threads_per_core;
	sibling_thread_mask = SUBCORE_THREAD_MASK(subcore_id, threads_per_core);

	/*
	 * First thread on the core ?
	 * if yes, setup the hmi cleanup state to !DONE
	 */
	if ((*(this_cpu()->core_hmi_state_ptr) & CORE_THREAD_MASK) == 0)
		*(this_cpu()->core_hmi_state_ptr) &= ~HMI_STATE_CLEANUP_DONE;

	/*
	 * First thread on subcore ?
	 * if yes, do cleanup.
	 *
	 * Clear TB and wait for other threads (one from each subcore) to
	 * finish its cleanup work.
	 */

	if ((*(this_cpu()->core_hmi_state_ptr) & sibling_thread_mask) == 0)
		timer_facility_do_cleanup(tfmr);

	/*
	 * Mark this thread bit. This bit will stay on until this thread
	 * exit from handle_hmi_exception().
	 */
	*(this_cpu()->core_hmi_state_ptr) |= this_cpu()->thread_mask;

	/*
	 * Check if each subcore has completed the cleanup work.
	 * if yes, then notify all the threads that we are done with cleanup.
	 */
	for (i = 0; i < split_core_mode; i++) {
		uint32_t subcore_thread_mask =
				SUBCORE_THREAD_MASK(i, threads_per_core);
		if (!(*(this_cpu()->core_hmi_state_ptr) & subcore_thread_mask))
			break;
	}

	if (i == split_core_mode)
		*(this_cpu()->core_hmi_state_ptr) |= HMI_STATE_CLEANUP_DONE;

	unlock(&hmi_lock);

	/* Wait for other subcore to complete the cleanup. */
	wait_for_subcore_threads();
}

static void hmi_exit(void)
{
	/* unconditionally unset the thread bit */
	*(this_cpu()->core_hmi_state_ptr) &= ~(this_cpu()->thread_mask);
}

int handle_hmi_exception(uint64_t hmer, struct OpalHMIEvent *hmi_evt)
{
	int recover = 1;
	uint64_t tfmr;

	/*
	 * In case of split core, some of the Timer facility errors need
	 * cleanup to be done before we proceed with the error recovery.
	 */
	pre_recovery_cleanup();

	lock(&hmi_lock);
	/*
	 * Not all HMIs would move TB into invalid state. Set the TB state
	 * looking at TFMR register. TFMR will tell us correct state of
	 * TB register.
	 */
	this_cpu()->tb_invalid = !(mfspr(SPR_TFMR) & SPR_TFMR_TB_VALID);
	prlog(PR_DEBUG, "HMI: Received HMI interrupt: HMER = 0x%016llx\n", hmer);
	if (hmi_evt)
		hmi_evt->hmer = hmer;
	if (hmer & SPR_HMER_PROC_RECV_DONE) {
		hmer &= ~SPR_HMER_PROC_RECV_DONE;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE;
			queue_hmi_event(hmi_evt, recover);
		}
		prlog(PR_DEBUG, "HMI: Processor recovery Done.\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_ERROR_MASKED) {
		hmer &= ~SPR_HMER_PROC_RECV_ERROR_MASKED;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_MASKED;
			queue_hmi_event(hmi_evt, recover);
		}
		prlog(PR_DEBUG, "HMI: Processor recovery Done (masked).\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_AGAIN) {
		hmer &= ~SPR_HMER_PROC_RECV_AGAIN;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE_AGAIN;
			queue_hmi_event(hmi_evt, recover);
		}
		prlog(PR_DEBUG, "HMI: Processor recovery occurred again before"
			"bit2 was cleared\n");
	}
	/* Assert if we see malfunction alert, we can not continue. */
	if (hmer & SPR_HMER_MALFUNCTION_ALERT) {
		hmer &= ~SPR_HMER_MALFUNCTION_ALERT;

		if (hmi_evt)
			decode_malfunction(hmi_evt);
	}

	/* Assert if we see Hypervisor resource error, we can not continue. */
	if (hmer & SPR_HMER_HYP_RESOURCE_ERR) {
		hmer &= ~SPR_HMER_HYP_RESOURCE_ERR;
		recover = 0;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_HYP_RESOURCE;
			queue_hmi_event(hmi_evt, recover);
		}
	}

	/*
	 * Assert for now for all TOD errors. In future we need to decode
	 * TFMR and take corrective action wherever required.
	 */
	if (hmer & SPR_HMER_TFAC_ERROR) {
		tfmr = mfspr(SPR_TFMR);		/* save original TFMR */
		hmer &= ~SPR_HMER_TFAC_ERROR;
		recover = chiptod_recover_tb_errors();
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_ERROR_SYNC;
			hmi_evt->type = OpalHMI_ERROR_TFAC;
			hmi_evt->tfmr = tfmr;
			queue_hmi_event(hmi_evt, recover);
		}
	}
	if (hmer & SPR_HMER_TFMR_PARITY_ERROR) {
		tfmr = mfspr(SPR_TFMR);		/* save original TFMR */
		hmer &= ~SPR_HMER_TFMR_PARITY_ERROR;
		recover = chiptod_recover_tb_errors();
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_TFMR_PARITY;
			hmi_evt->tfmr = tfmr;
			queue_hmi_event(hmi_evt, recover);
		}
	}

	/*
	 * HMER bits are sticky, once set to 1 they remain set to 1 until
	 * they are set to 0. Reset the error source bit to 0, otherwise
	 * we keep getting HMI interrupt again and again.
	 */
	mtspr(SPR_HMER, hmer);
	hmi_exit();
	/* Set the TB state looking at TFMR register before we head out. */
	this_cpu()->tb_invalid = !(mfspr(SPR_TFMR) & SPR_TFMR_TB_VALID);
	unlock(&hmi_lock);
	return recover;
}

static int64_t opal_handle_hmi(void)
{
	uint64_t hmer;
	struct OpalHMIEvent hmi_evt;

	/*
	 * Compiled time check to see size of OpalHMIEvent do not exceed
	 * that of struct opal_msg.
	 */
	BUILD_ASSERT(sizeof(struct opal_msg) >= sizeof(struct OpalHMIEvent));

	memset(&hmi_evt, 0, sizeof(struct OpalHMIEvent));
	hmi_evt.version = OpalHMIEvt_V2;

	hmer = mfspr(SPR_HMER);		/* Get HMER register value */
	handle_hmi_exception(hmer, &hmi_evt);

	return OPAL_SUCCESS;
}
opal_call(OPAL_HANDLE_HMI, opal_handle_hmi, 0);
