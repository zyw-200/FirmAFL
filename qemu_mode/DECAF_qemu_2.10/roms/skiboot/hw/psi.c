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

/*
 * Service Processor serial console handling code
 */
#include <io.h>
#include <psi.h>
#include <fsp.h>
#include <opal.h>
#include <gx.h>
#include <interrupts.h>
#include <cpu.h>
#include <trace.h>
#include <xscom.h>
#include <chip.h>
#include <lpc.h>
#include <i2c.h>
#include <timebase.h>
#include <platform.h>
#include <errorlog.h>

static LIST_HEAD(psis);
static u64 psi_link_timer;
static u64 psi_link_timeout;
static bool psi_link_poll_active;
static bool psi_ext_irq_policy = EXTERNAL_IRQ_POLICY_LINUX;

static void psi_register_interrupts(struct psi *psi);
static void psi_activate_phb(struct psi *psi);

static struct lock psi_lock = LOCK_UNLOCKED;

DEFINE_LOG_ENTRY(OPAL_RC_PSI_TIMEOUT, OPAL_PLATFORM_ERR_EVT, OPAL_PSI,
		OPAL_PLATFORM_FIRMWARE,
		OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION, OPAL_NA);

void psi_set_link_polling(bool active)
{
	printf("PSI: %sing link polling\n",
	       active ? "start" : "stopp");
	psi_link_poll_active = active;
}

void psi_disable_link(struct psi *psi)
{
	lock(&psi_lock);

	/*
	 * Note: This can be called with the link already down but
	 * not detected as such yet by this layer since psi_check_link_active()
	 * operates locklessly and thus won't update the PSI structure. This
	 * is a non-issue, the only consequence is the messages in the log
	 * mentioning first the link having gone down then being disabled.
	 */
	if (psi->active) {
		u64 reg;
		psi->active = false;

		/* Mask errors in SEMR */
		reg = in_be64(psi->regs + PSIHB_SEMR);
		reg = ((0xfffull << 36) | (0xfffull << 20));
		out_be64(psi->regs + PSIHB_SEMR, reg);
		printf("PSI: SEMR set to %llx\n", reg);

		/* Reset all the error bits in PSIHB_CR and
		 * disable FSP interrupts
		 */
		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~(0x7ffull << 20);
		reg &= ~PSIHB_CR_PSI_LINK_ENABLE;	/* flip link enable */
		/*
		 * Ensure no commands/spurious interrupts reach
		 * the processor, by flipping the command enable.
		 */
		reg &= ~PSIHB_CR_FSP_CMD_ENABLE;
		reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
		reg &= ~PSIHB_CR_FSP_IRQ; /* Clear interrupt state too */
		printf("PSI[0x%03x]: Disabling link!\n", psi->chip_id);
		out_be64(psi->regs + PSIHB_CR, reg);
		printf("PSI: PSIHB_CR (error bits) set to %llx\n",
				in_be64(psi->regs + PSIHB_CR));
		psi_set_link_polling(true);
	}

	unlock(&psi_lock);
}

/*
 * Resetting the FSP is a multi step sequence:
 * 1. Read the PSIHBCR
 * 2. Set the PSIHBCR[6] -- write register back.
 * 3. Read PSIHBCR again
 * 4. Reset PSIHBCR[6] -- write register back.
 */
void psi_reset_fsp(struct psi *psi)
{
	lock(&psi_lock);

	if (psi->active) {
		u64 reg;

		printf("PSI: Driving FSP reset via PSI\n");
		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~(0xfffull << 20);	/* Reset error bits */
		reg |= PSIHB_CR_FSP_RESET;	/* FSP reset trigger start */
		out_be64(psi->regs + PSIHB_CR, reg);
		printf("PSI[0x%03x]: FSP reset start PSIHBCR set to %llx\n",
			psi->chip_id, in_be64(psi->regs + PSIHB_CR));

		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~PSIHB_CR_FSP_RESET;	/* Clear FSP reset bit */
		out_be64(psi->regs + PSIHB_CR, reg);	/* Complete reset */
		printf("PSI[0x%03x]: FSP reset complete. PSIHBCR set to %llx\n",
			psi->chip_id, in_be64(psi->regs + PSIHB_CR));
	}
	unlock(&psi_lock);

	/* Now bring down the PSI link too... */
	psi_disable_link(psi);
}

bool psi_check_link_active(struct psi *psi)
{
	u64 val = in_be64(psi->regs + PSIHB_CR);

	/*
	 * Unlocked, used during fsp_poke_msg so we really want
	 * to avoid fancy link re-entrancy and deadlocks here
	 */
	if (!psi->active)
		return false;
	return (val & PSIHB_CR_PSI_LINK_ENABLE) &&
		(val & PSIHB_CR_FSP_LINK_ACTIVE);
}

struct psi *psi_find_link(uint32_t chip_id)
{
	struct psi *psi;

	list_for_each(&psis, psi, list) {
		if (psi->chip_id == chip_id)
			return psi;
	}
	return NULL;
}

#define PSI_LINK_CHECK_INTERVAL		10	/* Interval in secs */
#define PSI_LINK_RECOVERY_TIMEOUT	1800	/* 30 minutes */

static void psi_link_poll(void *data __unused)
{
	struct psi *psi;
	u64 now;

	if (!psi_link_poll_active)
		return;

	now = mftb();
	if (psi_link_timer == 0 ||
		(tb_compare(now, psi_link_timer) == TB_AAFTERB) ||
		(tb_compare(now, psi_link_timer) == TB_AEQUALB)) {

		lock(&psi_lock);

		list_for_each(&psis, psi, list) {
			u64 val;

			if (psi->active || !psi->working)
				continue;

			val = in_be64(psi->regs + PSIHB_CR);

			printf("PSI[0x%03x]: Poll CR=0x%016llx\n",
			       psi->chip_id, val);

			if ((val & PSIHB_CR_PSI_LINK_ENABLE) &&
			    (val & PSIHB_CR_FSP_LINK_ACTIVE)) {
				printf("PSI[0x%03x]: Found active link!\n",
				       psi->chip_id);
				psi_link_timeout = 0;
				psi->active = true;
				psi_activate_phb(psi);
				psi_set_link_polling(false);
				unlock(&psi_lock);
				fsp_reinit_fsp();
				return;
			}
		}
		if (!psi_link_timeout)
			psi_link_timeout =
				now + secs_to_tb(PSI_LINK_RECOVERY_TIMEOUT);

		if (tb_compare(now, psi_link_timeout) == TB_AAFTERB) {
			log_simple_error(&e_info(OPAL_RC_PSI_TIMEOUT),
				"PSI: Link timeout -- loss of FSP\n");
			/* Reset the link timeout and continue looking */
			psi_link_timeout = 0;
		}

		/* Poll every 10 seconds */
		psi_link_timer = now + secs_to_tb(PSI_LINK_CHECK_INTERVAL);

		unlock(&psi_lock);
	}
}

void psi_enable_fsp_interrupt(struct psi *psi)
{
	if (!psi->working)
		return;

	/* Enable FSP interrupts in the GXHB */
	lock(&psi_lock);
	out_be64(psi->regs + PSIHB_CR,
		 in_be64(psi->regs + PSIHB_CR) | PSIHB_CR_FSP_IRQ_ENABLE);
	unlock(&psi_lock);
}

/* Multiple bits can be set on errors */
static void decode_psihb_error(u64 val)
{
	if (val & PSIHB_CR_PSI_ERROR)
		printf("PSI: PSI Reported Error\n");
	if (val & PSIHB_CR_PSI_LINK_INACTIVE)
		printf("PSI: PSI Link Inactive Transition\n");
	if (val & PSIHB_CR_FSP_ACK_TIMEOUT)
		printf("PSI: FSP Ack Timeout\n");
	if (val & PSIHB_CR_MMIO_LOAD_TIMEOUT)
		printf("PSI: MMIO Load Timeout\n");
	if (val & PSIHB_CR_MMIO_LENGTH_ERROR)
		printf("PSI: MMIO Length Error\n");
	if (val & PSIHB_CR_MMIO_ADDRESS_ERROR)
		printf("PSI: MMIO Address Error\n");
	if (val & PSIHB_CR_MMIO_TYPE_ERROR)
		printf("PSI: MMIO Type Error\n");
	if (val & PSIHB_CR_UE)
		printf("PSI: UE Detected\n");
	if (val & PSIHB_CR_PARITY_ERROR)
		printf("PSI: Internal Parity Error\n");
	if (val & PSIHB_CR_SYNC_ERR_ALERT1)
		printf("PSI: Sync Error Alert1\n");
	if (val & PSIHB_CR_SYNC_ERR_ALERT2)
		printf("PSI: Sync Error Alert2\n");
	if (val & PSIHB_CR_FSP_COMMAND_ERROR)
		printf("PSI: FSP Command Error\n");
}


static void handle_psi_interrupt(struct psi *psi, u64 val)
{
	printf("PSI[0x%03x]: PSI mgmnt interrupt CR=0x%016llx\n",
	       psi->chip_id, val);

	if (val & (0xfffull << 20)) {
		decode_psihb_error(val);
		psi_disable_link(psi);
	} else if (val & (0x1full << 11))
		printf("PSI: FSP error detected\n");
}

/* TODO: Determine which of these needs to be handled by powernv */
static void handle_extra_interrupt(struct psi *psi)
{
	u64 val;

	val = in_be64(psi->regs + PSIHB_IRQ_STATUS);

	/*
	 * Decode interrupt type, call appropriate handlers
	 * when available.
	 */
	if (val & PSIHB_IRQ_STAT_OCC)
		occ_interrupt(psi->chip_id);
	if (val & PSIHB_IRQ_STAT_FSI)
		printf("PSI: FSI irq received\n");
	if (val & PSIHB_IRQ_STAT_LPC) {
		lpc_interrupt(psi->chip_id);

		/*
		 * i2c interrupts are ORed with the LPC ones on
		 * Murano DD2.1 and Venice DD2.0
		 */
		p8_i2c_interrupt(psi->chip_id);
	}
	if (val & PSIHB_IRQ_STAT_LOCAL_ERR)
		prd_psi_interrupt(psi->chip_id);
	if (val & PSIHB_IRQ_STAT_HOST_ERR) {
		if (platform.external_irq)
			platform.external_irq(psi->chip_id);
	} else {
		u64 xivr;

		/*
		 * The way our FPGA "pulses" the external interrupt
		 * on BMC machines means we might not see it in the
		 * status register anymore, so look at the latch in
		 * the XIVR
		 */
		xivr = in_be64(psi->regs + PSIHB_XIVR_HOST_ERR);
		if (xivr & PPC_BIT(39) && platform.external_irq)
			platform.external_irq(psi->chip_id);
	}

	/*
	 * TODO: Per Vicente Chung, CRESPs don't generate interrupts,
	 * and are just informational. Need to define the policy
	 * to handle them.
	 */
}

static void psi_spurious_fsp_irq(struct psi *psi)
{
	u64 reg, bit;

	prerror("PSI: Spurious interrupt, attempting clear\n");

	if (proc_gen == proc_gen_p8) {
		reg = PSIHB_XSCOM_P8_HBCSR_CLR;
		bit = PSIHB_XSCOM_P8_HBSCR_FSP_IRQ;
	} else {
		reg = PSIHB_XSCOM_P7_HBCSR_CLR;
		bit = PSIHB_XSCOM_P7_HBSCR_FSP_IRQ;
	}
	xscom_write(psi->chip_id, psi->xscom_base + reg, bit);
}

bool psi_poll_fsp_interrupt(struct psi *psi)
{
	return !!(in_be64(psi->regs + PSIHB_CR) & PSIHB_CR_FSP_IRQ);
}

static void psi_interrupt(struct irq_source *is, uint32_t isn __unused)
{
	struct psi *psi = is->data;
	u64 val;

	val = in_be64(psi->regs + PSIHB_CR);

	if (psi_link_poll_active) {
		printf("PSI[0x%03x]: PSI interrupt CR=0x%016llx (A=%d)\n",
		       psi->chip_id, val, psi->active);
	}

	/* Handle PSI interrupts first in case it's a link down */
	if (val & PSIHB_CR_PSI_IRQ) {
		handle_psi_interrupt(psi, val);

		/*
		 * If the link went down, re-read PSIHB_CR as
		 * the FSP interrupt might have been cleared.
		 */
		if (!psi->active)
			val = in_be64(psi->regs + PSIHB_CR);
	}


	/*
	 * We avoid forwarding FSP interrupts if the link isn't
	 * active. They should be masked anyway but it looks
	 * like the CR bit can remain set.
	 */
	if (val & PSIHB_CR_FSP_IRQ) {
		/*
		 * We have a case a flood with FSP mailbox interrupts
		 * when the link is down, see if we manage to clear
		 * the condition
		 */
		if (!psi->active)
			psi_spurious_fsp_irq(psi);
		else
			fsp_interrupt();
	}

	 /* P8 additional interrupt? */
	if (proc_gen == proc_gen_p8)
		handle_extra_interrupt(psi);

	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll(NULL);
}

static int64_t psi_p7_set_xive(struct irq_source *is, uint32_t isn __unused,
			       uint16_t server, uint8_t priority)
{
	struct psi *psi = is->data;
	uint64_t xivr;

	if (!psi->working)
		return OPAL_HARDWARE;

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |=	P7_IRQ_BUID(psi->interrupt) << 16;

	out_be64(psi->regs + PSIHB_XIVR, xivr);

	return OPAL_SUCCESS;
}

static int64_t psi_p7_get_xive(struct irq_source *is, uint32_t isn __unused,
			       uint16_t *server, uint8_t *priority)
{
	struct psi *psi = is->data;
	uint64_t xivr;

	if (!psi->working)
		return OPAL_HARDWARE;

	/* Read & decode the XIVR */
	xivr = in_be64(psi->regs + PSIHB_XIVR);

	*server = (xivr >> 40) & 0x7ff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

static int64_t psi_p8_set_xive(struct irq_source *is, uint32_t isn,
			       uint16_t server, uint8_t priority)
{
	struct psi *psi = is->data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case P8_IRQ_PSI_FSP:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case P8_IRQ_PSI_OCC:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case P8_IRQ_PSI_FSI:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case P8_IRQ_PSI_LPC:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case P8_IRQ_PSI_LOCAL_ERR:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case P8_IRQ_PSI_HOST_ERR:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |= (uint64_t)(isn & 7) << 29;

	out_be64(psi->regs + xivr_p, xivr);

	return OPAL_SUCCESS;
}

static int64_t psi_p8_get_xive(struct irq_source *is, uint32_t isn __unused,
			       uint16_t *server, uint8_t *priority)
{
	struct psi *psi = is->data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case P8_IRQ_PSI_FSP:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case P8_IRQ_PSI_OCC:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case P8_IRQ_PSI_FSI:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case P8_IRQ_PSI_LPC:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case P8_IRQ_PSI_LOCAL_ERR:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case P8_IRQ_PSI_HOST_ERR:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Read & decode the XIVR */
	xivr = in_be64(psi->regs + xivr_p);

	*server = (xivr >> 40) & 0xffff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

/* Called on a fast reset, make sure we aren't stuck with
 * an accepted and never EOId PSI interrupt
 */
void psi_irq_reset(void)
{
	struct psi *psi;
	uint64_t xivr;

	printf("PSI: Hot reset!\n");

	assert(proc_gen == proc_gen_p7);

	list_for_each(&psis, psi, list) {
		/* Mask the interrupt & clean the XIVR */
		xivr = 0x000000ff00000000UL;
		xivr |=	P7_IRQ_BUID(psi->interrupt) << 16;
		out_be64(psi->regs + PSIHB_XIVR, xivr);

#if 0 /* Seems to checkstop ... */
		/*
		 * Maybe not anymore; we were just blindly sending
		 * this on all iopaths, not just the active one;
		 * We don't even know if those psis are even correct.
		 */
		/* Send a dummy EOI to make sure the ICP is clear */
		icp_send_eoi(psi->interrupt);
#endif
	}
}

static const struct irq_source_ops psi_p7_irq_ops = {
	.get_xive = psi_p7_get_xive,
	.set_xive = psi_p7_set_xive,
	.interrupt = psi_interrupt,
};

static const struct irq_source_ops psi_p8_irq_ops = {
	.get_xive = psi_p8_get_xive,
	.set_xive = psi_p8_set_xive,
	.interrupt = psi_interrupt,
};

static const struct irq_source_ops psi_p8_host_err_ops = {
	.get_xive = psi_p8_get_xive,
	.set_xive = psi_p8_set_xive,
};

static void psi_tce_enable(struct psi *psi, bool enable)
{
	void *addr;
	u64 val;

	switch (proc_gen) {
	case proc_gen_p7:
		addr = psi->regs + PSIHB_CR;
		break;
	case proc_gen_p8:
		addr = psi->regs + PSIHB_PHBSCR;
		break;
	default:
		prerror("%s: Unknown CPU type\n", __func__);
		return;
	}

	val = in_be64(addr);
	if (enable)
		val |=  PSIHB_CR_TCE_ENABLE;
	else
		val &= ~PSIHB_CR_TCE_ENABLE;
	out_be64(addr, val);
}

/*
 * Configure the PSI interface for communicating with
 * an FSP, such as enabling the TCEs, FSP commands,
 * etc...
 */
void psi_init_for_fsp(struct psi *psi)
{
	uint64_t reg;
	bool enable_tce = true;

	lock(&psi_lock);

	/* Disable and setup TCE base address */
	psi_tce_enable(psi, false);

	switch (proc_gen) {
	case proc_gen_p7:
		out_be64(psi->regs + PSIHB_TAR, PSI_TCE_TABLE_BASE |
			 PSIHB_TAR_16K_ENTRIES);
		break;
	case proc_gen_p8:
		out_be64(psi->regs + PSIHB_TAR, PSI_TCE_TABLE_BASE |
			 PSIHB_TAR_256K_ENTRIES);
		break;
	default:
		enable_tce = false;
	};

	/* Enable various other configuration register bits based
	 * on what pHyp does. We keep interrupts disabled until
	 * after the mailbox has been properly configured. We assume
	 * basic stuff such as PSI link enable is already there.
	 *
	 *  - FSP CMD Enable
	 *  - FSP MMIO Enable
	 *  - TCE Enable
	 *  - Error response enable
	 *
	 * Clear all other error bits
	 */
	if (!psi->active) {
		prerror("PSI: psi_init_for_fsp() called on inactive link!\n");
		unlock(&psi_lock);
		return;
	}

	reg = in_be64(psi->regs + PSIHB_CR);
	reg |= PSIHB_CR_FSP_CMD_ENABLE;
	reg |= PSIHB_CR_FSP_MMIO_ENABLE;
	reg |= PSIHB_CR_FSP_ERR_RSP_ENABLE;
	reg &= ~0x00000000ffffffffull;
	out_be64(psi->regs + PSIHB_CR, reg);
	psi_tce_enable(psi, enable_tce);

	unlock(&psi_lock);
}

void psi_set_external_irq_policy(bool policy)
{
	psi_ext_irq_policy = policy;
}

/*
 * Register interrupt sources for all working links, not just the active ones.
 * This is a one time activity.
 */
static void psi_register_interrupts(struct psi *psi)
{
	/* Configure the interrupt BUID and mask it */
	switch (proc_gen) {
	case proc_gen_p7:
		/* On P7, we get a single interrupt */
		out_be64(psi->regs + PSIHB_XIVR,
			 P7_IRQ_BUID(psi->interrupt) << 16 |
			 0xffull << 32);

		/* Configure it in the GX controller as well */
		gx_configure_psi_buid(psi->chip_id,
				      P7_IRQ_BUID(psi->interrupt));

		/* Register the IRQ source */
		register_irq_source(&psi_p7_irq_ops,
				    psi, psi->interrupt, 1);
		break;
	case proc_gen_p8:
		/* On P8 we get a block of 8, set up the base/mask
		 * and mask all the sources for now
		 */
		out_be64(psi->regs + PSIHB_IRSN,
			 SETFIELD(PSIHB_IRSN_COMP, 0ul, psi->interrupt) |
			 SETFIELD(PSIHB_IRSN_MASK, 0ul, 0x7fff8ul) |
			 PSIHB_IRSN_DOWNSTREAM_EN |
			 PSIHB_IRSN_UPSTREAM_EN);
		out_be64(psi->regs + PSIHB_XIVR_FSP,
			 (0xffull << 32) | (P8_IRQ_PSI_FSP << 29));
		out_be64(psi->regs + PSIHB_XIVR_OCC,
			 (0xffull << 32) | (P8_IRQ_PSI_OCC << 29));
		out_be64(psi->regs + PSIHB_XIVR_FSI,
			 (0xffull << 32) | (P8_IRQ_PSI_FSI << 29));
		out_be64(psi->regs + PSIHB_XIVR_LPC,
			 (0xffull << 32) | (P8_IRQ_PSI_LPC << 29));
		out_be64(psi->regs + PSIHB_XIVR_LOCAL_ERR,
			 (0xffull << 32) | (P8_IRQ_PSI_LOCAL_ERR << 29));
		out_be64(psi->regs + PSIHB_XIVR_HOST_ERR,
			 (0xffull << 32) | (P8_IRQ_PSI_HOST_ERR << 29));

		/*
		 * Register the IRQ sources FSP, OCC, FSI, LPC
		 * and Local Error. Host Error is actually the
		 * external interrupt and the policy for that comes
		 * from the platform
		 */
		if (psi_ext_irq_policy == EXTERNAL_IRQ_POLICY_SKIBOOT) {
			register_irq_source(&psi_p8_irq_ops,
					    psi,
					    psi->interrupt + P8_IRQ_PSI_SKIBOOT_BASE,
					    P8_IRQ_PSI_ALL_COUNT);
		} else {
			register_irq_source(&psi_p8_irq_ops,
					    psi,
					    psi->interrupt + P8_IRQ_PSI_SKIBOOT_BASE,
					    P8_IRQ_PSI_LOCAL_COUNT);
			/*
			 * Host Error is handled by powernv; host error
			 * is at offset 5 from the PSI base.
			 */
			register_irq_source(&psi_p8_host_err_ops,
					    psi,
					    psi->interrupt + P8_IRQ_PSI_LINUX_BASE,
					    P8_IRQ_PSI_LINUX_COUNT);
		}
		break;
	default:
		/* Unknown: just no interrupts */
		prerror("PSI: Unknown interrupt type\n");
	}
}

static void psi_activate_phb(struct psi *psi)
{
	u64 reg;

	/*
	 * Disable interrupt emission in the control register,
	 * it will be re-enabled later, after the mailbox one
	 * will have been enabled.
	 */
	reg = in_be64(psi->regs + PSIHB_CR);
	reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
	out_be64(psi->regs + PSIHB_CR, reg);

	/* Enable interrupts in the mask register. We enable everything
	 * except for bit "FSP command error detected" which the doc
	 * (P7 BookIV) says should be masked for normal ops. It also
	 * seems to be masked under OPAL.
	 */
	reg = 0x0000010000100000ull;
	out_be64(psi->regs + PSIHB_SEMR, reg);

#if 0
	/* Dump the GXHB registers */
	printf("  PSIHB_BBAR   : %llx\n",
	       in_be64(psi->regs + PSIHB_BBAR));
	printf("  PSIHB_FSPBAR : %llx\n",
	       in_be64(psi->regs + PSIHB_FSPBAR));
	printf("  PSIHB_FSPMMR : %llx\n",
	       in_be64(psi->regs + PSIHB_FSPMMR));
	printf("  PSIHB_TAR    : %llx\n",
	       in_be64(psi->regs + PSIHB_TAR));
	printf("  PSIHB_CR     : %llx\n",
	       in_be64(psi->regs + PSIHB_CR));
	printf("  PSIHB_SEMR   : %llx\n",
	       in_be64(psi->regs + PSIHB_SEMR));
	printf("  PSIHB_XIVR   : %llx\n",
	       in_be64(psi->regs + PSIHB_XIVR));
#endif
}

static void psi_create_mm_dtnode(struct psi *psi)
{
	struct dt_node *np;
	uint64_t addr = (uint64_t)psi->regs;

	np = dt_new_addr(dt_root, "psi", addr);
	if (!np)
		return;

	/* Hard wire size to 4G */
	dt_add_property_cells(np, "reg", hi32(addr), lo32(addr), 1, 0);
	switch (proc_gen) {
	case proc_gen_p7:
		dt_add_property_strings(np, "compatible", "ibm,psi",
					"ibm,power7-psi");
		break;
	case proc_gen_p8:
		dt_add_property_strings(np, "compatible", "ibm,psi",
					"ibm,power8-psi");
		break;
	default:
		dt_add_property_strings(np, "compatible", "ibm,psi");
	}
	dt_add_property_cells(np, "interrupt-parent", get_ics_phandle());
	dt_add_property_cells(np, "interrupts", psi->interrupt, 1);
	dt_add_property_cells(np, "ibm,chip-id", psi->chip_id);
}

static struct psi *alloc_psi(uint64_t base)
{
	struct psi *psi;

	psi = zalloc(sizeof(struct psi));
	if (!psi) {
		prerror("PSI: Could not allocate memory\n");
		return NULL;
	}
	psi->xscom_base = base;
	return psi;
}

static struct psi *psi_probe_p7(struct proc_chip *chip, u64 base)
{
	struct psi *psi = NULL;
	uint64_t rc, val;

	rc = xscom_read(chip->id, base + PSIHB_XSCOM_P7_HBBAR, &val);
	if (rc) {
		prerror("PSI: Error %llx reading PSIHB BAR on chip %d\n",
				rc, chip->id);
		return NULL;
	}
	if (val & PSIHB_XSCOM_P7_HBBAR_EN) {
		psi = alloc_psi(base);
		if (!psi)
			return NULL;
		psi->working = true;
		rc = val >> 36;	/* Bits 0:1 = 0x00; 2:27 Bridge BAR... */
		rc <<= 20;	/* ... corresponds to bits 18:43 of base addr */
		psi->regs = (void *)rc;
	} else
		printf("PSI[0x%03x]: Working link not found\n", chip->id);

	return psi;
}

static struct psi *psi_probe_p8(struct proc_chip *chip, u64 base)
{
	struct psi *psi = NULL;
	uint64_t rc, val;

	rc = xscom_read(chip->id, base + PSIHB_XSCOM_P8_BASE, &val);
	if (rc) {
		prerror("PSI[0x%03x]: Error %llx reading PSIHB BAR\n",
			chip->id, rc);
		return NULL;
	}
	if (val & PSIHB_XSCOM_P8_HBBAR_EN) {
		psi = alloc_psi(base);
		if (!psi)
			return NULL;
		psi->working = true;
		psi->regs = (void *)(val & ~PSIHB_XSCOM_P8_HBBAR_EN);
	} else
		printf("PSI[0x%03x]: Working chip not found\n", chip->id);

	return psi;
}

static bool psi_init_psihb(struct dt_node *psihb)
{
	uint32_t chip_id = dt_get_chip_id(psihb);
	struct proc_chip *chip = get_chip(chip_id);
	struct psi *psi = NULL;
	u64 base, val;

	if (!chip) {
		prerror("PSI: Can't find chip!\n");
		return false;
	}

	base = dt_get_address(psihb, 0, NULL);

	if (dt_node_is_compatible(psihb, "ibm,power7-psihb-x"))
		psi = psi_probe_p7(chip, base);
	else if (dt_node_is_compatible(psihb, "ibm,power8-psihb-x"))
		psi = psi_probe_p8(chip, base);
	else {
		prerror("PSI: Unknown processor type\n");
		return false;
	}
	if (!psi)
		return false;

	list_add(&psis, &psi->list);

	val = in_be64(psi->regs + PSIHB_CR);
	if (val & PSIHB_CR_FSP_LINK_ACTIVE) {
		lock(&psi_lock);
		psi->active = true;
		unlock(&psi_lock);
	}

	psi->chip_id = chip->id;
	psi->interrupt = get_psi_interrupt(chip->id);

	chip->psi = psi;

	psi_create_mm_dtnode(psi);
	psi_register_interrupts(psi);
	psi_activate_phb(psi);

	printf("PSI[0x%03x]: Found PSI bridge [working=%d, active=%d]\n",
			psi->chip_id, psi->working, psi->active);
	return true;
}

void psi_fsp_link_in_use(struct psi *psi __unused)
{
	static bool poller_created = false;

	/* Do this once only */
	if (!poller_created) {
		poller_created = true;
		opal_add_poller(psi_link_poll, NULL);
	}
}

struct psi *psi_find_functional_chip(void)
{
	return list_top(&psis, struct psi, list);
}

void psi_init(void)
{
	struct dt_node *np;

	dt_for_each_compatible(dt_root, np, "ibm,psihb-x")
		psi_init_psihb(np);
}

