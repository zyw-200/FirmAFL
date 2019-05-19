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
#include <cpu.h>
#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <xscom.h>
#include <interrupts.h>
#include <cec.h>
#include <timebase.h>
#include <pci.h>
#include <chip.h>

/*
 * To get control of all threads, we sreset them via XSCOM after
 * patching the 0x100 vector. This will work as long as the target
 * HRMOR is 0. If Linux ever uses HRMOR, we'll have to consider
 * a more messy approach.
 *
 * The SCOM register we want is called "Core RAS Control" in the doc
 * and EX0.EC.PC.TCTL_GENERATE#0.TCTL.DIRECT_CONTROLS in the SCOM list
 *
 * Bits in there change from CPU rev to CPU rev but the bit we care
 * about, bit 60 "sreset_request" appears to have stuck to the same
 * place in both P7 and P7+. The register also has the same SCOM
 * address
 */
#define EX0_TCTL_DIRECT_CONTROLS0	0x08010400
#define EX0_TCTL_DIRECT_CONTROLS1	0x08010440
#define EX0_TCTL_DIRECT_CONTROLS2	0x08010480
#define EX0_TCTL_DIRECT_CONTROLS3	0x080104c0
#define   TCTL_DC_SRESET_REQUEST	PPC_BIT(60)

/* Flag tested by the OPAL entry code */
uint8_t reboot_in_progress;
static struct cpu_thread *resettor, *resettee;

static void flush_caches(void)
{
	uint64_t base = SKIBOOT_BASE;
	uint64_t end = base + SKIBOOT_SIZE;

	/* Not sure what the effect of sreset is on cores, so let's
	 * shoot a series of dcbf's on all cachelines that make up
	 * our core memory just in case...
	 */
	while(base < end) {
		asm volatile("dcbf 0,%0" : : "r" (base) : "memory");
		base += 128;
	}
	sync();
}

static bool do_reset_core_p7(struct cpu_thread *cpu)
{
	uint32_t xscom_addr, chip;
	uint64_t ctl;
	int rc;

	/* Add the Core# */
	xscom_addr = EX0_TCTL_DIRECT_CONTROLS0;
	xscom_addr |= ((cpu->pir >> 2) & 7) << 24;

	chip = pir_to_chip_id(cpu->pir);

	ctl = TCTL_DC_SRESET_REQUEST;
	rc = xscom_write(chip, xscom_addr, ctl);
	rc |= xscom_write(chip, xscom_addr + 0x40, ctl);
	rc |= xscom_write(chip, xscom_addr + 0x80, ctl);
	rc |= xscom_write(chip, xscom_addr + 0xc0, ctl);
	if (rc) {
		prerror("RESET: Error %d resetting CPU 0x%04x\n",
			rc, cpu->pir);
		return false;
	}
	return true;
}

static void fast_reset_p7(void)
{
	struct cpu_thread *cpu;

	resettee = this_cpu();
	resettor = NULL;

	/* Pick up a candidate resettor. We do that before we flush
	 * the caches
	 */
	for_each_cpu(cpu) {
		/*
		 * Some threads might still be in skiboot.
		 *
		 * But because we deal with entire cores and we don't want
		 * to special case things, we are just going to reset them
		 * too making the assumption that this is safe, they are
		 * holding no locks. This can only be true if they don't
		 * have jobs scheduled which is hopefully the case.
		 */
		if (cpu->state != cpu_state_os &&
		    cpu->state != cpu_state_active)
			continue;

		/*
		 * Only hit cores and only if they aren't on the same core
		 * as ourselves
		 */
		if (cpu_get_thread0(cpu) == cpu_get_thread0(this_cpu()) ||
		    cpu->pir & 0x3)
			continue;

		/* Pick up one of those guys as our "resettor". It will be
		 * in charge of resetting this CPU. We avoid resetting
		 * ourselves, not sure how well it would do with SCOM
		 */
		resettor = cpu;
		break;
	}

	if (!resettor) {
		printf("RESET: Can't find a resettor !\n");
		return;
	}
	printf("RESET: Resetting from 0x%04x, resettor 0x%04x\n",
	       this_cpu()->pir, resettor->pir);

	printf("RESET: Flushing caches...\n");

	/* Is that necessary ? */
	flush_caches();

	/* Reset everybody except self and except resettor */
	for_each_cpu(cpu) {
		if (cpu->state != cpu_state_os &&
		    cpu->state != cpu_state_active)
			continue;
		if (cpu_get_thread0(cpu) == cpu_get_thread0(this_cpu()) ||
		    cpu->pir & 0x3)
			continue;
		if (cpu_get_thread0(cpu) == cpu_get_thread0(resettor))
			continue;

		printf("RESET: Resetting CPU 0x%04x...\n", cpu->pir);

		if (!do_reset_core_p7(cpu))
			return;
	}

	/* Reset the resettor last because it's going to kill me ! */
	printf("RESET: Resetting CPU 0x%04x...\n", resettor->pir);
	if (!do_reset_core_p7(resettor))
		return;

	/* Don't return */
	for (;;)
		;
}

void fast_reset(void)
{
	uint32_t pvr = mfspr(SPR_PVR);
	extern uint32_t fast_reset_patch_start;
	extern uint32_t fast_reset_patch_end;
	uint32_t *dst, *src;

	printf("RESET: Fast reboot request !\n");

	/* XXX We need a way to ensure that no other CPU is in skiboot
	 * holding locks (via the OPAL APIs) and if they are, we need
	 * for them to get out
	 */
	reboot_in_progress = 1;
	time_wait_ms(200);

	/* Copy reset trampoline */
	printf("RESET: Copying reset trampoline...\n");
	src = &fast_reset_patch_start;
	dst = (uint32_t *)0x100;
	while(src < &fast_reset_patch_end)
		*(dst++) = *(src++);
	sync_icache();

	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		fast_reset_p7();
	}
}

static void cleanup_cpu_state(void)
{
	if (cpu_is_thread0(this_cpu())) {
		cleanup_tlb();
		init_shared_sprs();
	}
	init_replicated_sprs();
	reset_cpu_icp();
}

#ifdef FAST_REBOOT_CLEARS_MEMORY
static void fast_mem_clear(uint64_t start, uint64_t end)
{
	printf("MEMORY: Clearing %llx..%llx\n", start, end);

	while(start < end) {
		asm volatile("dcbz 0,%0" : : "r" (start) : "memory");
		start += 128;
	}
}

static void memory_reset(void)
{
	struct address_range *i;
	uint64_t skistart = SKIBOOT_BASE;
	uint64_t skiend = SKIBOOT_BASE + SKIBOOT_SIZE;

	printf("MEMORY: Clearing ...\n");

	list_for_each(&address_ranges, i, list) {
		uint64_t start = cleanup_addr(i->arange->start);
		uint64_t end = cleanup_addr(i->arange->end);

		if (start >= skiend || end <= skistart)
			fast_mem_clear(start, end);
		else {
			if (start < skistart)
				fast_mem_clear(start, skistart);
			if (end > skiend)
				fast_mem_clear(skiend, end);
		}
	}
}
#endif /* FAST_REBOOT_CLEARS_MEMORY */

/* Entry from asm after a fast reset */
void __noreturn fast_reboot(void);

void __noreturn fast_reboot(void)
{
	static volatile bool fast_boot_release;
	struct cpu_thread *cpu;

	printf("INIT: CPU PIR 0x%04x reset in\n", this_cpu()->pir);

	/* If this CPU was chosen as the resettor, it must reset the
	 * resettee (the one that initiated the whole process
	 */
	if (this_cpu() == resettor)
		do_reset_core_p7(resettee);

	/* Are we the original boot CPU ? If not, we spin waiting
	 * for a relase signal from CPU 1, then we clean ourselves
	 * up and go processing jobs.
	 */
	if (this_cpu() != boot_cpu) {
		this_cpu()->state = cpu_state_present;
		while (!fast_boot_release) {
			smt_very_low();
			sync();
		}
		smt_medium();
		cleanup_cpu_state();
		__secondary_cpu_entry();
	}

	/* We are the original boot CPU, wait for secondaries to
	 * be captured
	 */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state != cpu_state_present) {
			smt_very_low();
			sync();
		}
		smt_medium();
	}

	printf("INIT: Releasing secondaries...\n");

	/* Release everybody */
	fast_boot_release = true;
	sync();

	/* Wait for them to respond */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state == cpu_state_present) {
			smt_very_low();
			sync();
		}
	}

	printf("INIT: All done, resetting everything else...\n");

	/* Clear release flag for next time */
	fast_boot_release = false;
	reboot_in_progress = 0;

	/* Cleanup ourselves */
	cleanup_cpu_state();

	/* Set our state to active */
	this_cpu()->state = cpu_state_active;

	/* Poke the consoles (see comments in the code there) */
	fsp_console_reset();

	/* Reset/EOI the PSI interrupt */
	psi_irq_reset();

	/* Remove all PCI devices */
	pci_reset();

	/* Reset IO Hubs */
	cec_reset();

	/* Re-Initialize all discovered PCI slots */
	pci_init_slots();

	/* Clear memory */
#ifdef FAST_REBOOT_CLEARS_MEMORY
	memory_reset();
#endif
	load_and_boot_kernel(true);
}
