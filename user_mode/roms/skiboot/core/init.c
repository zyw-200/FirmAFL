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
#include <fsp.h>
#include <fsp-sysparam.h>
#include <psi.h>
#include <chiptod.h>
#include <nx.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <opal.h>
#include <opal-msg.h>
#include <elf.h>
#include <io.h>
#include <cec.h>
#include <device.h>
#include <pci.h>
#include <lpc.h>
#include <i2c.h>
#include <chip.h>
#include <interrupts.h>
#include <mem_region.h>
#include <trace.h>
#include <console.h>
#include <fsi-master.h>
#include <centaur.h>
#include <libfdt/libfdt.h>
#include <timer.h>
#include <ipmi.h>
#include <sensor.h>
#include <xive.h>

enum proc_gen proc_gen;

static uint64_t kernel_entry;
static bool kernel_32bit;
static char zero_location[16];

#ifdef SKIBOOT_GCOV
void skiboot_gcov_done(void);
#endif

struct debug_descriptor debug_descriptor = {
	.eye_catcher	= "OPALdbug",
	.version	= DEBUG_DESC_VERSION,
	.state_flags	= 0,
	.memcons_phys	= (uint64_t)&memcons,
	.trace_mask	= 0, /* All traces disabled by default */
	.console_log_levels = (PR_DEBUG << 4) | PR_NOTICE,
};

static bool try_load_elf64_le(struct elf_hdr *header)
{
	struct elf64_hdr *kh = (struct elf64_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64_phdr *ph;
	unsigned int i;

	printf("INIT: 64-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64_phdr *)(load_base + le64_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le64_to_cpu(ph->p_vaddr) > le64_to_cpu(kh->e_entry) ||
		    (le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_memsz)) <
		    le64_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le64_to_cpu(kh->e_entry) -
			le64_to_cpu(ph->p_vaddr) + le64_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}
	kernel_entry += load_base;
	kernel_32bit = false;

	printf("INIT: 64-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf64(struct elf_hdr *header)
{
	struct elf64_hdr *kh = (struct elf64_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64_phdr *ph;
	struct elf64_shdr *sh;
	unsigned int i;

	/* Check it's a ppc64 LE ELF */
	if (kh->ei_ident == ELF_IDENT		&&
	    kh->ei_data == ELF_DATA_LSB		&&
	    kh->e_machine == le16_to_cpu(ELF_MACH_PPC64)) {
		return try_load_elf64_le(header);
	}

	/* Check it's a ppc64 ELF */
	if (kh->ei_ident != ELF_IDENT		||
	    kh->ei_data != ELF_DATA_MSB		||
	    kh->e_machine != ELF_MACH_PPC64) {
		prerror("INIT: Kernel doesn't look like an ppc64 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64_phdr *)(load_base + kh->e_phoff);
	for (i = 0; i < kh->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PTYPE_LOAD)
			continue;
		if (ph->p_vaddr > kh->e_entry ||
		    (ph->p_vaddr + ph->p_memsz) < kh->e_entry)
			continue;

		/* Get our entry */
		kernel_entry = kh->e_entry - ph->p_vaddr + ph->p_offset;
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	/* For the normal big-endian ELF ABI, the kernel entry points
	 * to a function descriptor in the data section. Linux instead
	 * has it point directly to code. Test whether it is pointing
	 * into an executable section or not to figure this out. Default
	 * to assuming it obeys the ABI.
	 */
	sh = (struct elf64_shdr *)(load_base + kh->e_shoff);
	for (i = 0; i < kh->e_shnum; i++, sh++) {
		if (sh->sh_addr <= kh->e_entry &&
		      (sh->sh_addr + sh->sh_size) > kh->e_entry)
			break;
	}

	if (i == kh->e_shnum || !(sh->sh_flags & ELF_SFLAGS_X)) {
		kernel_entry = *(uint64_t *)(kernel_entry + load_base);
		kernel_entry = kernel_entry - ph->p_vaddr + ph->p_offset;
	}

	kernel_entry += load_base;
	kernel_32bit = false;

	printf("INIT: 64-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32_le(struct elf_hdr *header)
{
	struct elf32_hdr *kh = (struct elf32_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32_phdr *ph;
	unsigned int i;

	printf("INIT: 32-bit LE kernel discovered\n");

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32_phdr *)(load_base + le32_to_cpu(kh->e_phoff));
	for (i = 0; i < le16_to_cpu(kh->e_phnum); i++, ph++) {
		if (le32_to_cpu(ph->p_type) != ELF_PTYPE_LOAD)
			continue;
		if (le32_to_cpu(ph->p_vaddr) > le32_to_cpu(kh->e_entry) ||
		    (le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_memsz)) <
		    le32_to_cpu(kh->e_entry))
			continue;

		/* Get our entry */
		kernel_entry = le32_to_cpu(kh->e_entry) -
			le32_to_cpu(ph->p_vaddr) + le32_to_cpu(ph->p_offset);
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32(struct elf_hdr *header)
{
	struct elf32_hdr *kh = (struct elf32_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf32_phdr *ph;
	unsigned int i;

	/* Check it's a ppc32 LE ELF */
	if (header->ei_ident == ELF_IDENT		&&
	    header->ei_data == ELF_DATA_LSB		&&
	    header->e_machine == le16_to_cpu(ELF_MACH_PPC32)) {
		return try_load_elf32_le(header);
	}

	/* Check it's a ppc32 ELF */
	if (header->ei_ident != ELF_IDENT		||
	    header->ei_data != ELF_DATA_MSB		||
	    header->e_machine != ELF_MACH_PPC32) {
		prerror("INIT: Kernel doesn't look like an ppc32 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32_phdr *)(load_base + kh->e_phoff);
	for (i = 0; i < kh->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PTYPE_LOAD)
			continue;
		if (ph->p_vaddr > kh->e_entry ||
		    (ph->p_vaddr + ph->p_memsz) < kh->e_entry)
			continue;

		/* Get our entry */
		kernel_entry = kh->e_entry - ph->p_vaddr + ph->p_offset;
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}

	kernel_entry += load_base;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

extern char __builtin_kernel_start[];
extern char __builtin_kernel_end[];
extern uint64_t boot_offset;

static size_t kernel_size;
static size_t initramfs_size;

static bool start_preload_kernel(void)
{
	int loaded;

	/* Try to load an external kernel payload through the platform hooks */
	kernel_size = KERNEL_LOAD_SIZE;
	loaded = start_preload_resource(RESOURCE_ID_KERNEL,
					RESOURCE_SUBID_NONE,
					KERNEL_LOAD_BASE,
					&kernel_size);
	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform start load kernel failed\n");
		kernel_size = 0;
		return false;
	}

	initramfs_size = INITRAMFS_LOAD_SIZE;
	loaded = start_preload_resource(RESOURCE_ID_INITRAMFS,
					RESOURCE_SUBID_NONE,
					INITRAMFS_LOAD_BASE, &initramfs_size);
	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform start load initramfs failed\n");
		initramfs_size = 0;
		return false;
	}

	return true;
}

static bool load_kernel(void)
{
	struct elf_hdr *kh;
	int loaded;

	prlog(PR_NOTICE, "INIT: Waiting for kernel...\n");

	loaded = wait_for_resource_loaded(RESOURCE_ID_KERNEL,
					  RESOURCE_SUBID_NONE);

	if (loaded != OPAL_SUCCESS) {
		printf("INIT: platform wait for kernel load failed\n");
		kernel_size = 0;
	}

	/* Try embedded kernel payload */
	if (!kernel_size) {
		kernel_size = __builtin_kernel_end - __builtin_kernel_start;
		if (kernel_size) {
			/* Move the built-in kernel up */
			uint64_t builtin_base =
				((uint64_t)__builtin_kernel_start) -
				SKIBOOT_BASE + boot_offset;
			printf("Using built-in kernel\n");
			memmove(KERNEL_LOAD_BASE, (void*)builtin_base,
				kernel_size);
		}
	}

	if (dt_has_node_property(dt_chosen, "kernel-base-address", NULL)) {
		kernel_entry = dt_prop_get_u64(dt_chosen,
					       "kernel-base-address");
		printf("INIT: Kernel image at 0x%llx\n",kernel_entry);
		kh = (struct elf_hdr *)kernel_entry;
		/*
		 * If the kernel is at 0, copy back what we wrote over
		 * for the null branch catcher.
		 */
		if (kernel_entry == 0)
			memcpy(0, zero_location, 16);
	} else {
		if (!kernel_size)
			printf("INIT: Assuming kernel at %p\n",
			       KERNEL_LOAD_BASE);
		kh = (struct elf_hdr *)KERNEL_LOAD_BASE;
	}

	printf("INIT: Kernel loaded, size: %zu bytes (0 = unknown preload)\n",
	       kernel_size);

	if (kh->ei_ident != ELF_IDENT) {
		printf("INIT: ELF header not found. Assuming raw binary.\n");
		return true;
	}

	if (kh->ei_class == ELF_CLASS_64)
		return try_load_elf64(kh);
	else if (kh->ei_class == ELF_CLASS_32)
		return try_load_elf32(kh);

	printf("INIT: Neither ELF32 not ELF64 ?\n");
	return false;
}

static void load_initramfs(void)
{
	int loaded;

	loaded = wait_for_resource_loaded(RESOURCE_ID_INITRAMFS,
					  RESOURCE_SUBID_NONE);

	if (loaded != OPAL_SUCCESS || !initramfs_size)
		return;

	printf("INIT: Initramfs loaded, size: %zu bytes\n", initramfs_size);

	dt_add_property_u64(dt_chosen, "linux,initrd-start",
			(uint64_t)INITRAMFS_LOAD_BASE);
	dt_add_property_u64(dt_chosen, "linux,initrd-end",
			(uint64_t)INITRAMFS_LOAD_BASE + initramfs_size);
}

int64_t mem_dump_free(void);

void __noreturn load_and_boot_kernel(bool is_reboot)
{
	const struct dt_property *memprop;
	uint64_t mem_top;
	void *fdt;

	memprop = dt_find_property(dt_root, DT_PRIVATE "maxmem");
	if (memprop)
		mem_top = (u64)dt_property_get_cell(memprop, 0) << 32
			| dt_property_get_cell(memprop, 1);
	else /* XXX HB hack, might want to calc it */
		mem_top = 0x40000000;

	op_display(OP_LOG, OP_MOD_INIT, 0x000A);

	if (platform.exit)
		platform.exit();

	/* Load kernel LID */
	if (!load_kernel()) {
		op_display(OP_FATAL, OP_MOD_INIT, 1);
		abort();
	}

	load_initramfs();

	ipmi_set_fw_progress_sensor(IPMI_FW_OS_BOOT);

	if (!is_reboot) {
		/* We wait for the nvram read to complete here so we can
		 * grab stuff from there such as the kernel arguments
		 */
		fsp_nvram_wait_open();

		/* Wait for FW VPD data read to complete */
		fsp_code_update_wait_vpd(true);
	}
	fsp_console_select_stdout();

	/*
	 * OCC takes few secs to boot.  Call this as late as
	 * as possible to avoid delay.
	 */
	occ_pstates_init();

	/* Set kernel command line argument if specified */
#ifdef KERNEL_COMMAND_LINE
	dt_add_property_string(dt_chosen, "bootargs", KERNEL_COMMAND_LINE);
#endif

	op_display(OP_LOG, OP_MOD_INIT, 0x000B);

	/* Create the device tree blob to boot OS. */
	fdt = create_dtb(dt_root, false);
	if (!fdt) {
		op_display(OP_FATAL, OP_MOD_INIT, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x000C);

	/* Start the kernel */
	if (!is_reboot)
		op_panel_disable_src_echo();

	/* Clear SRCs on the op-panel when Linux starts */
	op_panel_clear_src();

	cpu_give_self_os();

	mem_dump_free();

	printf("INIT: Starting kernel at 0x%llx, fdt at %p (size 0x%x)\n",
	       kernel_entry, fdt, fdt_totalsize(fdt));

	debug_descriptor.state_flags |= OPAL_BOOT_COMPLETE;

	fdt_set_boot_cpuid_phys(fdt, this_cpu()->pir);
	if (kernel_32bit)
		start_kernel32(kernel_entry, fdt, mem_top);
	start_kernel(kernel_entry, fdt, mem_top);
}

static void dt_fixups(void)
{
	struct dt_node *n;
	struct dt_node *primary_lpc = NULL;

	/* lpc node missing #address/size cells. Also pick one as
	 * primary for now (TBD: How to convey that from HB)
	 */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
		dt_add_property_cells(n, "#address-cells", 2);
		dt_add_property_cells(n, "#size-cells", 1);
		dt_add_property_strings(n, "status", "ok");
	}

	/* Missing "primary" property in LPC bus */
	if (primary_lpc && !dt_has_node_property(primary_lpc, "primary", NULL))
		dt_add_property(primary_lpc, "primary", NULL, 0);

	/* Missing "scom-controller" */
	dt_for_each_compatible(dt_root, n, "ibm,xscom") {
		if (!dt_has_node_property(n, "scom-controller", NULL))
			dt_add_property(n, "scom-controller", NULL, 0);
	}
}

static void add_arch_vector(void)
{
	/**
	 * vec5 = a PVR-list : Number-of-option-vectors :
	 *	  option-vectors[Number-of-option-vectors + 1]
	 */
	uint8_t vec5[] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

	if (dt_has_node_property(dt_chosen, "ibm,architecture-vec-5", NULL))
		return;

	dt_add_property(dt_chosen, "ibm,architecture-vec-5",
			vec5, sizeof(vec5));
}

static void dt_init_misc(void)
{
	/* Check if there's a /chosen node, if not, add one */
	dt_chosen = dt_find_by_path(dt_root, "/chosen");
	if (!dt_chosen)
		dt_chosen = dt_new(dt_root, "chosen");
	assert(dt_chosen);

	/* Add IBM architecture vectors if needed */
	add_arch_vector();

	/* Add the "OPAL virtual ICS*/
	add_ics_node();

	/* Additional fixups. TODO: Move into platform */
	dt_fixups();
}

static void branch_null(void)
{
	assert_fail("Branch to NULL !");
}

static void setup_branch_null_catcher(void)
{
	void (*bn)(void) = branch_null;

	/*
	 * FIXME: This copies the function descriptor (16 bytes) for
	 * ABI v1 (ie. big endian).  This will be broken if we ever
	 * move to ABI v2 (ie little endian)
	 */
	memcpy(zero_location, 0, 16); /* Save away in case we need it later */
	memcpy(0, bn, 16);
}

/* Called from head.S, thus no prototype. */
void __noreturn main_cpu_entry(const void *fdt, u32 master_cpu);

typedef void (*ctorcall_t)(void);

static void do_ctors(void)
{
	extern ctorcall_t __ctors_start[], __ctors_end[];
	ctorcall_t *call;

	for (call = __ctors_start; call < __ctors_end; call++)
		(*call)();
}

void __noreturn main_cpu_entry(const void *fdt, u32 master_cpu)
{
	/*
	 * WARNING: At this point. the timebases have
	 * *not* been synchronized yet. Do not use any timebase
	 * related functions for timeouts etc... unless you can cope
	 * with the speed being some random core clock divider and
	 * the value jumping backward when the synchronization actually
	 * happens (in chiptod_init() below).
	 *
	 * Also the current cpu_thread() struct is not initialized
	 * either so we need to clear it out first thing first (without
	 * putting any other useful info in there jus yet) otherwise
	 * printf an locks are going to play funny games with "con_suspend"
	 */
	pre_init_boot_cpu();

	/*
	 * Before first printk, ensure console buffer is clear or
	 * reading tools might think it has wrapped
	 */
	clear_console();

	/* Put at 0 an OPD to a warning function in case we branch through
	 * a NULL function pointer
	 */
	setup_branch_null_catcher();

	do_ctors();

	printf("SkiBoot %s starting...\n", version);
	printf("initial console log level: memory %d, driver %d\n",
	       (debug_descriptor.console_log_levels >> 4),
	       (debug_descriptor.console_log_levels & 0x0f));
	prlog(PR_TRACE, "You will not see this\n");

#ifdef SKIBOOT_GCOV
	skiboot_gcov_done();
#endif

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();

	/* Now locks can be used */
	init_locks();

	/* Create the OPAL call table early on, entries can be overridden
	 * later on (FSP console code for example)
	 */
	opal_table_init();

	/*
	 * If we are coming in with a flat device-tree, we expand it
	 * now. Else look for HDAT and create a device-tree from them
	 *
	 * Hack alert: When entering via the OPAL entry point, fdt
	 * is set to -1, we record that and pass it to parse_hdat
	 */
	if (fdt == (void *)-1ul) {
		if (parse_hdat(true, master_cpu) < 0)
			abort();
	} else if (fdt == NULL) {
		if (parse_hdat(false, master_cpu) < 0)
			abort();
	} else {
		dt_expand(fdt);
	}

	/*
	 * From there, we follow a fairly strict initialization order.
	 *
	 * First we need to build up our chip data structures and initialize
	 * XSCOM which will be needed for a number of susbequent things.
	 *
	 * We want XSCOM available as early as the platform probe in case the
	 * probe requires some HW accesses.
	 *
	 * We also initialize the FSI master at that point in case we need
	 * to access chips via that path early on.
	 */
	init_chips();

	/* If we detect the mambo simulator, we can enable its special console
	 * early on. Do that now.
	 */
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		enable_mambo_console();

	xscom_init();
	mfsi_init();

	/*
	 * Put various bits & pieces in device-tree that might not
	 * already be there such as the /chosen node if not there yet,
	 * the ICS node, etc... This can potentially use XSCOM
	 */
	dt_init_misc();

	/*
	 * Initialize LPC (P8 only) so we can get to UART, BMC and
	 * other system controller. This is done before probe_platform
	 * so that the platform probing code can access an external
	 * BMC if needed.
	 */
	lpc_init();

	/*
	 * Now, we init our memory map from the device-tree, and immediately
	 * reserve areas which we know might contain data coming from
	 * HostBoot. We need to do these things before we start doing
	 * allocations outside of our heap, such as chip local allocs,
	 * otherwise we might clobber those data.
	 */
	mem_region_init();

	/* Reserve HOMER and OCC area */
	homer_init();

	/* Add the /opal node to the device-tree */
	add_opal_node();

	/*
	 * We probe the platform now. This means the platform probe gets
	 * the opportunity to reserve additional areas of memory if needed.
	 *
	 * Note: Timebases still not synchronized.
	 */
	probe_platform();

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();

	/* Allocate our split trace buffers now. Depends add_opal_node() */
	init_trace_buffers();

	/* On P7/P8, get the ICPs and make sure they are in a sane state */
	init_interrupts();

	/* On P9, initialize XIVE */
	init_xive();

	/* Grab centaurs from device-tree if present (only on FSP-less) */
	centaur_init();

	/* Initialize PSI (depends on probe_platform being called) */
	psi_init();

	/* Call in secondary CPUs */
	cpu_bringup();

	/*
	 * Sycnhronize time bases. Thi resets all the TB values to a small
	 * value (so they appear to go backward at this point), and synchronize
	 * all core timebases to the global ChipTOD network
	 */
	chiptod_init();

	/* Initialize i2c */
	p8_i2c_init();

	/* Register routine to dispatch and read sensors */
	sensor_init();

	/*
	 * We have initialized the basic HW, we can now call into the
	 * platform to perform subsequent inits, such as establishing
	 * communication with the FSP or starting IPMI.
	 */
	if (platform.init)
		platform.init();

	/* Setup dummy console nodes if it's enabled */
	if (dummy_console_enabled())
		dummy_console_add_nodes();

	/* Init SLW related stuff, including fastsleep */
	slw_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Read in NVRAM and set it up */
	nvram_init();

	phb3_preload_vpd();
	phb3_preload_capp_ucode();
	start_preload_kernel();

	/* NX init */
	nx_init();

	/* Initialize the opal messaging */
	opal_init_msg();

	/* Probe IO hubs */
	probe_p7ioc();

	/* Probe PHB3 on P8 */
	probe_phb3();

	/* Probe PHB4 on P9 */
	probe_phb4();

	/* Probe NPUs */
	probe_npu();

	/* Initialize PCI */
	pci_init_slots();

	/* Add OPAL timer related properties */
	late_init_timers();

	ipmi_set_fw_progress_sensor(IPMI_FW_PCI_INIT);

	/*
	 * These last few things must be done as late as possible
	 * because they rely on various other things having been setup,
	 * for example, add_opal_interrupts() will add all the interrupt
	 * sources that are going to the firmware. We can't add a new one
	 * after that call. Similarly, the mem_region calls will construct
	 * the reserve maps in the DT so we shouldn't affect the memory
	 * regions after that
	 */

	/* Add the list of interrupts going to OPAL */
	add_opal_interrupts();

	/* Now release parts of memory nodes we haven't used ourselves... */
	mem_region_release_unused();

	/* ... and add remaining reservations to the DT */
	mem_region_add_dt_reserved();

	prd_register_reserved_memory();

	load_and_boot_kernel(false);
}

void __noreturn __secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Secondary CPU called in */
	cpu_callin(cpu);

	init_hid();

	/* Some XIVE setup */
	xive_cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		int i;

		/* Process pending jobs on this processor */
		cpu_process_jobs();

		/* Relax a bit to give the simulator some breathing space */
		i = 1000;
		smt_very_low();
		asm volatile("mtctr %0;\n"
			     "1: nop; nop; nop; nop;\n"
			     "   nop; nop; nop; nop;\n"
			     "   nop; nop; nop; nop;\n"
			     "   nop; nop; nop; nop;\n"
			     "   bdnz 1b"
			     : : "r" (i) : "memory", "ctr");
		smt_medium();
	}
}

/* Called from head.S, thus no prototype. */
void __noreturn secondary_cpu_entry(void);

void __noreturn secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	prlog(PR_DEBUG, "INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	__secondary_cpu_entry();
}
