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

#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <bitutils.h>
#include <types.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/str/str.h>

#include <libflash/blocklevel.h>

#include <mem-map.h>
#include <op-panel.h>
#include <platform.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

struct mem_region;
extern struct mem_region *mem_region_next(struct mem_region *region);

static inline bool is_rodata(const void *p)
{
	return ((const char *)p >= __rodata_start && (const char *)p < __rodata_end);
}

#define OPAL_BOOT_COMPLETE 0x1
/* Debug descriptor. This structure is pointed to by the word at offset
 * 0x80 in the sapphire binary
 */
struct debug_descriptor {
	u8	eye_catcher[8];	/* "OPALdbug" */
#define DEBUG_DESC_VERSION	1
	u32	version;
	u8	console_log_levels;	/* high 4 bits in memory,
					 * low 4 bits driver (e.g. uart). */
	u8	state_flags; /* various state flags - OPAL_BOOT_COMPLETE etc */
	u16	reserved2;
	u32	reserved[2];

	/* Memory console */
	u64	memcons_phys;
	u32	memcons_tce;
	u32	memcons_obuf_tce;
	u32	memcons_ibuf_tce;

	/* Traces */
	u64	trace_mask;
	u32	num_traces;
#define DEBUG_DESC_MAX_TRACES	256
	u64	trace_phys[DEBUG_DESC_MAX_TRACES];
	u32	trace_size[DEBUG_DESC_MAX_TRACES];
	u32	trace_tce[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

/* Console logging */
#define PR_EMERG	0
#define PR_ALERT	1
#define PR_CRIT		2
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define PR_TRACE	8
#define PR_INSANE	9

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

void _prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
#define prerror(fmt...)	do { prlog(PR_ERR, fmt); } while(0)
#define prlog_once(arg, ...)	 		\
({						\
	static bool __prlog_once = false;	\
	if (!__prlog_once) {			\
		__prlog_once = true;		\
		prlog(arg, ##__VA_ARGS__);	\
	}					\
})

/* Location codes  -- at most 80 chars with null termination */
#define LOC_CODE_SIZE	80

/* Processor generation */
enum proc_gen {
	proc_gen_unknown,
	proc_gen_p7,		/* P7 and P7+ */
	proc_gen_p8,
	proc_gen_p9,
};
extern enum proc_gen proc_gen;

/* Convert a 4-bit number to a hex char */
extern char __attrconst tohex(uint8_t nibble);

/* Bit position of the most significant 1-bit (LSB=0, MSB=63) */
static inline int ilog2(unsigned long val)
{
	int left_zeros;

	asm volatile ("cntlzd %0,%1" : "=r" (left_zeros) : "r" (val));

	return 63 - left_zeros;
}

static inline bool is_pow2(unsigned long val)
{
	return val == (1ul << ilog2(val));
}

#define lo32(x)	((x) & 0xffffffff)
#define hi32(x)	(((x) >> 32) & 0xffffffff)

/* WARNING: _a *MUST* be a power of two */
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#define ALIGN_DOWN(_v, _a)	((_v) & ~((_a) - 1))

/* TCE alignment */
#define TCE_SHIFT	12
#define TCE_PSIZE	(1ul << 12)
#define TCE_MASK	(TCE_PSIZE - 1)

/* Not the greatest variants but will do for now ... */
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

/* Clean the stray high bit which the FSP inserts: we only have 52 bits real */
static inline u64 cleanup_addr(u64 addr)
{
	return addr & ((1ULL << 52) - 1);
}

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel32(uint64_t entry, void* fdt,
			   uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine from HDAT and create device-tree */
extern int parse_hdat(bool is_opal, uint32_t master_cpu);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Full skiboot version number (possibly includes gitid). */
extern const char version[];

/* Debug support */
extern char __sym_map_start[];
extern char __sym_map_end[];
extern unsigned long get_symbol(unsigned long addr,
				char **sym, char **sym_end);

/* Fast reboot support */
extern void fast_reset(void);
extern void __noreturn __secondary_cpu_entry(void);
extern void __noreturn load_and_boot_kernel(bool is_reboot);
extern void cleanup_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);

/* Various probe routines, to replace with an initcall system */
extern void probe_p7ioc(void);
extern void probe_phb3(void);
extern void probe_phb4(void);
extern int phb3_preload_capp_ucode(void);
extern void phb3_preload_vpd(void);
extern int phb4_preload_capp_ucode(void);
extern void phb4_preload_vpd(void);
extern void probe_npu(void);
extern void uart_init(void);
extern void homer_init(void);
extern void occ_pstates_init(void);
extern void slw_init(void);
extern void add_cpu_idle_state_properties(void);
extern void occ_fsp_init(void);
extern void lpc_rtc_init(void);

/* flash support */
struct flash_chip;
extern int flash_register(struct blocklevel_device *bl, bool is_system_flash);
extern int flash_start_preload_resource(enum resource_id id, uint32_t subid,
					void *buf, size_t *len);
extern int flash_resource_loaded(enum resource_id id, uint32_t idx);
extern bool flash_reserve(void);
extern void flash_release(void);


/* NVRAM support */
extern void nvram_init(void);
extern void nvram_read_complete(bool success);

/* UART stuff */
extern void uart_setup_linux_passthrough(void);
extern void uart_setup_opal_console(void);
extern bool uart_enabled(void);

/* OCC interrupt */
extern void occ_interrupt(uint32_t chip_id);
extern void occ_send_dummy_interrupt(void);

/* OCC load support */
extern void occ_poke_load_queue(void);

/* OCC/Host PNOR ownership */
enum pnor_owner {
	PNOR_OWNER_HOST,
	PNOR_OWNER_EXTERNAL,
};
extern void occ_pnor_set_owner(enum pnor_owner owner);

/* PRD */
extern void prd_psi_interrupt(uint32_t proc);
extern void prd_tmgt_interrupt(uint32_t proc);
extern void prd_occ_reset(uint32_t proc);
extern void prd_init(void);
extern void prd_register_reserved_memory(void);

/* Flatten device-tree */
extern void *create_dtb(const struct dt_node *root, bool exclusive);

/* SLW reinit function for switching core settings */
extern int64_t slw_reinit(uint64_t flags);

/* SLW update timer function */
extern void slw_update_timer_expiry(uint64_t new_target);

/* Is SLW timer available ? */
extern bool slw_timer_ok(void);

/* Fallback fake RTC */
extern void fake_rtc_init(void);

#endif /* __SKIBOOT_H */
