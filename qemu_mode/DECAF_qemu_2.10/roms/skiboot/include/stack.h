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

#ifndef __STACKFRAME_H
#define __STACKFRAME_H

#include <mem-map.h>

#define STACK_ENTRY_OPAL_API	0	/* OPAL call */
#define STACK_ENTRY_HMI		0x0e60	/* Hypervisor maintenance */
#define STACK_ENTRY_RESET	0x0100	/* System reset */
#define STACK_ENTRY_SOFTPATCH	0x1500	/* Soft patch (denorm emulation) */

/* Safety/ABI gap at top of stack */
#define STACK_TOP_GAP		0x100

/* Remaining stack space (gap included) */
#define NORMAL_STACK_SIZE	STACK_SIZE

/* Offset to get to normal CPU stacks */
#define CPU_STACKS_OFFSET	(CPU_STACKS_BASE + \
				 NORMAL_STACK_SIZE - STACK_TOP_GAP)

/* Gap below the stack. If our stack checker sees the stack below that
 * gap, it will flag a stack overflow
 */
#define STACK_SAFETY_GAP	512

/* Warning threshold, if stack goes below that on mcount, print a
 * warning.
 */
#define STACK_WARNING_GAP	2048

#ifndef __ASSEMBLY__

#include <stdint.h>

/* This is the struct used to save GPRs etc.. on OPAL entry
 * and from some exceptions. It is not always entirely populated
 * depending on the entry type
 */
struct stack_frame {
	/* Standard 112-byte stack frame header (the minimum size required,
	 * using an 8-doubleword param save area). The callee (in C) may use
	 * lrsave; we declare these here so we don't get our own save area
	 * overwritten */
	uint64_t	backchain;
	uint64_t	crsave;
	uint64_t	lrsave;
	uint64_t	compiler_dw;
	uint64_t	linker_dw;
	uint64_t	tocsave;
	uint64_t	paramsave[8];

	/* Space for stack-local vars used by asm. At present we only use
	 * one doubleword. */
	uint64_t	locals[1];

	/* Entry type */
	uint64_t	type;

	/* GPR save area
	 *
	 * We don't necessarily save everything in here
	 */
	uint64_t	gpr[32];

	/* Other SPR saved
	 *
	 * Only for some exceptions.
	 */
	uint32_t	cr;
	uint32_t	xer;
	uint64_t	ctr;
	uint64_t	lr;
	uint64_t	pc;
	uint64_t	cfar;
	uint64_t	srr0;
	uint64_t	srr1;
	uint64_t	hsrr0;
	uint64_t	hsrr1;
} __attribute__((aligned(16)));

/* Backtrace */
struct bt_entry {
	unsigned long	sp;
	unsigned long	pc;
};

/* Boot stack top */
extern void *boot_stack_top;

/* Create a backtrace */
extern void __backtrace(struct bt_entry *entries, unsigned int *count);

/* Convert a backtrace to ASCII */
extern void __print_backtrace(unsigned int pir, struct bt_entry *entries,
			      unsigned int count, char *out_buf,
			      unsigned int *len, bool symbols);

/* For use by debug code, create and print backtrace, uses a static buffer */
extern void backtrace(void);

#ifdef STACK_CHECK_ENABLED
extern void check_stacks(void);
#else
static inline void check_stacks(void) { }
#endif

#endif /* __ASSEMBLY__ */
#endif /* __STACKFRAME_H */

