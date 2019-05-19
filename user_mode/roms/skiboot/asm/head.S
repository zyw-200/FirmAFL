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

#include <asm-utils.h>
#include <asm-offsets.h>
#include <mem-map.h>
#include <processor.h>
#include <opal-api.h>
#include <stack.h>

#define EPAPR_MAGIC	0x65504150

/* Power management instructions */
#define PPC_INST_NAP		.long 0x4c000364
#define PPC_INST_SLEEP		.long 0x4c0003a4
#define PPC_INST_RVWINKLE	.long 0x4c0003e4

#define GET_STACK(stack_reg,pir_reg)				\
	sldi	stack_reg,pir_reg,STACK_SHIFT;			\
	addis	stack_reg,stack_reg,CPU_STACKS_OFFSET@ha;	\
	addi	stack_reg,stack_reg,CPU_STACKS_OFFSET@l;

#define GET_CPU()						\
	clrrdi	%r13,%r1,STACK_SHIFT

#define SAVE_GPR(reg,sp)	std %r##reg,STACK_GPR##reg(sp)
#define REST_GPR(reg,sp)	ld %r##reg,STACK_GPR##reg(sp)

	.section ".head","ax"

	. = 0
.global __head
__head:
	/* When booted as an OPAL LID, this is a pointer to the OPAL
	 * variant of the NACA
	 */
	.llong	opal_naca

	/* This entry point is used when booting with a flat device-tree
	 * pointer in r3
	 */
	. = 0x10
.global fdt_entry
fdt_entry:
	mr	%r27,%r3
	li	%r25,0
	b	boot_entry

	/* This is a pointer to a descriptor used by debugging tools
	 * on the service processor to get to various trace buffers
	 */
	. = 0x80
	.llong	debug_descriptor

	/* This is our boot semaphore used for CPUs to sync, it has to be
	 * at an easy to locate address (without relocation) since we
	 * need to get at it very early, before we apply our relocs
	 */
	. = 0xf0
boot_sem:
	.long	0

	/* And this is a boot flag used to kick secondaries into the
	 * main code.
	 */
boot_flag:
	.long	0

	/* This is used to trigger an assert() and in turn an ATTN
	 * in skiboot when a special sequence is written at this
	 * address. For testing purposes only.
	 */
	. = 0xf8
.global attn_trigger
attn_trigger:
	.long	0

	/* This is the host initiated reset trigger for test */
	. = 0xfc
.global hir_trigger
hir_trigger:
	.long	0

	. = 0x100
	/* BML entry, load up r3 with device tree location */
	li	%r3, 0
	oris	%r3, %r3, 0xa
	b	fdt_entry /* hack for lab boot */

	/* Entry point set by the FSP */
	.= 0x180
	li	%r27,0
	li	%r25,0
	b	boot_entry

#define EXCEPTION(nr)		\
	.= nr			;\
	mtsprg0	%r3		;\
	mfspr	%r3,SPR_CFAR	;\
	mtsprg1 %r4		;\
	li	%r4,nr		;\
	b	_exception

	/* More exception stubs */
	EXCEPTION(0x200)
	EXCEPTION(0x300)
	EXCEPTION(0x380)
	EXCEPTION(0x400)
	EXCEPTION(0x480)
	EXCEPTION(0x500)
	EXCEPTION(0x600)
	EXCEPTION(0x700)
	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)
	EXCEPTION(0xc00)
	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)
	EXCEPTION(0xe40)
	EXCEPTION(0xe60)
	EXCEPTION(0xe80)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0xf60)
	EXCEPTION(0xf80)
	EXCEPTION(0x1000)
	EXCEPTION(0x1100)
	EXCEPTION(0x1200)
	EXCEPTION(0x1300)
	EXCEPTION(0x1400)
	EXCEPTION(0x1500)
	EXCEPTION(0x1600)

	.= 0x1e00
_exception:
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	std	%r3,STACK_CFAR(%r1)
	std	%r4,STACK_TYPE(%r1)
	mfsprg0	%r3
	mfsprg1 %r4
	SAVE_GPR(0,%r1)
	SAVE_GPR(1,%r1)
	SAVE_GPR(2,%r1)
	SAVE_GPR(3,%r1)
	SAVE_GPR(4,%r1)
	SAVE_GPR(5,%r1)
	SAVE_GPR(6,%r1)
	SAVE_GPR(7,%r1)
	SAVE_GPR(8,%r1)
	SAVE_GPR(9,%r1)
	SAVE_GPR(10,%r1)
	SAVE_GPR(11,%r1)
	SAVE_GPR(12,%r1)
	SAVE_GPR(13,%r1)
	SAVE_GPR(14,%r1)
	SAVE_GPR(15,%r1)
	SAVE_GPR(16,%r1)
	SAVE_GPR(17,%r1)
	SAVE_GPR(18,%r1)
	SAVE_GPR(19,%r1)
	SAVE_GPR(20,%r1)
	SAVE_GPR(21,%r1)
	SAVE_GPR(22,%r1)
	SAVE_GPR(23,%r1)
	SAVE_GPR(24,%r1)
	SAVE_GPR(25,%r1)
	SAVE_GPR(26,%r1)
	SAVE_GPR(27,%r1)
	SAVE_GPR(28,%r1)
	SAVE_GPR(29,%r1)
	SAVE_GPR(30,%r1)
	SAVE_GPR(31,%r1)
	mfcr	%r3
	mfxer	%r4
	mfctr	%r5
	mflr	%r6
	stw	%r3,STACK_CR(%r1)
	stw	%r4,STACK_XER(%r1)
	stw	%r5,STACK_CTR(%r1)
	stw	%r5,STACK_LR(%r1)
	mfspr	%r3,SPR_SRR0
	mfspr	%r4,SPR_SRR1
	mfspr	%r5,SPR_HSRR0
	mfspr	%r6,SPR_HSRR1
	std	%r3,STACK_SRR0(%r1)
	std	%r4,STACK_SRR1(%r1)
	std	%r5,STACK_HSRR0(%r1)
	std	%r6,STACK_HSRR1(%r1)
	mr	%r3,%r1
	LOAD_IMM64(%r4, SKIBOOT_BASE)
	LOAD_IMM32(%r5, exception_entry_foo - __head)
	add	%r4,%r4,%r5
	mtctr	%r4
	bctrl
	b	.
exception_entry_foo:
	b	exception_entry

	.= 0x2000
	/* This is the OPAL branch table. It's populated at boot time
	 * with function pointers to the various OPAL functions from
	 * the content of the .opal_table section, indexed by Token.
	 */
.global opal_branch_table
opal_branch_table:
	.space	8 * (OPAL_LAST + 1)

/* Stores the offset we were started from.  Used later on if we want to
 * read any unrelocated code/data such as the built-in kernel image
 */
.global boot_offset
boot_offset:
        .llong   0

/*
 *
 * Boot time entry point from FSP
 *
 * All CPUs come here
 *
 * Boot code NV register usage:
 *
 *   r31 :  Boot PIR
 *   r30 :  Current running offset
 *   r29 :  Target address
 *   r28 :  PVR
 *   r27 :  DTB pointer (or NULL)
 *   r26 :  PIR thread mask
 *   r25 :  Selected master CPU (OPAL boot)
 */
.global boot_entry
boot_entry:
	/* Check PVR and set some CR bits */
	mfspr	%r28,SPR_PVR
	li	%r26,3	/* Default to SMT4 */
	srdi	%r3,%r28,16
	cmpwi	cr0,%r3,PVR_TYPE_P7
	beq	1f
	cmpwi	cr0,%r3,PVR_TYPE_P7P
	beq	1f
	cmpwi	cr0,%r3,PVR_TYPE_P8
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P8E
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P8NVL
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P9
	beq 	1f
	attn		/* Unsupported CPU type... what do we do ? */

	/* P8 -> 8 threads */
2:	li	%r26,7

	/* Get our reloc offset into r30 */
1:	bcl	20,31,$+4
1:	mflr	%r30
	subi	%r30,%r30,(1b - __head)

	/* Store reloc offset in boot_offset */
	LOAD_IMM32(%r3, boot_offset - __head)
	add     %r3,%r3,%r30
	std     %r30,0(%r3)

	/* Get ourselves a TOC & relocate it to our target address */
	LOAD_IMM32(%r2,__toc_start - __head)
	LOAD_IMM64(%r29, SKIBOOT_BASE)
	add	%r2,%r2,%r29

	/* Fixup our MSR (remove TA) */
	LOAD_IMM64(%r3, (MSR_HV | MSR_SF))
	mtmsrd	%r3,0

	/* Check our PIR, avoid threads */
	mfspr	%r31,SPR_PIR
	and.	%r0,%r31,%r26
	bne	secondary_wait

	/* Initialize per-core SPRs */
	bl init_shared_sprs

	/* Pick a boot CPU, cpu index in r31 */
	LOAD_IMM32(%r3, boot_sem - __head)
	add	%r3,%r3,%r30
1:	lwarx	%r4,0,%r3
	addi	%r0,%r4,1
	stwcx.	%r0,0,%r3
	bne	1b
	isync
	cmpwi	cr0,%r4,0
	bne	secondary_wait

	/* Make sure we are in SMT medium */
	smt_medium

	/* Initialize thread SPRs */
	bl init_replicated_sprs

	/* Save the initial offset. The secondary threads will spin on boot_flag
	 * before relocation so we need to keep track of its location to wake
	 * them up.
	 */
	mr	%r15,%r30

	/* Check if we need to copy ourselves up and update %r30 to
	 * be our new offset
	 */
	cmpd	%r29,%r30
	beq	2f
	LOAD_IMM32(%r3, _sbss - __head)
	srdi	%r3,%r3,3
	mtctr	%r3
	mr	%r4,%r30
	mr	%r30,%r29
	/* copy the skiboot image to the new offset */
1:	ld	%r0,0(%r4)
	std	%r0,0(%r29)
	addi	%r29,%r29,8
	addi	%r4,%r4,8
	bdnz	1b
	/* flush caches, etc */
	sync
	icbi	0,%r29
	sync
	isync
	/* branch to the new image location and continue */
	LOAD_IMM32(%r3, 2f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	bctr

	/* Get ready for C code: get a stack */
2:	GET_STACK(%r1,%r31)

	/* Clear up initial frame */
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)

	/* Relocate ourselves */
	bl	call_relocate

	/* Tell secondaries to move to second stage (relocated) spin loop */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r15
	li	%r0,1
	stw	%r0,0(%r3)

	/* Clear BSS */
	li	%r0,0
	LOAD_ADDR_FROM_TOC(%r3, _sbss)
	LOAD_ADDR_FROM_TOC(%r4, _ebss)
	subf	%r4,%r3,%r4
	srdi	%r4,%r4,3
	mtctr	%r4
1:	std	%r0,0(%r3)
	addi	%r3,%r3,8
	bdnz	1b

	/* Get our per-cpu pointer into r13 */
	GET_CPU()

#ifdef STACK_CHECK_ENABLED
	/* Initialize stack bottom mark to 0, it will be updated in C code */
	li	%r0,0
	std	%r0,CPUTHREAD_STACK_BOT_MARK(%r13)
#endif
	/* Jump to C */
	mr	%r3,%r27
	mr	%r4,%r25
	bl	main_cpu_entry
	b	.

	/* Secondary CPUs wait here r31 is PIR */
secondary_wait:	
	/* The primary might be in the middle of relocating us,
	 * so first we spin on the boot_flag
	 */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r30
1:	smt_very_low
	lwz	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	/* Init some registers */
	bl init_replicated_sprs

	/* Switch to new runtime address */
	mr	%r30,%r29
	LOAD_IMM32(%r3, 1f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	isync
	bctr	
1:
	/* Now wait for cpu_secondary_start to be set */
	LOAD_ADDR_FROM_TOC(%r3, cpu_secondary_start)
1:	smt_very_low	
	ld	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	smt_medium

	/* Check our PIR is in bound */
	LOAD_ADDR_FROM_TOC(%r5, cpu_max_pir)
	lwz	%r5,0(%r5)
	cmpw	%r31,%r5
	bgt-	secondary_not_found

	/* Get our stack, cpu thread, and jump to C */
	GET_STACK(%r1,%r31)
	li	%r0,0
	std	%r0,0(%r1)
	std	%r0,16(%r1)
	GET_CPU()

	bl	secondary_cpu_entry
	b	.

	/* Not found... what to do ? set some global error ? */
secondary_not_found:
	smt_very_low
	b	.

call_relocate:
	mflr	%r14
	LOAD_IMM32(%r4,__dynamic_start - __head)
	LOAD_IMM32(%r5,__rela_dyn_start - __head)
	add	%r4,%r4,%r30
	add	%r5,%r5,%r30
	mr	%r3,%r30
	bl	relocate
	cmpwi	%r3,0
	bne	1f
	mtlr	%r14
	blr
1:	/* Fatal relocate failure */
	attn

/* This is a little piece of code that is copied down to
 * 0x100 when doing a "fast reset"
 */
.global fast_reset_patch_start
fast_reset_patch_start:	
	smt_medium
	LOAD_IMM64(%r30, SKIBOOT_BASE)
	LOAD_IMM32(%r3, fast_reset_entry - __head)
	add	%r3,%r30,%r3
	mtctr	%r3
	bctr
.global fast_reset_patch_end
fast_reset_patch_end:

/* Fast reset code. We clean up the TLB and a few SPRs and
 * return to C code. All CPUs do that, the CPU triggering the
 * reset does it to itself last. The C code will sort out who
 * the master is. We come from the trampoline above with
 * r30 containing SKIBOOT_BASE
 */
fast_reset_entry:
	/* Clear out SLB */
	li	%r6,0
	slbmte	%r6,%r6
	slbia
	ptesync

	/* Get PIR */
	mfspr	%r31,SPR_PIR

	/* Get a stack and restore r13 */
	GET_STACK(%r1,%r31)
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)
	GET_CPU()

	/* Get our TOC */
	addis	%r2,%r30,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Go to C ! */
	bl	fast_reboot
	b	.

.global cleanup_tlb
cleanup_tlb:
	/* Clean the TLB */
	li	%r3,128
	mtctr	%r3
	li	%r4,0x800		/* IS field = 0b10 */
	ptesync
1:	tlbiel	%r4
	addi	%r4,%r4,0x1000
	bdnz	1b
	ptesync

#define FIXUP_ENDIAN                                              \
       tdi   0,0,0x48;   /* Reverse endian of b . + 8          */ \
       b     $+36;       /* Skip trampoline if endian is good  */ \
       .long 0x05009f42; /* bcl 20,31,$+4                      */ \
       .long 0xa602487d; /* mflr r10                           */ \
       .long 0x1c004a39; /* addi r10,r10,28                    */ \
       .long 0xa600607d; /* mfmsr r11                          */ \
       .long 0x01006b69; /* xori r11,r11,1                     */ \
       .long 0xa6035a7d; /* mtsrr0 r10                         */ \
       .long 0xa6037b7d; /* mtsrr1 r11                         */ \
       .long 0x2400004c  /* rfid                               */

.global enter_rvwinkle
enter_rvwinkle:
	/* Before entering rvwinkle, we create a stack frame
	 * and save our non-volatile registers.
	 *
	 * We also save these SPRs:
	 *
	 *  - HSPRG0	in GPR0 slot
	 *  - HSPRG1	in GPR1 slot
	 *
	 *  - xxx TODO: HIDs
	 *  - TODO: Mask MSR:ME during the process
	 */
	mflr	%r0
	std	%r0,16(%r1)
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	SAVE_GPR(2,%r1)
	SAVE_GPR(14,%r1)
	SAVE_GPR(15,%r1)
	SAVE_GPR(16,%r1)
	SAVE_GPR(17,%r1)
	SAVE_GPR(18,%r1)
	SAVE_GPR(19,%r1)
	SAVE_GPR(20,%r1)
	SAVE_GPR(21,%r1)
	SAVE_GPR(22,%r1)
	SAVE_GPR(23,%r1)
	SAVE_GPR(24,%r1)
	SAVE_GPR(25,%r1)
	SAVE_GPR(26,%r1)
	SAVE_GPR(27,%r1)
	SAVE_GPR(28,%r1)
	SAVE_GPR(29,%r1)
	SAVE_GPR(30,%r1)
	SAVE_GPR(31,%r1)
	mfcr	%r3
	mfxer	%r4
	mfspr	%r5,SPR_HSPRG0
	mfspr	%r6,SPR_HSPRG1
	stw	%r3,STACK_CR(%r1)
	stw	%r4,STACK_XER(%r1)
	std	%r5,STACK_GPR0(%r1)
	std	%r6,STACK_GPR1(%r1)

	/* Save stack pointer in struct cpu_thread */
	std	%r1,CPUTHREAD_SAVE_R1(%r13)

	/* rvwinkle sequence */
	ptesync
0:	ld	%r0,CPUTHREAD_SAVE_R1(%r13)
	cmpd	cr0,%r0,%r0
	bne	0b
	PPC_INST_RVWINKLE
	b	.

/* This is a little piece of code that is copied down to
 * 0x100 when doing a "rvwinkle reinit"
 */
.global rvwinkle_patch_start
rvwinkle_patch_start:
	FIXUP_ENDIAN
	smt_medium
	LOAD_IMM64(%r30, SKIBOOT_BASE)
	LOAD_IMM32(%r3, rvwinkle_restore - __head)
	add	%r3,%r30,%r3
	mtctr	%r3
	bctr
.global rvwinkle_patch_end
rvwinkle_patch_end:

rvwinkle_restore:
	/* Get PIR */
	mfspr	%r31,SPR_PIR

	/* Initialize per-core SPRs
	 *
	 * XXX We do it on each thread ... oh well, improve that later
	 */
	bl init_shared_sprs

	/* Initialize thread SPRs */
	bl init_replicated_sprs

	/* Get that CPU stack base and use it to restore r13 */
	GET_STACK(%r1,%r31)
	GET_CPU()

	/* Restore original stack pointer */
	ld	%r1,CPUTHREAD_SAVE_R1(%r13)

	/* Restore more stuff */
	lwz	%r3,STACK_CR(%r1)
	lwz	%r4,STACK_XER(%r1)
	ld	%r5,STACK_GPR0(%r1)
	ld	%r6,STACK_GPR1(%r1)
	mtcr	%r3
	mtxer	%r4
	mtspr	SPR_HSPRG0,%r5
	mtspr	SPR_HSPRG1,%r6
	REST_GPR(2,%r1)
	REST_GPR(14,%r1)
	REST_GPR(15,%r1)
	REST_GPR(16,%r1)
	REST_GPR(17,%r1)
	REST_GPR(18,%r1)
	REST_GPR(19,%r1)
	REST_GPR(20,%r1)
	REST_GPR(21,%r1)
	REST_GPR(22,%r1)
	REST_GPR(23,%r1)
	REST_GPR(24,%r1)
	REST_GPR(25,%r1)
	REST_GPR(26,%r1)
	REST_GPR(27,%r1)
	REST_GPR(28,%r1)
	REST_GPR(29,%r1)
	REST_GPR(30,%r1)
	REST_GPR(31,%r1)

	/* Get LR back, pop stack and return */
	addi	%r1,%r1,STACK_FRAMESIZE
	ld	%r0,16(%r1)
	mtlr	%r0
	blr

/* Functions to initialize replicated and shared SPRs to sane
 * values. This is called at boot and on soft-reset
 */
.global init_shared_sprs
init_shared_sprs:
	li	%r0,0
	mtspr	SPR_SDR1, %r0
	mtspr	SPR_AMOR, %r0

	mfspr	%r3,SPR_PVR
	srdi	%r3,%r3,16
	cmpwi	cr0,%r3,PVR_TYPE_P7
	beq	1f
	cmpwi	cr0,%r3,PVR_TYPE_P7P
	beq	2f
	cmpwi	cr0,%r3,PVR_TYPE_P8E
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8
	beq	3f
	cmpwi	cr0,%r3,PVR_TYPE_P8NVL
	beq	3f
	/* Unsupported CPU type... what do we do ? */
	b	9f

1:	/* P7 */
	/* TSCR: Value from pHyp */
	LOAD_IMM32(%r3,0x880DE880)
	mtspr	SPR_TSCR, %r3
	b	9f

2:	/* P7+ */
	/* TSCR: Recommended value by HW folks */
	LOAD_IMM32(%r3,0x88CDE880)
	mtspr	SPR_TSCR, %r3
	b	9f

3:	/* P8E/P8 */
	/* TSCR: Recommended value by HW folks */
	LOAD_IMM32(%r3,0x8ACC6880)
	mtspr	SPR_TSCR, %r3
	mfspr	%r3,SPR_LPCR
	rldicr	%r3,%r3,12,60
	ori	%r3,%r3,4
	rldicr	%r3,%r3,52,63
	mtspr	SPR_LPCR,%r3
	sync
	isync
	/* HID0: Clear bit 13 (enable core recovery) */
	mfspr	%r3,SPR_HID0
	li	%r0,1
	sldi	%r0,%r0,(63-13)
	andc	%r3,%r3,%r0
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	/* HMEER: Enable HMIs for core recovery and TOD errors. */
	LOAD_IMM64(%r0,SPR_HMEER_HMI_ENABLE_MASK)
	mfspr	%r3,SPR_HMEER
	or	%r3,%r3,%r0
	sync
	mtspr	SPR_HMEER,%r3
	isync
	/* RPR (per-LPAR but let's treat it as replicated for now) */
	LOAD_IMM64(%r3,0x00000103070F1F3F)
	mtspr	SPR_RPR,%r3
9:	blr

.global init_replicated_sprs
init_replicated_sprs:
	/* LPCR: sane value */
	LOAD_IMM64(%r3,0x0070000000000004)
	mtspr	SPR_LPCR, %r3

	/* XXX TODO: Add more */
	blr

/*
 *
 * NACA structure, accessed by the FPS to find the SPIRA
 *
 */
	. = 0x4000
.global naca
naca:
	.llong	spirah			/* 0x0000 : SPIRA-H  */
	.llong	0			/* 0x0008 : Reserved */
	.llong	0			/* 0x0010 : Reserved */
	.llong	hv_release_data		/* 0x0018 : HV release data */
	.llong	0			/* 0x0020 : Reserved */
	.llong	0			/* 0x0028 : Reserved */
	.llong	spira			/* 0x0030 : SP Interface Root */
	.llong	hv_lid_load_table	/* 0x0038 : LID load table */
	.llong	0			/* 0x0040 : Reserved */
	.space	68
	.long	0			/* 0x008c : Reserved */
	.space	16
	.long	SPIRA_ACTUAL_SIZE	/* 0x00a0 : Actual size of SPIRA */
	.space	28
	.llong	0			/* 0x00c0 : resident module loadmap */
	.space	136
	.llong	0			/* 0x0150 : reserved */
	.space	40
	.llong	0			/* 0x0180 : reserved */
	.space	36
	.long	0			/* 0x01ac : control flags */
	.byte	0			/* 0x01b0 : reserved */
	.space	4
	.byte	0			/* 0x01b5 : default state for SW attn */
	.space	1
	.byte	0x01			/* 0x01b7 : PCIA format */
	.space	0xe48

	.balign	0x10
hv_release_data:
	.space	58
	.llong	0x666			/* VRM ? */

	.balign	0x10
hv_lid_load_table:
	.long	0x10
	.long	0x10
	.long	0
	.long	0

/*
 *
 * OPAL variant of NACA
 *
 */
.global opal_naca
opal_naca:
	.llong	opal_boot_trampoline	/* Primary entry (used ?) */
	.llong	opal_boot_trampoline	/* Secondary entry (used ?) */
	.llong	spira			/* Spira pointer */
	.llong	0			/* Load address */
	.llong	opal_boot_trampoline	/* 0x180 trampoline */
	.llong	0			/* More stuff as seen in objdump ...*/
	.llong	0
	.llong	0
	.llong	0

	/* The FSP seems to ignore our primary/secondary entry
	 * points and instead copy that bit down to 0x180 and
	 * patch the first instruction to get our expected
	 * boot CPU number. We ignore that patching for now and
	 * got to the same entry we use for pHyp and FDT HB.
	 */
opal_boot_trampoline:
	li	%r25,0
	li	%r27,-1
	ba	boot_entry - __head

/*
 *
 * OPAL entry point from operating system
 *
 * Register usage:
 *
 *       r0: Token
 *       r2: OPAL Base
 *  r3..r10: Args
 *      r12: Scratch
 * r13..r31: Preserved
 *
 */
	.balign	0x10
.global opal_entry
opal_entry:
	/* Get our per CPU stack */
	mfspr	%r12,SPR_PIR
	GET_STACK(%r12,%r12)
	stdu	%r12,-STACK_FRAMESIZE(%r12)

	/* Save caller r1, establish new r1 */
	std	%r1,STACK_GPR1(%r12)
	mr	%r1,%r12

	/* May save arguments for tracing */
#ifdef OPAL_TRACE_ENTRY
	std	%r3,STACK_GPR3(%r1)
	std	%r4,STACK_GPR4(%r1)
	std	%r5,STACK_GPR5(%r1)
	std	%r6,STACK_GPR6(%r1)
	std	%r7,STACK_GPR7(%r1)
	std	%r8,STACK_GPR8(%r1)
	std	%r9,STACK_GPR9(%r1)
	std	%r10,STACK_GPR10(%r1)
#endif
	/* Save Token (r0), LR and r13 */
	mflr	%r12
	std	%r0,STACK_GPR0(%r1)
	std	%r13,STACK_GPR13(%r1)
	std	%r12,STACK_LR(%r1)

	/* Get the CPU thread */
	GET_CPU()

	/* Store token in CPU thread */
	std	%r0,CPUTHREAD_CUR_TOKEN(%r13)

	/* Mark the stack frame */
	li	%r12,STACK_ENTRY_OPAL_API	
	std	%r12,STACK_TYPE(%r1)

	/* Get our TOC */
	addis	%r2,%r2,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Check for a reboot in progress */
	LOAD_ADDR_FROM_TOC(%r12, reboot_in_progress)
	lbz	%r12,0(%r12)
	cmpwi	%r12,0
	bne	3f

#ifdef OPAL_TRACE_ENTRY
	mr	%r3,%r1
	bl	opal_trace_entry
	ld	%r0,STACK_GPR0(%r1)
	ld	%r3,STACK_GPR3(%r1)
	ld	%r4,STACK_GPR4(%r1)
	ld	%r5,STACK_GPR5(%r1)
	ld	%r6,STACK_GPR6(%r1)
	ld	%r7,STACK_GPR7(%r1)
	ld	%r8,STACK_GPR8(%r1)
	ld	%r9,STACK_GPR9(%r1)
	ld	%r10,STACK_GPR10(%r1)
#endif /* OPAL_TRACE_ENTRY */

	/* Convert our token into a table entry and get the
	 * function pointer. Also check the token.
	 */
	cmpldi	%r0,OPAL_LAST
	bgt-	2f
	sldi	%r0,%r0,3
	LOAD_ADDR_FROM_TOC(%r12, opal_branch_table)
	ldx	%r0,%r12,%r0
	cmpldi	%r0,0
	beq-	2f
	mtctr	%r0

	/* Jump ! */
	bctrl

1:	ld	%r12,STACK_LR(%r1)
	mtlr	%r12
	ld	%r13,STACK_GPR13(%r1)
	ld	%r1,STACK_GPR1(%r1)
	blr

2:	/* Bad token */
	ld	%r3,STACK_GPR0(%r1)
	bl	opal_bad_token
	b	1b

3:	/* Reboot in progress, reject all calls */
	li	%r3,OPAL_BUSY
	b	1b

.global start_kernel
start_kernel:
	sync
	icbi	0,%r3
	sync
	isync
	mtctr	%r3
	mr	%r3,%r4
	LOAD_IMM64(%r8,SKIBOOT_BASE);
	LOAD_IMM32(%r10, opal_entry - __head)
	add	%r9,%r8,%r10
	LOAD_IMM32(%r6, EPAPR_MAGIC)
	addi	%r7,%r5,1
	li	%r4,0
	li	%r5,0
	bctr

	.global start_kernel32
start_kernel32:
	mfmsr	%r10
	clrldi	%r10,%r10,1
	mtmsrd	%r10,0
	sync
	isync
	b	start_kernel

.global start_kernel_secondary
start_kernel_secondary:
	sync
	isync
	mtctr	%r3
	mfspr	%r3,SPR_PIR
	bctr
