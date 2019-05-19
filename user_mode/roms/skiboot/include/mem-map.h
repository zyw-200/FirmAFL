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

#ifndef __MEM_MAP_H
#define __MEM_MAP_H

/* This is our main offset for relocation. All our buffers
 * are offset from that and our code relocates itself to
 * that location
 */
#define SKIBOOT_BASE		0x30000000

/* Stack size set to 16K, some of it will be used for
 * machine check (see stack.h)
 */
#define STACK_SHIFT		14
#define STACK_SIZE		(1 << STACK_SHIFT)

/* The NACA and other stuff in head.S need to be at the start: we
 * give it 64k before placing the SPIRA and related data.
 */
#define SPIRA_OFF		0x00010000
#define SPIRAH_OFF		0x00010400

/* Actual SPIRA size is lesser than 1K (presently 0x340 bytes).
 * Use 1K for legacy SPIRA and 1K for SPIRA-H.
 * Then follow with for proc_init_data (aka PROCIN).
 * These need to be at fixed addresses in case we're ever little
 * endian: linker can't endian reverse a pointer for us.  Text, data
 * et. al. follows this.
 */
#define PROCIN_OFF		(SPIRA_OFF + 0x800)

/* Initial MDST table like PROCIN, we need fixed addresses,
 * we leave a 2k gap for PROCIN
 */
#define MDST_TABLE_OFF		(SPIRA_OFF + 0x1000)

/* Like MDST, we need fixed address for CPU control header.
 * We leave a 2k gap for MDST. CPU_CTL table is of size ~4k
 */
#define CPU_CTL_OFF             (SPIRA_OFF + 0x1800)

/* We keep a gap of 2M for skiboot text & bss for now. We will
 * then we have our heap which goes up to base + 14M (so 12M for
 * now, though we can certainly reduce that a lot).
 *
 * Ideally, we should fix the heap end and use _end to basically
 * initialize our heap so that it covers anything from _end to
 * that heap end, avoiding wasted space.
 *
 * That's made a bit tricky however due to how we create those
 * regions statically in mem_region.c, but still on the list of
 * things to improve.
 *
 * As of this writing (2014/4/6), we use approc 512K for skiboot
 * core and 2M of heap on a 1 socket machine.
 *
 * As of 2015/5/7 we use approx 800k for skiboot, 500k HEAP for
 * mambo boot.
 */
#define HEAP_BASE		(SKIBOOT_BASE + 0x00300000)
#define HEAP_SIZE		0x00d00000

/* This is the location of our console buffer at base + 16M */
#define INMEM_CON_START		(SKIBOOT_BASE + 0x01000000)
#define INMEM_CON_LEN  		0x100000

/* This is the location of HBRT console buffer at base + 17M */
#define HBRT_CON_START		(SKIBOOT_BASE + 0x01100000)
#define HBRT_CON_LEN  		0x100000

/* Tell FSP to put the init data at base + 20M, allocate 8M */
#define SPIRA_HEAP_BASE		(SKIBOOT_BASE + 0x01200000)
#define SPIRA_HEAP_SIZE		0x00800000

/* This is our PSI TCE table. It's 16K entries on P7 and 256K
 * entries on P8
 */
#define PSI_TCE_TABLE_BASE	(SKIBOOT_BASE + 0x01a00000)
#define PSI_TCE_TABLE_SIZE_P7	0x00020000UL
#define PSI_TCE_TABLE_SIZE_P8	0x00200000UL

/* Total size of the above area
 *
 * (Ensure this has at least a 64k alignment)
 */
#define SKIBOOT_SIZE		0x01c00000

/* We start laying out the CPU stacks from here, indexed by PIR
 * each stack is STACK_SIZE in size (naturally aligned power of
 * two) and the bottom of the stack contains the cpu thread
 * structure for the processor, so it can be obtained by a simple
 * bit mask from the stack pointer.
 *
 * The size of this array is dynamically determined at boot time
 */
#define CPU_STACKS_BASE		(SKIBOOT_BASE + SKIBOOT_SIZE)

/*
 * Address at which we load the kernel LID. This is also where
 * we expect a passed-in kernel if booting without FSP and
 * without a built-in kernel.
 */
#define KERNEL_LOAD_BASE	((void *)0x20000000)
#define KERNEL_LOAD_SIZE	0x08000000

#define INITRAMFS_LOAD_BASE	KERNEL_LOAD_BASE + KERNEL_LOAD_SIZE
#define INITRAMFS_LOAD_SIZE	0x08000000

/* Size allocated to build the device-tree */
#define	DEVICE_TREE_MAX_SIZE	0x80000


#endif /* __MEM_MAP_H */
