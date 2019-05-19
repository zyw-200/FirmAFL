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

#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#include <stdint.h>
#include <ccan/list/list.h>

/*
 * Note about interrupt numbers on P7/P7+
 * ======================================
 *
 * The form of an interrupt number in the system on P7/P7+ is as follow:
 *
 * |  Node  | T| Chip|GX|           BUID           |   Level   |
 * |--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|
 *
 * Where:
 *
 *  - Node   : The 3-bit node number
 *  - T      : 1 for a Torrent chip, 0 otherwise
 *  - Chip   : 2-bit chip number in a node
 *  - GX     : GX bus identifier
 *  - BUID   : Bus identifier (*)
 *  - Level  : Interrupt number
 *
 * (*) The BUID/Level distinction is mostly historical, interrupt
 *     controllers such as the ICS in the PHBs "use" some of the
 *     low BUID bits as an extension to the interrupt number
 *
 * The NodeID and ChipID together form a 5-bit Processor Chip ID as
 * found in the PIR or in the SPIRA data structures (without the T bit)
 *
 * PSI interrupt numbering scheme:
 * -------------------------------
 *
 * This is tentatively deduced from stuff I found in some SCOM regs
 * and in the BookIV. The PSIHB can be used to specify the 9-bit BUID,
 * the Level is always 0. The doc also says that it prepends the 6-bit
 * PowerBus chipID (Node + T + Chip). I *assume* that it also prepends
 * a 0 in place of the GX bit.
 *
 * OPAL seems to be arbitrarily using a BUID value of 0x3, I shall do
 * the same "just in case" :-)
 *
 * NOTE: From grep'ing around the giant SCOM file for "Build", I found
 *       what looks like a register in the GX controller (Mode1
 *       register) where the PSI BUID can be stored as well. From
 *       looking around with the FSP getscom command, it appears
 *       that both pHyp and OPAL set this consistently to the same
 *       value that appears in the PHB configuration.
 *
 * => This is confirmed. The NX needs a similar configuration, this
 *    tells the GX controller not to forward transactions for these
 *    BUIDs down the GX bus.
 *
 * PCI interrupt numbering scheme:
 * -------------------------------
 *
 * See IOCs
 *
 * NX interrupt numbering scheme (p7+):
 * ------------------------------------
 *
 * TBD
 *
 * 
 * Additional note about routing of interrupts in P7 and P7+
 * =========================================================
 *
 * There are two on-chip sources of interrupts on these that need a
 * special treatment: The PSI interrupt and the NX interrupts.
 *
 * The problem is that they use the same BUID space as the IO chips
 * connected to the GX bus, so the GX controller needs to be told
 * about these BUIDs in order to avoid forwarding them down the GX
 * link (and possibly choking due to the lack of reply).
 *
 * The bad news is that it's all undocumented. The good news is that
 * I found the info after chatting with Bill Daly (HW design) and
 * looking at the SCOM register maps.
 *
 * The way to set that up differs between P7 and P7+:
 *
 * - On P7, it's in the GX_MODE1 register at SCOM 0x0201180A, which
 *   among other things, contains those bits:
 *
 *     18:26 PSI_BUID: BUID to be used to indicate the interrupt is
 *                     for the PSI
 *        27 DISABLE_PSI_BUID: set to 1 to disable the buid reservation
 *                             for PSI
 *
 *   So one must write the 9-bit BUID (without the top chipID) of the
 *   PSI interrupt in there and clear the disable bit.
 *
 * - On P7+ it's in the GX_MODE4 register at SCOM 0x02011811
 *
 *         0 ENABLE_NX_BUID: set to 1 to enable the buid reservation for nx
 *       1:9 NX_BUID_BASE: BUID BASE to be used to indicate the interrupt
 *                         is for the nx
 *     10:18 NX_BUID_MASK: BUID mask for the nx buid base
 *     19:27 PSI_BUID: BUID to be used to indicate the interrupt is for
 *                     the PSI
 *        28 DISABLE_PSI_BUID: set to 1 to disable the buid reservation
 *                             for PSI
 *
 * Note: The NX_BUID_MASK should have bits set to 1 that are relevant for
 *       the comparison to NX_BUID_BASE, ie 4 interrupts means a mask
 *       value of b'111111100
 */

#define P7_PSI_IRQ_BUID	0x3	/* 9-bit BUID for the PSI interrupts */

/* Extract individual components of an IRQ number */
#define P7_IRQ_BUID(irq)	(((irq) >>  4) & 0x1ff)
#define P7_IRQ_GXID(irq)	(((irq) >> 13) & 0x1)
#define P7_IRQ_CHIP(irq)	(((irq) >> 14) & 0x3)
#define P7_IRQ_TBIT(irq)	(((irq) >> 16) & 0x1)
#define P7_IRQ_NODE(irq)	(((irq) >> 17) & 0x7)

/* Extract the "full BUID" (extension + BUID) */
#define P7_IRQ_FBUID(irq)	(((irq) >> 4) & 0xffff)

/* BUID Extension (GX + CHIP + T + NODE) */
#define P7_IRQ_BEXT(irq)	(((irq) >> 13) & 0x7f)

/* Strip extension from BUID */
#define P7_BUID_BASE(buid)	((buid) & 0x1ff)


/* Note about interrupt numbers on P8
 * ==================================
 *
 * On P8 the interrupts numbers are just a flat space of 19-bit,
 * there is no BUID or similar.
 *
 * However, various unit tend to require blocks of interrupt that
 * are naturally power-of-two aligned
 *
 * Our P8 Interrupt map consits thus of dividing the chip space
 * into "blocks" of 2048 interrupts. Block 0 is for random chip
 * interrupt sources (NX, PSI, OCC, ...) and keeps sources 0..15
 * clear to avoid conflits with IPIs etc.... Block 1..n are assigned
 * to PHB 0..n respectively. The number of blocks is determined by the
 * number of bits assigned to chips.
 *
 * That gives us an interrupt number made of:
 *  18               n+1 n   11  10                         0
 *  |                  | |    | |                           |
 * +--------------------+------+-----------------------------+
 * |        Chip#       | PHB# |             IVE#            |
 * +--------------------+------+-----------------------------+
 *
 * Where n = 18 - p8_chip_id_bits
 *
 * For P8 we have 6 bits for Chip# as defined by p8_chip_id_bits. We
 * therefore support a max of 2^6 = 64 chips.
 *
 * For P8NVL we have an extra PHB and so we assign 5 bits for Chip#
 * and therefore support a max of 32 chips.
 *
 * Each PHB supports 2K interrupt sources, which is shared by
 * LSI and MSI. With default configuration, MSI would use range
 * [0, 0x7f7] and LSI would use [0x7f8, 0x7ff]. The interrupt
 * source should be combined with IRSN to form final hardware
 * IRQ.
 *
 */

uint32_t p8_chip_irq_block_base(uint32_t chip, uint32_t block);
uint32_t p8_chip_irq_phb_base(uint32_t chip, uint32_t phb);
uint32_t p8_irq_to_chip(uint32_t irq);
uint32_t p8_irq_to_block(uint32_t irq);
uint32_t p8_irq_to_phb(uint32_t irq);

/* Total number of bits in the P8 interrupt space */
#define P8_IRQ_BITS		19

/* Number of bits per block */
#define P8_IVE_BITS		11

#define P8_IRQ_BLOCK_MISC	0
#define P8_IRQ_BLOCK_PHB_BASE	1

/* Assignment of the "MISC" block:
 * -------------------------------
 *
 * PSI interface has 6 interrupt sources:
 *
 * FSP, OCC, FSI, LPC, Local error, Host error
 *
 * and thus needs a block of 8
 */
#define P8_IRQ_MISC_PSI_BASE		0x10	/* 0x10..0x17 */

/* These are handled by skiboot */
#define P8_IRQ_PSI_SKIBOOT_BASE		0
#define P8_IRQ_PSI_FSP			0
#define P8_IRQ_PSI_OCC			1
#define P8_IRQ_PSI_FSI			2
#define P8_IRQ_PSI_LPC			3
#define P8_IRQ_PSI_LOCAL_ERR		4
#define P8_IRQ_PSI_LOCAL_COUNT		5
#define P8_IRQ_PSI_ALL_COUNT		6

/* TBD: NX, AS, ...
 */
/* These are passed onto Linux */
#define P8_IRQ_PSI_LINUX_BASE		5
#define P8_IRQ_PSI_HOST_ERR		5	/* Used for UART */
#define P8_IRQ_PSI_LINUX_COUNT		1

/* Note about interrupt numbers on P9
 * ==================================
 *
 * P9 uses a completely different interrupt controller, XIVE.
 *
 * It targets objects using a combination of block number and
 * index within a block. However, we try to avoid exposing that
 * split to the OS in order to keep some abstraction in case the
 * way we allocate these change.
 *
 * The lowest level entity in Xive is the ESB (state bits).
 *
 * Those are spread between PHBs, PSI bridge and XIVE itself which
 * provide a large amount of state bits for IPIs and other SW and HW
 * generated interrupts by sources that don't have their own ESB logic
 *
 * Due to that spread, they aren't a good representation of a global
 * interrupt number.
 *
 * Each such source however needs to be targetted at an EAS (IVT)
 * entry in a table which will control targetting information and
 * associate that interrupt with a logical number.
 *
 * Thus that table entry number represents a good "global interrupt
 * number". Additionally, for the host OS, we will keep the logical
 * number equal to the global number.
 *
 * The details of how these are assigned on P9 can be found in
 * hw/xive.c. P9 HW will only use a subset of the definitions and
 * functions in this file (or the corresponding core/interrupts.c).
 */

struct irq_source;

/*
 * IRQ sources register themselves here. If an "interrupts" callback
 * is provided, then all interrupts in that source will appear in
 * 'opal-interrupts' and will be handled by us.
 *
 * The "eoi" callback is optional and can be used for interrupts
 * requiring a special EOI at the source level. Typically will
 * be used for XIVE interrupts coming from PHBs.
 */
struct irq_source_ops {
	int64_t (*set_xive)(struct irq_source *is, uint32_t isn,
			    uint16_t server, uint8_t priority);
	int64_t (*get_xive)(struct irq_source *is, uint32_t isn,
			    uint16_t *server, uint8_t *priority);
	void (*interrupt)(struct irq_source *is, uint32_t isn);
	void (*eoi)(struct irq_source *is, uint32_t isn);
};

struct irq_source {
	uint32_t			start;
	uint32_t			end;
	const struct irq_source_ops	*ops;
	void				*data;
	struct list_node		link;
};

extern void __register_irq_source(struct irq_source *is);
extern void register_irq_source(const struct irq_source_ops *ops, void *data,
				uint32_t start, uint32_t count);
extern void unregister_irq_source(uint32_t start, uint32_t count);
extern void adjust_irq_source(struct irq_source *is, uint32_t new_count);

extern uint32_t get_psi_interrupt(uint32_t chip_id);

extern struct dt_node *add_ics_node(void);
extern void add_opal_interrupts(void);
extern uint32_t get_ics_phandle(void);

struct cpu_thread;

extern void reset_cpu_icp(void);
extern void icp_send_eoi(uint32_t interrupt);
extern void icp_prep_for_rvwinkle(void);
extern void icp_kick_cpu(struct cpu_thread *cpu);

extern void init_interrupts(void);

extern bool irq_source_eoi(uint32_t isn);


#endif /* __INTERRUPTS_H */
