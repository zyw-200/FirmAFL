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
 * This inits are in part auto-generated from tables coming
 * from the HW guys, then hand updated
 */
#include <skiboot.h>
#include <p7ioc.h>
#include <p7ioc-regs.h>
#include <io.h>
#include <processor.h>
#include <timebase.h>

#undef DUMP_CI_ROUTING
#undef DUMP_REG_WRITES

#ifdef DUMP_REG_WRITES
#define REGW(offset, value)     do {                            \
                out_be64(ioc->regs + (offset), (value));        \
		printf("  REGW: %06lx=%016lx RB: %016llx\n",	\
		       (unsigned long)(offset),			\
		       (unsigned long)(value),			\
		       in_be64(ioc->regs + (offset)));		\
		in_be64(ioc->regs + (offset));			\
        } while(0)
#else
#define REGW(offset, value)     do {                            \
                out_be64(ioc->regs + (offset), (value));        \
		in_be64(ioc->regs + (offset));			\
        } while(0)
#endif
#define REGR(offset)	in_be64(ioc->regs + (offset))

static void p7ioc_init_BI(struct p7ioc *ioc)
{
	printf("P7IOC: Init BI...\n");

        /*** General settings ***/

        /* Init_1 and Init_2: Different between P7 and P7+ */
        if (PVR_TYPE(mfspr(SPR_PVR)) == PVR_TYPE_P7P) {
		printf("P7IOC:   -> Configured for P7+\n");

                /* Chicken switches */
                REGW(0x3c00d8, 0x0004000000000600UL);
                /* GX config */
                REGW(0x3c00a0, 0x9F8929BE00880085UL);
        } else {
		printf("P7IOC:   -> Configured for P7\n");

                /* P7 setting assumes "early write done" mode is
                 * enabled in the GX controller. It seems to be
                 * the case but maybe we want to check/set it via
                 * xscom ?
                 */
                /* Chicken switches */
                REGW(0x3c00d8, 0x00040000000004C0UL);
                /* GX config */
                REGW(0x3c00a0, 0x9C8929BE00880085UL);
        }

	/*
	 * Note: While running skiboot on Firebird-L, I have
	 * to print something or wait for a while. The root
	 * cause wasn't identified yet.
	 */
	time_wait_ms(100);

        /* Init_3: Upbound Credit Config */
        REGW(0x3c00c8, 0x0303060403030000UL);
        /* Init_4: Credit Init Timer */
        REGW(0x3c00e8, 0x00000000000000FFUL);

        /* Init_4.1: BI Ack Timing */
        REGW(0x3c00e8, 0x0000FC0000000000UL);
        /* Init_5: Ordering Override 0*/
        REGW(0x3c0200, 0x0000000000000000UL);
        /* Init_6: Ordering Override 1*/
        REGW(0x3c0208, 0x0000000000000000UL);

        /*** Downbound TTYPE table ***/

        /* Init_7: Enable sequence / speculation for CI Loads */
        REGW(0x3c00a8, 0x0000000000000004UL);
        /* Init_8: */
        REGW(0x3c00b0, 0x700800C000000000UL);
        /* Init_9: Enable sequence / speculation for CI Stores */
        REGW(0x3c00a8, 0x0000000000000005UL);
        /* Init_10: */
        REGW(0x3c00b0, 0x704820C000000000UL);
        /* Init_11: Enable speculation for EOI */
        REGW(0x3c00a8, 0x000000000000001BUL);
        /* Init_12: */
        REGW(0x3c00b0, 0x3590204000000000UL);
        /* Init_13: ENable speculation for DMA Rd Responses */
        REGW(0x3c00a8, 0x0000000000000020UL);
        /* Init_14: */
        REGW(0x3c00b0, 0x1103C4C000000000UL);
        /* Init_15: Enable sequence for DMA RWNITC */
        REGW(0x3c00a8, 0x0000000000000001UL);
        /* Init_16: */
        REGW(0x3c00b0, 0xC000000000000000UL);
        /* Init_17: Enable sequence for IOKill */
        REGW(0x3c00a8, 0x0000000000000009UL);
        /* Init_18: */
        REGW(0x3c00b0, 0x4208210000000000UL);
        /* Init_19: Enable sequence for IOKill */
        REGW(0x3c00a8, 0x000000000000000AUL);
        /* Init_20: */
        REGW(0x3c00b0, 0x4200210000000000UL);
        /* Init_21: Enable sequence for FMTC CI Store w/Kill */
        REGW(0x3c00a8, 0x0000000000000021UL);

        /*** Timer controls ***/

        /* Init_22: */
        REGW(0x3c00b0, 0x4200300000000000UL);
        /* Init_23: Dnbound timer mask */
        REGW(0x3c0190, 0x0040000000000000UL);
        /* Init_24: Upbound timer mask 0 */
        REGW(0x3c0180, 0x0010001000100010UL);
        /* Init_25: Upbound timer mask 1 */
        REGW(0x3c0188, 0x0010000000000000UL);
        /* Init_26: Credit sync check config */
        REGW(0x3c00f0, 0xC102000000000000UL);

        /*** Setup trace ***/

        /* Init_27: DBG stop trace */
        REGW(0x3c0410, 0x4000000000000000UL);
        /* Init_28: DBG control */
        REGW(0x3c0400, 0x0000000000000000UL);
        /* Init_29: DBG Mode */
        REGW(0x3c0408, 0xA0000000F0CC3300UL);
        /* Init_29a: DBG C0 (Stop on Error) */
        REGW(0x3c0418, 0xF4F00FFF00000000UL);
        /* Init_30: DBG pre-mux select */
        REGW(0x3c0478, 0x0023000000000000UL);
        /* Init_31: CA0 mode */
        REGW(0x3c04b0, 0x8000000000000000UL);
        /* Init_32: CA0 Compression 0 */
        REGW(0x3c04b8, 0x0000000000000000UL);
        /* Init_33: CA0 Compression 1 */
        REGW(0x3c04c0, 0x0000000000000000UL);
        /* Init_34: CA0 Pattern A march (cmd1 selected val) */
        REGW(0x3c0480, 0x008000007FFFFF00UL);
        /* Init_35: CA0 Trigger 0 definition (pattern A) */
        REGW(0x3c04a0, 0x8000000000000000UL);
        /* Init_36: CA1 mode */
        REGW(0x3c0530, 0x8000000000000000UL);
        /* Init_37: CA1 Compression 0 */
        REGW(0x3c0538, 0x0000000000000000UL);
        /* Init_38: CA1 Compression 1 */
        REGW(0x3c0540, 0x0000000000000000UL);
        /* Init_39: CA2 mode */
        REGW(0x3c05b0, 0x8000000000000000UL);
        /* Init_40: CA2 Compression 0 */
        REGW(0x3c05b8, 0x0000000000000000UL);
        /* Init_41: CA2 Compression 1 */
        REGW(0x3c05c0, 0x0000000000000000UL);
        /* Init_42: CA3 Mode */
        REGW(0x3c0630, 0x8000000000000000UL);
        /* Init_43: CA3 Compression 0 */
        REGW(0x3c0638, 0x0000000000000000UL);
        /* Init_44: CA3 Compression 1 */
        REGW(0x3c0640, 0x0000000000000000UL);
        /* Init_45: CA3 Pattern A match (AIB val) */
        REGW(0x3c0600, 0x80000100FFFEFF00UL);
        /* Init_46: CA3 Trigger 0 definition (pattern A) */
        REGW(0x3c0620, 0x8000000000000000UL);
        /* Init_47: DBG unfreeze trace */
        REGW(0x3c0410, 0x1000000000000000UL);
        /* Init_48: DBG start trace */
        REGW(0x3c0410, 0x8000000000000000UL);

        /*** AIB Port Config ***/

        /* Init_49: AIB Port Information */
        REGW(0x3c00d0, 0x0888888800000000UL);
        /* Init_50: Port Ordering controls */
        REGW(0x3c0200, 0x0000000000000000UL);

        /*** LEMs (need to match recov. tables) ***/

        /* Init_51: Clear upbound LEM */
        REGW(0x3c0000, 0x0000000000000000UL);
        /* Init_52: Clear upbound WOF */
        REGW(0x3c0040, 0x0000000000000000UL);
        /* Init_53: Clear Dnbound LEM */
        REGW(0x3c0050, 0x0000000000000000UL);
        /* Init_54: Clear Dnbound WOF */
        REGW(0x3c0090, 0x0000000000000000UL);
        /* Init_55: Clear Fences */
        REGW(0x3c0130, 0x0000000000000000UL);
        /* Init_56: Clear Erpt latches */
        REGW(0x3c0148, 0x0080000000000000UL);
        /* Init_57: Set Upbound LEM Action0 */
        REGW(0x3c0030, 0x0800000000800000UL);
        /* Init_58: Set Upbound LEN Action1 */
        REGW(0x3c0038, 0x0000000000000000UL);
        /* Init_59: Set Upbound LEM Mask (AND write) */
        REGW(0x3c0020, 0x0800000000000000UL);
        /* Init_60: Set Dnbound LEM Action0 */
        REGW(0x3c0080, 0x2000080CA07FFF40UL);
        /* Init_61: Set Dnbound LEM Action1 */
        REGW(0x3c0088, 0x0000000000000000UL);
        /* Init_62: Set Dnbound LEM Mask (AND write) */
        REGW(0x3c0070, 0x00000800200FFE00UL);

        /*** Setup Fences (need to match recov. tables) ***/

        /* Init_63: Set Upbound Damage Control 0 (GX Err) */
        REGW(0x3c0100, 0xF7FFFFFFFF7FFFFFUL);
        /* Init_64: Set Upbound Damage Control 1 (AIB Fence) */
        REGW(0x3c0108, 0xF7FFFFFFFF7FFFFFUL);
        /* Init_65: Set Upbound Damage Control 2 (Drop Pkt) */
        REGW(0x3c0110, 0x0010054000000000UL);
        /* Init_66: Set Dnbound Damage Control 0 (GX Err) */
        REGW(0x3c0118, 0xDFFFF7F35F8000BFUL);
        /* Init_67: Set Dnbound Damage Control 1 (AIB Fence) */
        REGW(0x3c0120, 0xDFFFF7F35F8000BFUL);
        /* Init_68: Set Dnbound Damage Control 2 (Drop Pkt) */
        REGW(0x3c0128, 0x0000000C00000000UL);
}

static void p7ioc_init_MISC_HSS(struct p7ioc *ioc)
{
        unsigned int i, regbase;

	printf("P7IOC: Init HSS...\n");

        /* Note: These values might need to be tweaked per system and
         * per physical port depending on electrical characteristics.
         *
         * For now we stick to the defaults provided by the spec.
         */
        for (i = 0; i < P7IOC_NUM_PHBS; i++) {
                regbase = P7IOC_HSS_BASE + i * P7IOC_HSS_STRIDE;

		if (!p7ioc_phb_enabled(ioc, i))
			continue;

                /* Init_1: HSSn CTL2 */
                REGW(regbase + P7IOC_HSSn_CTL2_OFFSET, 0xFFFF6DB6DB000000UL);
                /* Init_2: HSSn CTL3 */
                REGW(regbase + P7IOC_HSSn_CTL3_OFFSET, 0x1130000320000000UL);
                /* Init_3: HSSn CTL8 */
                REGW(regbase + P7IOC_HSSn_CTL8_OFFSET, 0xDDDDDDDD00000000UL);

#if 0 /* All these remain set to the values configured by the FSP */
                /* Init_4: HSSn CTL9 */
                REGW(regbase + P7IOC_HSSn_CTL9_OFFSET, 0x9999999900000000);
                /* Init_5: HSSn CTL10 */
                REGW(regbase + P7IOC_HSSn_CTL10_OFFSET, 0x8888888800000000);
                /* Init_6: HSSn CTL11 */
                REGW(regbase + P7IOC_HSSn_CTL11_OFFSET, 0x4444444400000000);
                /* Init_7: HSSn CTL12 */
                REGW(regbase + P7IOC_HSSn_CTL12_OFFSET, 0x3333333300000000);
                /* Init_8: HSSn CTL13 */
                REGW(regbase + P7IOC_HSSn_CTL13_OFFSET, 0x2222222200000000);
                /* Init_9: HSSn CTL14 */
                REGW(regbase + P7IOC_HSSn_CTL14_OFFSET, 0x1111111100000000);
                /* Init_10: HSSn CTL15 */
                REGW(regbase + P7IOC_HSSn_CTL15_OFFSET, 0x1111111100000000);
                /* Init_11: HSSn CTL16 */
                REGW(regbase + P7IOC_HSSn_CTL16_OFFSET, 0x9999999900000000);
                /* Init_12: HSSn CTL17 */
                REGW(regbase + P7IOC_HSSn_CTL17_OFFSET, 0x8888888800000000);
                /* Init_13: HSSn CTL18 */
                REGW(regbase + P7IOC_HSSn_CTL18_OFFSET, 0xDDDDDDDD00000000);
                /* Init_14: HSSn CTL19 */
                REGW(regbase + P7IOC_HSSn_CTL19_OFFSET, 0xCCCCCCCC00000000);
                /* Init_15: HSSn CTL20 */
                REGW(regbase + P7IOC_HSSn_CTL20_OFFSET, 0xBBBBBBBB00000000);
                /* Init_16: HSSn CTL21 */
		REGW(regbase + P7IOC_HSSn_CTL21_OFFSET, 0x9999999900000000);
                /* Init_17: HSSn CTL22 */
		REGW(regbase + P7IOC_HSSn_CTL22_OFFSET, 0x8888888800000000);
                /* Init_18: HSSn CTL23 */
		REGW(regbase + P7IOC_HSSn_CTL23_OFFSET, 0x7777777700000000);
#endif
	}
}

static void p7ioc_init_RGC(struct p7ioc *ioc)
{
	unsigned int i;
	uint64_t val, cfg;

	printf("P7IOC: Init RGC...\n");

	/*** Clear ERPT Macros ***/
	
	/* Init_1: RGC Configuration reg */
	cfg = REGR(0x3e1c08);
	REGW(0x3e1c08, cfg | PPC_BIT(1));
	time_wait_ms(1);

	/* Init_2: RGC Configuration reg */
	REGW(0x3e1c08, cfg);

	/*** Set LEM regs (needs to match recov. code) */

	/* Init_3: LEM FIR Accumulator */
	REGW(0x3e1e00, 0x0000000000000000UL);
	/* Init_4: LEM Action 0 */
	REGW(0x3e1e30, 0x0FFF791F0B030000UL);
	/* Init_5: LEN Action 1 */
	REGW(0x3e1e38, 0x0000000000000000UL);
	/* Init_6: LEM WOF */
	REGW(0x3e1e40, 0x0000000000000000UL);
	/* Init_7: LEM Mask Reg (AND write) */
	REGW(0x3e1e20, 0x0FFF001F03030000UL);

	/*** Set GEM regs (masks still on, no irpts can occur yet) ***/

	/* Init_8: GEM XFIR */
	REGW(0x3e0008, 0x0000000000000000UL);
	/* Init_9: GEM WOF */
	REGW(0x3e0028, 0x0000000000000000UL);

	/*** Set Damage Controls (needs to match recov.) ***/

	/* Init_10: LDCP */
	REGW(0x3e1c18, 0xF00086C0B4FCFFFFUL);

	/*** Read status (optional) ***/

	/* Init_11: Read status */
	val = REGR(0x3e1c10);
	printf("P7IOC:   Init_11 Status: %016llx\n", val);

	/*** Set running configuration **/

	/* Init_12: Configuration reg (modes, values, timers) */
	REGW(0x3e1c08, 0x10000077CE100000UL);

	/* Init_13: Cmd/Dat Crd Allocation */
	REGW(0x3e1c20, 0x00000103000700FFUL);
	/* Init_14: GP reg - disable errs, wrap, stop_trc */
	REGW(0x3e1018, 0x0000000000000000UL);
	/* Init_15: Configuration reg (start init timers) */
	cfg = REGR(0x3e1c08);
	REGW(0x3e1c08, cfg | 0x00003f0000000000UL);

	/*** Setup  interrupts ***/

	/* Init_16: BUID Register
	 *
	 * XXX NOTE: This needs to be clarified. According to the doc
	 * the register contains a 9-bit BUID, which makes sense so far.
	 *
	 * However, the initialization sequence says "depends on which
	 * GX bus) which doesn't since afaik the GX bus number is encoded
	 * in the BUID Extension bit which is right *above* the 9-bit
	 * BUID in the interrupt message.
	 *
	 * So I must be missing something here... For now I'll just
	 * write my 9-bit BUID and we'll see what happens.
	 *
	 */
	REGW(0x3e1800, (uint64_t)ioc->rgc_buid << PPC_BITLSHIFT(31));

	/* Init_17: Supposed to lock the IODA table but we aren't racing
	 *          with anybody so there is little point.
	 *
	 * Note: If/when we support some kind of error recovery that
	 *       involves re-initializing the IOC, then we might have
	 *       to take some locks but it's assumed that the necessary
	 *       lock(s) will be obtained by the caller.
	 */
	//REGR(0x3e1840, 0x0000000000000000);

	/* Init_18: IODA Table Addr: Select IST*/
	REGW(0x3e1820, 0x8001000000000000UL);
	/* Init_19: IODA Table Data: IRPT 0 */
	REGW(0x3e1830, 0x0000000000000000UL);
	/* Init_20: IODA Table Data: IRPT 1 */
	REGW(0x3e1830, 0x0000000000000000UL);
	/* Init_21: IODA Table Addr: Select HRT */
	REGW(0x3e1820, 0x8000000000000000UL);
	/* Init_22: IODA Table Data: HRT
	 *
	 * XXX Figure out what this actually is and what value should
	 *     we use. For now, do like BML and use 0
	 */
	for (i = 0; i < 4; i++)
		REGW(0x3e1830, 0x0000000000000000UL);

	/* Init_23: IODA Table Addr: select XIVT */
	REGW(0x3e1820, 0x8002000000000000UL);
	/* Init_24: IODA Table Data: Mask all interrupts */
	for (i = 0; i < 16; i++)
		REGW(0x3e1830, 0x000000ff00000000UL);

	/* Init_25: Clear table lock if any was stale */
	REGW(0x3e1840, 0x0000000000000000UL);

	/* Init_32..37: Set the PHB AIB addresses. We configure those
	 * to the values recommended in the p7IOC doc.
	 *
	 * XXX NOTE: I cannot find a documentation for these, I assume
	 * they just take the full 64-bit address, but we may want to
	 * dbl check just in case (it seems to be what BML does but
	 * I'm good at mis-reading Milton's Perl).
	 */
	for (i = 0; i < P7IOC_NUM_PHBS; i++) {
		if (!p7ioc_phb_enabled(ioc, i))
			continue;
		REGW(0x3e1080 + (i << 3),
		     ioc->mmio1_win_start + PHBn_AIB_BASE(i));
	}
}

static void p7ioc_init_ci_routing(struct p7ioc *ioc)
{
	unsigned int i, j = 0;
	uint64_t rmatch[47];
	uint64_t rmask[47];
	uint64_t pmask;

	/* Init_130: clear all matches (except 47 which routes to the RGC) */
	for (i = 0; i < 47; i++) {
		rmatch[i] = REGR(P7IOC_CI_RMATC_REG(i)) &
			~(P7IOC_CI_RMATC_ADDR_VALID |
			  P7IOC_CI_RMATC_BUID_VALID |
			  P7IOC_CI_RMATC_TYPE_VALID);
		rmask[i] = 0;
		REGW(P7IOC_CI_RMATC_REG(i), rmatch[i]);
	}

	/* Init_131...224: configure routing for everything except RGC
	 *
	 * We are using a slightly different routing setup than the
	 * example to make the code easier. We configure all PHB
	 * routing entries by doing all of PHB0 first, then all of PHB1
	 * etc...
	 *
	 * Then we append everything else except the RGC itself which
	 * remains hard wired at entry 47. So the unused entries live
	 * at 39..46.
	 *
	 *  -      0 : PHB0 LSI BUID
	 *  -      1 : PHB0 MSI BUID
	 *  -      2 : PHB0 AIB Registers
	 *  -      3 : PHB0 IO Space
	 *  -      4 : PHB0 M32 Space
	 *  -      5 : PHB0 M64 Space
	 *  -  6..11 : PHB1
	 *  - 12..17 : PHB2
	 *  - 18..23 : PHB3
	 *  - 24..29 : PHB4
	 *  - 30..35 : PHB5
	 *  -     36 : Invalidates broadcast (FMTC)
	 *  -     37 : Interrupt response for RGC
	 *  -     38 : RGC GEM BUID
	 *  - 39..46 : Unused (alternate M64 ?)
	 *  -     47 : RGC ASB Registers (catch all)
	 */

	/* Helper macro to set a rule */
#define CI_ADD_RULE(p, k, d, m)	do {				\
		rmask[j] = P7IOC_CI_RMATC_ENCODE_##k(m);	\
		rmatch[j]= P7IOC_CI_RMATC_PORT(p)     |		\
			   P7IOC_CI_RMATC_##k##_VALID |		\
			   P7IOC_CI_RMATC_ENCODE_##k(d);	\
		j++;						\
	} while (0)

	pmask = 0;
	for (i = 0; i < P7IOC_NUM_PHBS; i++) {
		unsigned int buid_base = ioc->buid_base + PHBn_BUID_BASE(i);

		if (!p7ioc_phb_enabled(ioc, i))
			continue;

		/* LSI BUIDs, match all 9 bits (1 BUID per PHB) */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), BUID,
			    buid_base + PHB_BUID_LSI_OFFSET, 0x1ff);

		/* MSI BUIDs, match 4 bits (16 BUIDs per PHB) */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), BUID,
			    buid_base + PHB_BUID_MSI_OFFSET, 0x1f0);

		/* AIB reg space */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), ADDR,
			    ioc->mmio1_win_start + PHBn_AIB_BASE(i),
			    ~(PHBn_AIB_SIZE - 1));

		/* IO space */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), ADDR,
			    ioc->mmio1_win_start + PHBn_IO_BASE(i),
			    ~(PHB_IO_SIZE - 1));

		/* M32 space */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), ADDR,
			    ioc->mmio2_win_start + PHBn_M32_BASE(i),
			    ~(PHB_M32_SIZE - 1));

		/* M64 space */
		CI_ADD_RULE(P7IOC_CI_PHB_PORT(i), ADDR,
			    ioc->mmio2_win_start + PHBn_M64_BASE(i),
			    ~(PHB_M64_SIZE - 1));

		/* For use with invalidate bcasts */
		pmask |= P7IOC_CI_PHB_PORT(i);
	}

	/* Invalidates broadcast to all PHBs */
	CI_ADD_RULE(pmask, TYPE, 0x80, 0xf0);

	/* Interrupt responses go to RGC */
	CI_ADD_RULE(P7IOC_CI_RGC_PORT, TYPE, 0x60, 0xf0);

	/* RGC GEM BUID (1 BUID) */
	CI_ADD_RULE(P7IOC_CI_RGC_PORT, BUID, ioc->rgc_buid, 0x1ff);

	/* Program the values masks first */
	for (i = 0; i < 47; i++)
		REGW(P7IOC_CI_RMASK_REG(i), rmask[i]);
	for (i = 0; i < 47; i++)
		REGW(P7IOC_CI_RMATC_REG(i), rmatch[i]);

	/* Init_225: CI Match 47 (Configure RGC catch all) */
	REGW(P7IOC_CI_RMASK_REG(47), 0x0000000000000000UL);
	REGW(P7IOC_CI_RMATC_REG(47), 0x4000800000000000UL);

#ifdef DUMP_CI_ROUTING
	printf("P7IOC: CI Routing table:\n");
	for (i = 0; i < 48; i++)
		printf("  [%.2d] MTCH: %016llx MSK: %016llx\n", i,
		       REGR(P7IOC_CI_RMATC_REG(i)),
		       REGR(P7IOC_CI_RMASK_REG(i)));
#endif /* DUMP_CI_ROUTING */
}

static void p7ioc_init_CI(struct p7ioc *ioc)
{
	printf("P7IOC: Init CI...\n");

	/*** Clear ERPT macros ***/

	/* XXX NOTE: The doc seems to also provide "alternate freq ratio"
	 * settings. Not sure what they are about, let's stick to the
	 * original values for now.
	 */

	/* Init_1: CI Port 0 Configuration */
	REGW(0x3d0000, 0x420000C0073F0002UL);
	/* Init_2: CI Port 0 Configuration */
	REGW(0x3d0000, 0x020000C0073F0002UL);
	/* Init_3: CI Port 1 Configuration */
	REGW(0x3d1000, 0x42000FCF07200002UL);
	/* Init_4: CI Port 1 Configuration */
	REGW(0x3d1000, 0x02000FCF07200002UL);
	/* Init_5: CI Port 2 Configuration */
	REGW(0x3d2000, 0x420000C307200002UL);
	/* Init_6: CI Port 2 Configuration */
	REGW(0x3d2000, 0x020000C307200002UL);
	/* Init_7: CI Port 3 Configuration */
	REGW(0x3d3000, 0x420000C307200002UL);
	/* Init_8: CI Port 3 Configuration */
	REGW(0x3d3000, 0x020000C307200002UL);
	/* Init_9: CI Port 4 Configuration */
	REGW(0x3d4000, 0x420000C307200002UL);
	/* Init_10: CI Port 4 Configuration */
	REGW(0x3d4000, 0x020000C307200002UL);
	/* Init_11: CI Port 5 Configuration */
	REGW(0x3d5000, 0x420000C307200002UL);
	/* Init_12: CI Port 5 Configuration */
	REGW(0x3d5000, 0x020000C307200002UL);
	/* Init_13: CI Port 6 Configuration */
	REGW(0x3d6000, 0x420000C307200002UL);
	/* Init_14: CI Port 6 Configuration */
	REGW(0x3d6000, 0x020000C307200002UL);
	/* Init_15: CI Port 7 Configuration */
	REGW(0x3d7000, 0x420000C307200002UL);
	/* Init_16: CI Port 7 Configuration */
	REGW(0x3d7000, 0x020000C307200002UL);

	/*** Set LEM regs (need to match recov.) ***/

	/* Init_17: CI Port 0 LEM FIR Accumulator */
	REGW(0x3d0200, 0x0000000000000000UL);
	/* Init_18: CI Port 0 LEM Action 0 */
	REGW(0x3d0230, 0x0A00000000000000UL);
	/* Init_19: CI Port 0 LEM Action 1 */
	REGW(0x3d0238, 0x0000000000000000UL);
	/* Init_20: CI Port 0 LEM WOF */
	REGW(0x3d0240, 0x0000000000000000UL);
	/* Init_21: CI Port 0 LEM Mask (AND write) */
	REGW(0x3d0220, 0x0200000000000000UL);
	/* Init_22: CI Port 1 LEM FIR Accumularor */
	REGW(0x3d1200, 0x0000000000000000UL);
	/* Init_23: CI Port 1 LEM Action 0 */
	REGW(0x3d1230, 0x0000000000000000UL);
	/* Init_24: CI Port 1 LEM Action 1 */
	REGW(0x3d1238, 0x0000000000000000UL);
	/* Init_25: CI Port 1 LEM WOF */
	REGW(0x3d1240, 0x0000000000000000UL);
	/* Init_26: CI Port 1 LEM Mask (AND write) */
	REGW(0x3d1220, 0x0000000000000000UL);
	/* Init_27: CI Port 2 LEM FIR Accumulator */
	REGW(0x3d2200, 0x0000000000000000UL);
	/* Init_28: CI Port 2 LEM Action 0 */
	REGW(0x3d2230, 0xA4F4000000000000UL);
	/* Init_29: CI Port 2 LEM Action 1 */
	REGW(0x3d2238, 0x0000000000000000UL);
	/* Init_30: CI Port 2 LEM WOF */
	REGW(0x3d2240, 0x0000000000000000UL);
	/* Init_31: CI Port 2 LEM Mask (AND write) */
	REGW(0x3d2220, 0x0000000000000000UL);
	/* Init_32: CI Port 3 LEM FIR Accumulator */
	REGW(0x3d3200, 0x0000000000000000UL);
	/* Init_33: CI Port 3 LEM Action 0 */
	REGW(0x3d3230, 0xA4F4000000000000UL);
	/* Init_34: CI Port 3 LEM Action 1 */
	REGW(0x3d3238, 0x0000000000000000UL);
	/* Init_35: CI Port 3 LEM WOF */
	REGW(0x3d3240, 0x0000000000000000UL);
	/* Init_36: CI Port 3 LEM Mask (AND write) */
	REGW(0x3d3220, 0x0000000000000000UL);
	/* Init_37: CI Port 4 LEM FIR Accumulator */
	REGW(0x3d4200, 0x0000000000000000UL);
	/* Init_38: CI Port 4 Action 0 */
	REGW(0x3d4230, 0xA4F4000000000000UL);
	/* Init_39: CI Port 4 Action 1 */
	REGW(0x3d4238, 0x0000000000000000UL);
	/* Init_40: CI Port 4 WOF */
	REGW(0x3d4240, 0x0000000000000000UL);
	/* Init_41: CI Port 4 Mask (AND write) */
	REGW(0x3d4220, 0x0000000000000000UL);
	/* Init_42: CI Port 5 LEM FIR Accumulator */
	REGW(0x3d5200, 0x0000000000000000UL);
	/* Init_43: CI Port 5 Action 0 */
	REGW(0x3d5230, 0xA4F4000000000000UL);
	/* Init_44: CI Port 5 Action 1 */
	REGW(0x3d5238, 0x0000000000000000UL);
	/* Init_45: CI Port 4 WOF */
	REGW(0x3d5240, 0x0000000000000000UL);
	/* Init_46: CI Port 5 Mask (AND write) */
	REGW(0x3d5220, 0x0000000000000000UL);
	/* Init_47: CI Port 6 LEM FIR Accumulator */
	REGW(0x3d6200, 0x0000000000000000UL);
	/* Init_48: CI Port 6 Action 0 */
	REGW(0x3d6230, 0xA4F4000000000000UL);
	/* Init_49: CI Port 6 Action 1 */
	REGW(0x3d6238, 0x0000000000000000UL);
	/* Init_50: CI Port 6 WOF */
	REGW(0x3d6240, 0x0000000000000000UL);
	/* Init_51: CI Port 6 Mask (AND write) */
	REGW(0x3d6220, 0x0000000000000000UL);
	/* Init_52: CI Port 7 LEM FIR Accumulator */
	REGW(0x3d7200, 0x0000000000000000UL);
	/* Init_53: CI Port 7 Action 0 */
	REGW(0x3d7230, 0xA4F4000000000000UL);
	/* Init_54: CI Port 7 Action 1 */
	REGW(0x3d7238, 0x0000000000000000UL);
	/* Init_55: CI Port 7 WOF */
	REGW(0x3d7240, 0x0000000000000000UL);
	/* Init_56: CI Port 7 Mask (AND write) */
	REGW(0x3d7220, 0x0000000000000000UL);

	/*** Set Damage Controls (need match recov.) ***/

	/* Init_57: CI Port 0 LDCP*/
	REGW(0x3d0010, 0x421A0000000075FFUL);
	/* Init_58: CI Port 1 LDCP */
	REGW(0x3d1010, 0x421A000000007FFFUL);
	/* Init_59: CI Port 2 LDCP */
	REGW(0x3d2010, 0x421A24F400005B0BUL);
	/* Init_60: CI Port 3 LDCP */
	REGW(0x3d3010, 0x421A24F400005B0BUL);
	/* Init_61: CI Port 4 LDCP */
	REGW(0x3d4010, 0x421A24F400005B0BUL);
	/* Init_62: CI Port 5 LDCP */
	REGW(0x3d5010, 0x421A24F400005B0BUL);
	/* Init_63: CI Port 6 LDCP */
	REGW(0x3d6010, 0x421A24F400005B0BUL);
	/* Init_64: CI Port 7 LDCP */
	REGW(0x3d7010, 0x421A24F400005B0BUL);

	/*** Setup Trace 0 ***/

	/* Init_65: CI Trc 0 DBG - Run/Status (stop trace) */
	REGW(0x3d0810, 0x5000000000000000UL);
	/* Init_66: CI Trc 0 DBG - Mode (not cross trig CA's) */
	REGW(0x3d0808, 0xB0000000F0000000UL);
	/* Init_66a: CI Trc 0 DBG - C0 (stop on error) */
	REGW(0x3d0818, 0xF4F00FFF00000000UL);
	/* Init_67: CI Trc 0 DBG - Select (port 0 mode 2) */
	REGW(0x3d0878, 0x0002000000000000UL);
	/* Init_68: CI Trc 0 CA0 - Pattern A (RX cmd val) */
	REGW(0x3d0880, 0xC0200000DFFFFF00UL);
	/* Init_69: CI Trc 0 CA0 - Trigger 0 (Pattern A) */
	REGW(0x3d08a0, 0x8000000000000000UL);
	/* Init_70: CI Trc 0 - Mode */
	REGW(0x3d08b0, 0x8000000000000000UL);
	/* Init_71: CI Trc 0 CA1 - Pattern A (TX cmd val) */
	REGW(0x3d0900, 0xC0200000DFFFFF00UL);
	/* Init_72: CI Trc 0 CA1 - Trigger 0 (Pattern A) */
	REGW(0x3d0920, 0x8000000000000000UL);
	/* Init_73: CI Trc 0 CA1 - Mode */
	REGW(0x3d0930, 0x8000000000000000UL);
	/* Init_74: CI Trc 0 DBG - Run/Status (start trace) */
	REGW(0x3d0810, 0x8000000000000000UL);

	/*** Setup Trace 1 ***/

	/* Init_75: CI Trc 1 DBG - Run/Status (stop trace) */
	REGW(0x3d0c10, 0x5000000000000000UL);
	/* Init_76: CI Trc 1 DBG - Mode (not cross trig CA's) */
	REGW(0x3d0c08, 0xB0000000F0000000UL);
	/* Init_76a: CI Trc 1 DBG - C0 (stop on error) */
	REGW(0x3d0c18, 0xF4F00FFF00000000UL);
	/* Init_77: CI Trc 1 DBG - Select (port 1 mode 2) */
	REGW(0x3d0c78, 0x0102000000000000UL);
	/* Init_78: CI Trc 1 CA0 - Pattern A (RX cmd val) */
	REGW(0x3d0c80, 0xC0200000DFFFFF00UL);
	/* Init_79: CI Trc 1 CA0 - Trigger 0 (Pattern A) */
	REGW(0x3d0ca0, 0x8000000000000000UL);
	/* Init_80: CI Trc 1 CA0 - Mode */
	REGW(0x3d0cb0, 0x8000000000000000UL);
	/* Init_81: CI Trc 1 CA1 - Pattern A (TX cmd val) */
	REGW(0x3d0d00, 0xC0200000DFFFFF00UL);
	/* Init_82: CI Trc 1 CA1 - Trigger 0 (Pattern A) */
	REGW(0x3d0d20, 0x8000000000000000UL);
	/* Init_83: CI Trc 1 CA1 - Mode */
	REGW(0x3d0d30, 0x8000000000000000UL);
	/* Init_84: CI Trc 1 DBG - Run/Status (start trace) */
	REGW(0x3d0c10, 0x8000000000000000UL);

	/* Init_85...92:
	 *
	 * XXX NOTE: Here we normally read the Port 0 to 7 status regs
	 * which is optional. Eventually we might want to do it to check
	 * if the status matches expectations
	 *
	 * (regs 0x3d0008 to 0x3d7008)
	 */

	/*** Set buffer allocations (credits) ***/

	/* Init_93: CI Port 0 Rx Cmd Buffer Allocation */
	REGW(0x3d0050, 0x0808040400000000UL);
	/* Init_94: CI Port 0 Rx Dat Buffer Allocation */
	REGW(0x3d0060, 0x0006000200000000UL);
	/* Init_95: CI Port 1 Tx Cmd Buffer Allocation */
	REGW(0x3d1030, 0x0000040400000000UL);
	/* Init_96: CI Port 1 Tx Dat Buffer Allocation */
	REGW(0x3d1040, 0x0000004800000000UL);
	/* Init_97: CI Port 1 Rx Cmd Buffer Allocation */
	REGW(0x3d1050, 0x0008000000000000UL);
	/* Init_98: CI Port 1 Rx Dat Buffer Allocation */
	REGW(0x3d1060, 0x0048000000000000UL);
	/* Init_99: CI Port 2 Tx Cmd Buffer Allocation */
	REGW(0x3d2030, 0x0808080800000000UL);
	/* Init_100: CI Port 2 Tx Dat Buffer Allocation */
	REGW(0x3d2040, 0x0086008200000000UL);
	/* Init_101: CI Port 2 Rx Cmd Buffer Allocation */
	REGW(0x3d2050, 0x0808080800000000UL);
	/* Init_102: CI Port 2 Rx Dat Buffer Allocation */
	REGW(0x3d2060, 0x8648000000000000UL);
	/* Init_103: CI Port 3 Tx Cmd Buffer Allocation */
	REGW(0x3d3030, 0x0808080800000000UL);
	/* Init_104: CI Port 3 Tx Dat Buffer Allocation */
	REGW(0x3d3040, 0x0086008200000000UL);
	/* Init_105: CI Port 3 Rx Cmd Buffer Allocation */
	REGW(0x3d3050, 0x0808080800000000UL);
	/* Init_106: CI Port 3 Rx Dat Buffer Allocation */
	REGW(0x3d3060, 0x8648000000000000UL);
	/* Init_107: CI Port 4 Tx Cmd Buffer Allocation */
	REGW(0x3d4030, 0x0808080800000000UL);
	/* Init_108: CI Port 4 Tx Dat Buffer Allocation */
	REGW(0x3d4040, 0x0086008200000000UL);
	/* Init_109: CI Port 4 Rx Cmd Buffer Allocation */
	REGW(0x3d4050, 0x0808080800000000UL);
	/* Init_110: CI Port 4 Rx Dat Buffer Allocation */
	REGW(0x3d4060, 0x8648000000000000UL);
	/* Init_111: CI Port 5 Tx Cmd Buffer Allocation */
	REGW(0x3d5030, 0x0808080800000000UL);
	/* Init_112: CI Port 5 Tx Dat Buffer Allocation */
	REGW(0x3d5040, 0x0086008200000000UL);
	/* Init_113: CI Port 5 Rx Cmd Buffer Allocation */
	REGW(0x3d5050, 0x0808080800000000UL);
	/* Init_114: CI Port 5 Rx Dat Buffer Allocation */
	REGW(0x3d5060, 0x8648000000000000UL);
	/* Init_115: CI Port 6 Tx Cmd Buffer Allocation */
	REGW(0x3d6030, 0x0808080800000000UL);
	/* Init_116: CI Port 6 Tx Dat Buffer Allocation */
	REGW(0x3d6040, 0x0086008200000000UL);
	/* Init_117: CI Port 6 Rx Cmd Buffer Allocation */
	REGW(0x3d6050, 0x0808080800000000UL);
	/* Init_118: CI Port 6 Rx Dat Buffer Allocation */
	REGW(0x3d6060, 0x8648000000000000UL);
	/* Init_119: CI Port 7 Tx Cmd Buffer Allocation */
	REGW(0x3d7030, 0x0808080800000000UL);
	/* Init_120: CI Port 7 Tx Dat Buffer Allocation */
	REGW(0x3d7040, 0x0086008200000000UL);
	/* Init_121: CI Port 7 Rx Cmd Buffer Allocation */
	REGW(0x3d7050, 0x0808080800000000UL);
	/* Init_122: CI Port 6 Rx Dat Buffer Allocation */
	REGW(0x3d7060, 0x8648000000000000UL);

	/*** Channel ordering ***/

	/* Init_123: CI Port 1 Ordering */
	REGW(0x3d1070, 0x73D0735E00000000UL);
	/* Init_124: CI Port 2 Ordering */
	REGW(0x3d2070, 0x73D0735E00000000UL);
	/* Init_125: CI Port 3 Ordering */
	REGW(0x3d3070, 0x73D0735E00000000UL);
	/* Init_126: CI Port 4 Ordering */
	REGW(0x3d4070, 0x73D0735E00000000UL);
	/* Init_127: CI Port 5 Ordering */
	REGW(0x3d5070, 0x73D0735E00000000UL);
	/* Init_128: CI Port 6 Ordering */
	REGW(0x3d6070, 0x73D0735E00000000UL);
	/* Init_129: CI POrt 7 Ordering */
	REGW(0x3d7070, 0x73D0735E00000000UL);

	/*** Setup routing (port 0 only) */

	p7ioc_init_ci_routing(ioc);

	/*** Set Running Configuration/Crd Init Timers ***
	 *
	 * XXX NOTE: Supposed to only modify bits 8:15
	 */

	/* Init_226: CI Port 1 Configuration */
	REGW(0x3d1000, 0x023F0FCF07200002UL);
	/* Init_227: CI Port 2 Configuration */
	REGW(0x3d2000, 0x023F00C307200002UL);
	/* Init_228: CI Port 3 Configuration */
	REGW(0x3d3000, 0x023F00C307200002UL);
	/* Init_229: CI Port 4 Configuration */
	REGW(0x3d4000, 0x023F00C307200002UL);
	/* Init_230: CI Port 5 Configuration */
	REGW(0x3d5000, 0x023F00C307200002UL);
	/* Init_231: CI Port 6 Configuration */
	REGW(0x3d6000, 0x023F00C307200002UL);
	/* Init_232: CI Port 7 Configuration */
	REGW(0x3d7000, 0x023F00C307200002UL);
	/* Init_233: CI Port 0 Configuration */
	REGW(0x3d0000, 0x023F00C0073F0002UL);
}

static void p7ioc_init_PHBs(struct p7ioc *ioc)
{
	unsigned int i;

	printf("P7IOC: Init PHBs...\n");

	/* We use the same reset sequence that we use for
	 * fast reboot for consistency
	 */
	for (i = 0; i < P7IOC_NUM_PHBS; i++) {
		if (p7ioc_phb_enabled(ioc, i))
			p7ioc_phb_reset(&ioc->phbs[i].phb);
	}
}

static void p7ioc_init_MISC(struct p7ioc *ioc)
{
	printf("P7IOC: Init MISC...\n");

	/*** Set LEM regs ***/

	/* Init_1: LEM FIR Accumulator */
	REGW(0x3ea000, 0x0000000000000000UL);
	/* Init_2: LEM Action 0 */
	REGW(0x3ea030, 0xFFFFFFFCEE3FFFFFUL);
	/* Init_3: LEM Action 1 */
	REGW(0x3ea038, 0x0000000001C00000UL);
	/* Init_4: LEM WOF */
	REGW(0x3ea040, 0x0000000000000000UL);
	/* Init_5: LEM Mask (AND write) */
	REGW(0x3ea020, 0x000F03F0CD3FFFFFUL);
	/* Init_5.1: I2C LEM FIR Accumulator */
	REGW(0x3eb000, 0x0000000000000000UL);
	/* Init_5.2: I2C LEM Action 0 */
	REGW(0x3eb030, 0xEE00000000000000UL);
	/* Init_5.3: I2C LEM Action 1 */
	REGW(0x3eb038, 0x0000000000000000UL);
	/* Init_5.4: I2C LEM WOF */
	REGW(0x3eb040, 0x0000000000000000UL);
	/* Init_5.5: I2C LEM Mask (AND write) */
	REGW(0x3eb020, 0x4600000000000000UL);

	/*** Set RGC GP bits (error enables) ***/

	/* Init_7: RGC GP0 control (enable umux errors) */
	REGW(0x3e1018, 0x8888880000000000ULL);

	/*** Central Trace Setup ***
	 *
	 * By default trace 4 PHBs Rx/Tx, but this can be changed
	 * for debugging purposes
	 */

	/* Init_8: */
	REGW(0x3ea810, 0x5000000000000000UL);
	/* Init_9: */
	REGW(0x3ea800, 0x0000000000000000UL);
	/* Init_10: */
	REGW(0x3ea808, 0xB0000000F0000000UL);
	/* Init_11: */
	REGW(0x3ea818, 0xF4F00FFF00000000UL);
	/* Init_12: */
	REGW(0x3ea820, 0x0000000000000000UL);
	/* Init_13: */
	REGW(0x3ea828, 0x0000000000000000UL);
	/* Init_14: */
	REGW(0x3ea830, 0x0000000000000000UL);
	/* Init_15: */
	REGW(0x3ea838, 0x0000000000000000UL);
	/* Init_16: */
	REGW(0x3ea840, 0x0000000000000000UL);
	/* Init_17: */
	REGW(0x3ea878, 0x0300000000000000UL);

	/* Init_18: PHB0 mux select (Rx/Tx) */
	REGW(0x000F80, 0x0000000000000000UL);
	/* Init_19: PHB1 mux select (Rx/Tx) */
	REGW(0x010F80, 0x0000000000000000UL);
	/* Init_19.0: PHB2 mux select (Rx/Tx) */
	REGW(0x020F80, 0x0000000000000000UL);
	/* Init_19.1: PHB3 mux select (Rx/Tx) */
	REGW(0x030F80, 0x0000000000000000UL);
	/* Init_19.2: PHB4 mux select (Rx/Tx) */
	REGW(0x040F80, 0x0000000000000000UL);
	/* Init_19.3: PHB5 mux select (Rx/Tx) */
	REGW(0x050F80, 0x0000000000000000UL);

	/* Init_20: */
	REGW(0x3ea880, 0x40008000FF7F0000UL);
	/* Init_21: */
	REGW(0x3ea888, 0x0000000000000000UL);
	/* Init_22: */
	REGW(0x3ea890, 0x0000000000000000UL);
	/* Init_23: */
	REGW(0x3ea898, 0x0000000000000000UL);
	/* Init_24: */
	REGW(0x3ea8a0, 0x8000000000000000UL);
	/* Init_25: */
	REGW(0x3ea8a8, 0x0000000000000000UL);
	/* Init_26: */
	REGW(0x3ea8b0, 0x8000000000000000UL);
	/* Init_27: */
	REGW(0x3ea8b8, 0x0000000000000000UL);
	/* Init_28: */
	REGW(0x3ea8c0, 0x0000000000000000UL);
	/* Init_29: */
	REGW(0x3ea900, 0x40008000FF7F0000UL);
	/* Init_30: */
	REGW(0x3ea908, 0x0000000000000000UL);
	/* Init_31: */
	REGW(0x3ea910, 0x0000000000000000UL);
	/* Init_32: */
	REGW(0x3ea918, 0x0000000000000000UL);
	/* Init_33: */
	REGW(0x3ea920, 0x8000000000000000UL);
	/* Init_34: */
	REGW(0x3ea928, 0x0000000000000000UL);
	/* Init_35: */
	REGW(0x3ea930, 0x8000000000000000UL);
	/* Init_36: */
	REGW(0x3ea938, 0x0000000000000000UL);
	/* Init_37: */
	REGW(0x3ea940, 0x0000000000000000UL);
	/* Init_38: */
	REGW(0x3ea980, 0x40008000FF7F0000UL);
	/* Init_39: */
	REGW(0x3ea988, 0x0000000000000000UL);
	/* Init_40: */
	REGW(0x3ea990, 0x0000000000000000UL);
	/* Init_41: */
	REGW(0x3ea998, 0x0000000000000000UL);
	/* Init_42: */
	REGW(0x3ea9a0, 0x8000000000000000UL);
	/* Init_43: */
	REGW(0x3ea9a8, 0x0000000000000000UL);
	/* Init_44: */
	REGW(0x3ea9b0, 0x8000000000000000UL);
	/* Init_45: */
	REGW(0x3ea9b8, 0x0000000000000000UL);
	/* Init_46: */
	REGW(0x3ea9c0, 0x0000000000000000UL);
	/* Init_47: */
	REGW(0x3eaa00, 0x40008000FF7F0000UL);
	/* Init_48: */
	REGW(0x3eaa08, 0x0000000000000000UL);
	/* Init_49: */
	REGW(0x3eaa10, 0x0000000000000000UL);
	/* Init_50: */
	REGW(0x3eaa18, 0x0000000000000000UL);
	/* Init_51: */
	REGW(0x3eaa20, 0x8000000000000000UL);
	/* Init_52: */
	REGW(0x3eaa28, 0x0000000000000000UL);
	/* Init_53: */
	REGW(0x3eaa30, 0x8000000000000000UL);
	/* Init_54: */
	REGW(0x3eaa38, 0x0000000000000000UL);
	/* Init_55: */
	REGW(0x3eaa40, 0x0000000000000000UL);
	/* Init_56: */
	REGW(0x3ea810, 0x1000000000000000UL);
	/* Init_57: */
	REGW(0x3ea810, 0x8000000000000000UL);

	/*** I2C Master init fixup */

	/* Init_58: I2C Master Operation Control */
	REGW(0x3eb0a8, 0x8100000000000000UL);
}

static void p7ioc_init_GEM(struct p7ioc *ioc)
{
	printf("P7IOC: Init GEM...\n");

	/*** Check for errors */

	/* XXX TODO */
#if 0
	/* Init_1: */
	REGR(0x3e0008, 0);
	/* Init_2: */
	REGR(0x3e0010, 0);
	/* Init_3: */
	REGR(0x3e0018, 0);
#endif

	/*** Get ready for new errors, allow interrupts ***
	 *
	 * XXX: Need to leave all unused port masked to prevent
	 * invalid errors
	 */

	/* Init_4: GEM XFIR */
	REGW(0x3e0008, 0x0000000000000000);
	/* Init_5: GEM Mask (See FIXME) */
	REGW(0x3e0020, 0x000F033FFFFFFFFFUL);
	/* Init_6: GEM WOF */
	REGW(0x3e0028, 0x0000000000000000);
}

int64_t p7ioc_inits(struct p7ioc *ioc)
{
	p7ioc_init_BI(ioc);
	p7ioc_init_MISC_HSS(ioc);
	p7ioc_init_RGC(ioc);
	p7ioc_init_CI(ioc);
	p7ioc_init_PHBs(ioc);
	p7ioc_init_MISC(ioc);
	p7ioc_init_GEM(ioc);

	return OPAL_SUCCESS;

}

void p7ioc_reset(struct io_hub *hub)
{
	struct p7ioc *ioc = iohub_to_p7ioc(hub);
	unsigned int i;

	/* We could do a full cold reset of P7IOC but for now, let's
	 * not bother and just try to clean up the interrupts as best
	 * as possible
	 */

	/* XXX TODO: RGC interrupts */

	printf("P7IOC: Clearing IODA...\n");

	/* First clear all IODA tables and wait a bit */
	for (i = 0; i < 6; i++) {
		if (p7ioc_phb_enabled(ioc, i))
			p7ioc_phb_reset(&ioc->phbs[i].phb);
	}
}
