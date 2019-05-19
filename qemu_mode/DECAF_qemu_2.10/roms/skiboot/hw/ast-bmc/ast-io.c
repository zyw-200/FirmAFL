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
 * Note about accesses to the AST2400 internal memory map:
 *
 * There are two ways to genrate accesses to the AHB bus of the AST2400
 * from the host. The LPC->AHB bridge and the iLPC->AHB bridge.
 *
 * LPC->AHB bridge
 * ---------------
 *
 * This bridge directly converts memory or firmware accesses using
 * a set of registers for establishing a remapping window. We prefer
 * using FW space as normal memory space is limited to byte accesses
 * to a fixed 256M window, while FW space allows us to use different
 * access sizes and to control the IDSEL bits which essentially enable
 * a full 4G address space.
 *
 * The way FW accesses map onto AHB is controlled via two registers
 * in the BMC's LPC host controller:
 *
 * HICR7 at 0x1e789088 [31:16] : ADRBASE
 *                     [15:00] : HWMBASE
 *
 * HICR8 at 0x1e78908c [31:16] : ADRMASK
 *		       [15:00] : HWNCARE
 *
 * All decoding/remapping happens on the top 16 bits of the LPC address
 * named LPC_ADDR as follow:
 *
 *  - For decoding, LPC_ADDR bits are compared with HWMBASE if the
 *    corresponding bit in HWNCARE is 0.
 *
 *  - For remapping, the AHB address is constructed by taking bits
 *    from LPC_ADDR if the corresponding bit in ADRMASK is 0 or in
 *    ADRBASE if the corresponding bit in ADRMASK is 1
 *
 * Example of 2MB SPI flash, LPC 0xFCE00000~0xFCFFFFFF onto
 *                           AHB 0x30000000~0x301FFFFF (SPI flash)
 *
 * ADRBASE=0x3000 HWMBASE=0xFCE0
 * ADRMASK=0xFFE0 HWNCARE=0x001F
 *
 * This comes pre-configured by the BMC or HostBoot to access the PNOR
 * flash from IDSEL 0 as follow:
 *
 * ADRBASE=0x3000 HWMBASE=0x0e00 for 32MB
 * ADRMASK=0xfe00 HWNCARE=0x01ff
 *
 * Which means mapping of   LPC 0x0e000000..0x0fffffff onto
 *                          AHB 0x30000000..0x31ffffff
 *
 * iLPC->AHB bridge
 * ---------------
 *
 * This bridge is hosted in the SuperIO part of the BMC and is
 * controlled by a series of byte-sized registers accessed indirectly
 * via IO ports 0x2e and 0x2f.
 *
 * Via these, byte by byte, we can construct an AHB address and
 * fill a data buffer to trigger a write cycle, or we can do a
 * read cycle and read back the data, byte after byte.
 *
 * This is fairly convoluted and slow but works regardless of what
 * mapping was established in the LPC->AHB bridge.
 *
 * For the time being, we use the iLPC->AHB for everything except
 * pnor accesses. In the long run, we will reconfigure the LPC->AHB
 * to provide more direct access to all of the BMC address space but
 * we'll only do that after the boot script/program on the BMC is
 * updated to restore the bridge to a state compatible with the SBE
 * expectations on boot.
 */

#include <skiboot.h>
#include <lpc.h>
#include <lock.h>

#include "ast.h"

#define BMC_SIO_SCR28 0x28
#define BOOT_FLAGS_VERSION 0x42

#define BMC_SIO_SCR29 0x29
#define BMC_SIO_SCR29_MEMBOOT 0x10

enum {
	BMC_SIO_DEV_NONE	= -1,
	BMC_SIO_DEV_UART1	= 2,
	BMC_SIO_DEV_UART2	= 3,
	BMC_SIO_DEV_SWC		= 4,
	BMC_SIO_DEV_KBC		= 5,
	BMC_SIO_DEV_P80		= 7,
	BMC_SIO_DEV_UART3	= 0xb,
	BMC_SIO_DEV_UART4	= 0xc,
	BMC_SIO_DEV_LPC2AHB	= 0xd,
	BMC_SIO_DEV_MBOX	= 0xe,
};

static struct lock bmc_sio_lock = LOCK_UNLOCKED;
static int bmc_sio_cur_dev = BMC_SIO_DEV_NONE;

/*
 * SuperIO indirect accesses
 */
static void bmc_sio_outb(uint8_t val, uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	lpc_outb(val, 0x2f);
}

static uint8_t bmc_sio_inb(uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	return lpc_inb(0x2f);
}

static void bmc_sio_get(int dev)
{
	lock(&bmc_sio_lock);

	if (bmc_sio_cur_dev == dev || dev < 0)
		return;

	if (bmc_sio_cur_dev == BMC_SIO_DEV_NONE) {
		/* Send SuperIO password */
		lpc_outb(0xa5, 0x2e);
		lpc_outb(0xa5, 0x2e);
	}

	/* Select logical dev */
	bmc_sio_outb(dev, 0x07);

	bmc_sio_cur_dev = dev;
}

static void bmc_sio_put(bool lock_sio)
{
	if (lock_sio) {
		/* Re-lock SuperIO */
		lpc_outb(0xaa, 0x2e);

		bmc_sio_cur_dev = BMC_SIO_DEV_NONE;
	}
	unlock(&bmc_sio_lock);
}

/*
 * AHB accesses via iLPC->AHB in SuperIO. Works on byteswapped
 * values (ie. Little Endian registers)
 */
static void bmc_sio_ahb_prep(uint32_t reg, uint8_t type)
{
	/* Enable iLPC->AHB */
	bmc_sio_outb(0x01, 0x30);

	/* Address */
	bmc_sio_outb((reg >> 24) & 0xff, 0xf0);
	bmc_sio_outb((reg >> 16) & 0xff, 0xf1);
	bmc_sio_outb((reg >>  8) & 0xff, 0xf2);
	bmc_sio_outb((reg      ) & 0xff, 0xf3);

	/* bytes cycle type */
	bmc_sio_outb(type, 0xf8);
}

static void bmc_sio_ahb_writel(uint32_t val, uint32_t reg)
{
	bmc_sio_get(BMC_SIO_DEV_LPC2AHB);

	bmc_sio_ahb_prep(reg, 2);

	/* Write data */
	bmc_sio_outb(val >> 24, 0xf4);
	bmc_sio_outb(val >> 16, 0xf5);
	bmc_sio_outb(val >>  8, 0xf6);
	bmc_sio_outb(val      , 0xf7);

	/* Trigger */
	bmc_sio_outb(0xcf, 0xfe);

	bmc_sio_put(false);
}

static uint32_t bmc_sio_ahb_readl(uint32_t reg)
{
	uint32_t val = 0;

	bmc_sio_get(BMC_SIO_DEV_LPC2AHB);

	bmc_sio_ahb_prep(reg, 2);

	/* Trigger */
	bmc_sio_inb(0xfe);

	/* Read results */
	val = (val << 8) | bmc_sio_inb(0xf4);
	val = (val << 8) | bmc_sio_inb(0xf5);
	val = (val << 8) | bmc_sio_inb(0xf6);
	val = (val << 8) | bmc_sio_inb(0xf7);

	bmc_sio_put(false);

	return val;
}

/*
 * External API
 *
 * We only support 4-byte accesses to all of AHB. We additionally
 * support 1-byte accesses to the flash area only.
 *
 * We could support all access sizes via iLPC but we don't need
 * that for now.
 */
#define PNOR_AHB_ADDR	0x30000000
static uint32_t pnor_lpc_offset;

void ast_ahb_writel(uint32_t val, uint32_t reg)
{
	/* For now, always use iLPC->AHB, it will byteswap */
	bmc_sio_ahb_writel(val, reg);
}

uint32_t ast_ahb_readl(uint32_t reg)
{
	/* For now, always use iLPC->AHB, it will byteswap */
	return bmc_sio_ahb_readl(reg);
}

int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + pnor_lpc_offset;
		int64_t rc;

		while(len) {
			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint32_t *)src, 4);
				chunk = 4;
			} else {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint8_t *)src, 1);
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_write.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			src += chunk;
		}
		return 0;
	}

	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted write bytes access to %08x\n", reg);
	return -EINVAL;
}

int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + pnor_lpc_offset;
		int64_t rc;

		while(len) {
			uint32_t dat;

			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
				if (!rc)
					*(uint32_t *)dst = dat;
				chunk = 4;
			} else {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
				if (!rc)
					*(uint8_t *)dst = dat;
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_read.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			dst += chunk;
		}
		return 0;
	}
	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted read bytes access to %08x\n", reg);
	return -EINVAL;
}

static void ast_setup_sio_irq_polarity(void)
{
	/* Select logical dev 2 */
	bmc_sio_get(BMC_SIO_DEV_UART1);
	bmc_sio_outb(0x01, 0x71); /* level low */
	bmc_sio_put(false);

	/* Select logical dev 3 */
	bmc_sio_get(BMC_SIO_DEV_UART2);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev 4 */
	bmc_sio_get(BMC_SIO_DEV_SWC);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev 5 */
	bmc_sio_get(BMC_SIO_DEV_KBC);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_outb(0x01, 0x73); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev 7 */
	bmc_sio_get(BMC_SIO_DEV_P80);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev d */
	bmc_sio_get(BMC_SIO_DEV_UART3);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev c */
	bmc_sio_get(BMC_SIO_DEV_UART4);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev d */
	bmc_sio_get(BMC_SIO_DEV_LPC2AHB);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(false);

	/* Select logical dev e */
	bmc_sio_get(BMC_SIO_DEV_MBOX);
	bmc_sio_outb(0x01, 0x71); /* irq level low */
	bmc_sio_put(true);
}

void ast_io_init(void)
{
	uint32_t hicr7;

	/* Read the configuration of the LPC->AHB bridge for PNOR
	 * to extract the PNOR LPC offset which can be different
	 * depending on flash size
	 */

	hicr7 = bmc_sio_ahb_readl(LPC_HICR7);
	pnor_lpc_offset = (hicr7 & 0xffffu) << 16;
	prlog(PR_DEBUG, "AST: PNOR LPC offset: 0x%08x\n", pnor_lpc_offset);

	/* Configure all AIO interrupts to level low */
	ast_setup_sio_irq_polarity();
}

bool ast_is_ahb_lpc_pnor(void)
{
	uint8_t boot_version;
	uint8_t boot_flags;

	boot_version = bmc_sio_inb(BMC_SIO_SCR28);
	if (boot_version != BOOT_FLAGS_VERSION)
		return true;

	boot_flags = bmc_sio_inb(BMC_SIO_SCR29);
	return !(boot_flags & BMC_SIO_SCR29_MEMBOOT);
}

void ast_setup_ibt(uint16_t io_base, uint8_t irq)
{
	uint32_t v;

	v = bmc_sio_ahb_readl(LPC_iBTCR0);
	v = v & ~(0xfffffc00u);
	v = v | (((uint32_t)io_base) << 16);
	v = v | (((uint32_t)irq) << 12);
	bmc_sio_ahb_writel(v, LPC_iBTCR0);
}

bool ast_is_vuart1_enabled(void)
{
	uint32_t v;

	v = bmc_sio_ahb_readl(VUART1_GCTRLA);
	return !!(v & 1);
}

void ast_setup_vuart1(uint16_t io_base, uint8_t irq)
{
	uint32_t v;

	/* IRQ level low */
	v = bmc_sio_ahb_readl(VUART1_GCTRLA);
	v = v & ~2u;
	bmc_sio_ahb_writel(v, VUART1_GCTRLA);
	v = bmc_sio_ahb_readl(VUART1_GCTRLA);

	/* IRQ number */
	v = bmc_sio_ahb_readl(VUART1_GCTRLB);
	v = (v & ~0xf0u) | (irq << 4);
	bmc_sio_ahb_writel(v, VUART1_GCTRLB);

	/* Address */
	bmc_sio_ahb_writel(io_base & 0xff, VUART1_ADDRL);
	bmc_sio_ahb_writel(io_base >> 8, VUART1_ADDRH);
}

/* Setup SuperIO UART 1 */
void ast_setup_sio_uart1(uint16_t io_base, uint8_t irq)
{
	bmc_sio_get(BMC_SIO_DEV_UART1);

	/* Disable UART1 for configuration */
	bmc_sio_outb(0x00, 0x30);

	/* Configure base and interrupt */
	bmc_sio_outb(io_base >> 8, 0x60);
	bmc_sio_outb(io_base & 0xff, 0x61);
	bmc_sio_outb(irq, 0x70);
	bmc_sio_outb(0x01, 0x71); /* level low */

	/* Enable UART1 */
	bmc_sio_outb(0x01, 0x30);

	bmc_sio_put(true);
}

void ast_disable_sio_uart1(void)
{
	bmc_sio_get(BMC_SIO_DEV_UART1);

	/* Disable UART1 */
	bmc_sio_outb(0x00, 0x30);

	bmc_sio_put(true);
}
