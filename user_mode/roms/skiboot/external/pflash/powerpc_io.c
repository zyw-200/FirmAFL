#define _GNU_SOURCE /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <byteswap.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <arpa/inet.h>
#include <assert.h>

#include "io.h"

/* Big endian warning/note:
 *
 * The register accessors return byteswapped data for registers
 */
uint32_t (*ast_ahb_readl)(uint32_t offset);
void (*ast_ahb_writel)(uint32_t val, uint32_t offset);
int (*ast_copy_to_ahb)(uint32_t reg, const void *src, uint32_t len);
int (*ast_copy_from_ahb)(void *dst, uint32_t reg, uint32_t len);

static enum ppc_platform {
	plat_unknown,
	plat_rhesus,
	plat_ast_bmc,
} ppc_platform;

static int lpc_io_fd = -1, lpc_fw_fd = -1;
static uint32_t lpc_old_flash_reg;
static uint32_t ahb_flash_base, ahb_flash_size, lpc_flash_offset;

static void lpc_outb(uint8_t val, uint16_t port)
{
	int rc;

	lseek(lpc_io_fd, port, SEEK_SET);
	rc = write(lpc_io_fd, &val, 1);
	if (rc != 1) {
		perror("Can't write to LPC IO");
		exit(1);
	}
}

static uint8_t lpc_inb(uint16_t port)
{
	uint8_t val;
	int rc;

	lseek(lpc_io_fd, port, SEEK_SET);
	rc = read(lpc_io_fd, &val, 1);
	if (rc != 1) {
		perror("Can't read from LPC IO");
		exit(1);
	}
	return val;
}

int lpc_fw_write32(uint32_t val, uint32_t addr)
{
	int rc;

	/* The value passed in is in big endian always */
	lseek(lpc_fw_fd, addr, SEEK_SET);
	rc = write(lpc_fw_fd, &val, 4);
	if (rc != 4) {
		perror("Can't write to LPC FW");
		exit(1);
	}
	return 0;
}

int lpc_fw_read32(uint32_t *val, uint32_t addr)
{
	int rc;

	lseek(lpc_fw_fd, addr, SEEK_SET);
	rc = read(lpc_fw_fd, val, 4);
	if (rc != 4) {
		perror("Can't read from LPC FW");
		exit(1);
	}
	return 0;
}

static void lpc_sio_outb(uint8_t val, uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	lpc_outb(val, 0x2f);
}

static uint8_t lpc_sio_inb(uint8_t reg)
{
	lpc_outb(reg, 0x2e);
	return lpc_inb(0x2f);
}

static void lpc_ahb_prep(uint32_t reg, uint8_t type)
{
	/* Address */
	lpc_sio_outb((reg >> 24) & 0xff, 0xf0);
	lpc_sio_outb((reg >> 16) & 0xff, 0xf1);
	lpc_sio_outb((reg >>  8) & 0xff, 0xf2);
	lpc_sio_outb((reg      ) & 0xff, 0xf3);

	/* 4 bytes cycle */
	lpc_sio_outb(type, 0xf8);
}

static void lpc_ahb_writel(uint32_t val, uint32_t reg)
{
	lpc_ahb_prep(reg, 2);

	/* Write data */
	lpc_sio_outb(val >> 24, 0xf4);
	lpc_sio_outb(val >> 16, 0xf5);
	lpc_sio_outb(val >>  8, 0xf6);
	lpc_sio_outb(val      , 0xf7);

	/* Trigger */
	lpc_sio_outb(0xcf, 0xfe);
}

static uint32_t lpc_ahb_readl(uint32_t reg)
{
	uint32_t val = 0;

	lpc_ahb_prep(reg, 2);

	/* Trigger */	
	lpc_sio_inb(0xfe);

	/* Read results */
	val = (val << 8) | lpc_sio_inb(0xf4);
	val = (val << 8) | lpc_sio_inb(0xf5);
	val = (val << 8) | lpc_sio_inb(0xf6);
	val = (val << 8) | lpc_sio_inb(0xf7);

	return val;
}

static void lpc_ahb_init(bool bmc_flash)
{
	uint32_t b;

	/* Send SuperIO password */
	lpc_outb(0xa5, 0x2e);
	lpc_outb(0xa5, 0x2e);

	/* Select logical dev d */
	lpc_sio_outb(0x0d, 0x07);

	/* Enable iLPC->AHB */
	lpc_sio_outb(0x01, 0x30);

	/* Save flash base */
	lpc_old_flash_reg = b = lpc_ahb_readl(LPC_CTRL_BASE + 0x88);
	/* Upate flash base */
	if (bmc_flash) {
		ahb_flash_base = BMC_FLASH_BASE;
		ahb_flash_size = BMC_FLASH_SIZE;
	} else {
		ahb_flash_base = PNOR_FLASH_BASE;
		ahb_flash_size = PNOR_FLASH_SIZE;
	}
	lpc_flash_offset = 0x0e000000;
	b = (b & 0x0000ffff) | ahb_flash_base;
	lpc_ahb_writel(b, LPC_CTRL_BASE + 0x88);
	b = lpc_ahb_readl(LPC_CTRL_BASE + 0x88);
}

static int lpc_ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	int rc;

	if (reg < ahb_flash_base ||
	    (reg + len) > (ahb_flash_base + ahb_flash_size))
		return -1;
	reg = (reg - ahb_flash_base) + lpc_flash_offset;

	lseek(lpc_fw_fd, reg, SEEK_SET);
	rc = read(lpc_fw_fd, dst, len);
	if (rc != len) {
		perror("Can't read bulk from LPC FW");
		exit(1);
	}
	return 0;
}

static int lpc_ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	int rc;

	if (reg < ahb_flash_base ||
	    (reg + len) > (ahb_flash_base + ahb_flash_size))
		return -1;
	reg = (reg - ahb_flash_base) + lpc_flash_offset;

	lseek(lpc_fw_fd, reg, SEEK_SET);
	rc = write(lpc_fw_fd, src, len);
	if (rc != len) {
		perror("Can't write bulk from LPC FW");
		exit(1);
	}
	return 0;
}

/*
 * Write protect: TODO use custom IPMI to control lock from BMC
 */
static uint32_t lpc_gpio_ctl_readl(uint32_t offset)
{
	return lpc_ahb_readl(GPIO_CTRL_BASE + offset);
}

static void lpc_gpio_ctl_writel(uint32_t val, uint32_t offset)
{
	lpc_ahb_writel(val, GPIO_CTRL_BASE + offset);
}

bool set_wrprotect(bool protect)
{
	uint32_t reg;
	bool was_protected;

	if (ppc_platform != plat_ast_bmc)
		return false;

	reg = lpc_gpio_ctl_readl(0x20);
	was_protected = !!(reg & 0x00004000);
	if (protect)
		reg |= 0x00004000; /* GPIOF[6] value */
	else
		reg &= ~0x00004000; /* GPIOF[6] value */
	lpc_gpio_ctl_writel(reg, 0x20);
	reg = lpc_gpio_ctl_readl(0x24);
	reg |= 0x00004000; /* GPIOF[6] direction */
	lpc_gpio_ctl_writel(reg, 0x24);

	return was_protected;
}

static void open_lpc(bool bmc_flash)
{      
	lpc_fw_fd = open("/sys/kernel/debug/powerpc/lpc/fw", O_RDWR);
	if (lpc_fw_fd < 0) {
		perror("can't open LPC MEM");
		exit(1);
	}

	if (ppc_platform != plat_ast_bmc)
		return;

	lpc_io_fd = open("/sys/kernel/debug/powerpc/lpc/io", O_RDWR);
	if (lpc_io_fd < 0) {
		perror("can't open LPC IO");
		exit(1);
	}

	ast_ahb_readl = lpc_ahb_readl;
	ast_ahb_writel = lpc_ahb_writel;
	ast_copy_to_ahb = lpc_ast_copy_to_ahb;
	ast_copy_from_ahb = lpc_ast_copy_from_ahb;

	lpc_ahb_init(bmc_flash);
}

void close_devs(void)
{
	if (lpc_io_fd < 0 ||  lpc_fw_fd < 0)
		return;

	if (ppc_platform != plat_ast_bmc)
		return;

	/* Restore flash base */
	lpc_ahb_writel(lpc_old_flash_reg, LPC_CTRL_BASE + 0x88);
}

static void open_pci(bool bmc_flash)
{
	/* XXX */
	fprintf(stderr, "WARNING: PCI access method not implemented !\n");
	fprintf(stderr, "         Use -l or --lpc\n");
	exit(1);
}

static void identify_platform(void)
{
	FILE *cpuinfo;
	char *lptr = NULL;
	size_t lsize = 0;
	bool found = false;

	ppc_platform = plat_unknown;

	cpuinfo = fopen("/proc/cpuinfo", "r");
	if (!cpuinfo) {
		perror("Can't open /proc/cpuinfo");
		exit(1);
	}
	while(!found && getline(&lptr, &lsize, cpuinfo) >= 0) {
		if (!strncmp(lptr, "model", 5)) {
			if (strcasestr(lptr, "rhesus"))
				ppc_platform = plat_rhesus;
			else if (strcasestr(lptr, "palmetto"))
				ppc_platform = plat_ast_bmc;
			found = true;
		}
		free(lptr);
		lptr = NULL;
		lsize = 0;
	}
}

void open_devs(bool use_lpc, bool bmc_flash)
{
	if (ppc_platform == plat_unknown) {
		fprintf(stderr, "Unsupported platform !\n");
		exit(1);
	}

	if (use_lpc)
		open_lpc(bmc_flash);
	else
		open_pci(bmc_flash);
}

void check_platform(bool *has_sfc, bool *has_ast)
{
	identify_platform();

	*has_sfc = ppc_platform == plat_rhesus;
	*has_ast = ppc_platform == plat_ast_bmc;
}
