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

#define pr_fmt(fmt)	"LPC: " fmt

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <lock.h>
#include <chip.h>
#include <lpc.h>
#include <timebase.h>
#include <errorlog.h>
#include <opal-api.h>
#include <platform.h>

//#define DBG_IRQ(fmt...) prerror(fmt)
#define DBG_IRQ(fmt...) do { } while(0)

DEFINE_LOG_ENTRY(OPAL_RC_LPC_READ, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LPC_WRITE, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LPC_SYNC, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

/* Used exclusively in manufacturing mode */
DEFINE_LOG_ENTRY(OPAL_RC_LPC_SYNC_PERF, OPAL_PLATFORM_ERR_EVT, OPAL_LPC,
		 OPAL_MISC_SUBSYSTEM, OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF,
		 OPAL_NA);

#define ECCB_CTL	0 /* b0020 -> b00200 */
#define ECCB_STAT	2 /* b0022 -> b00210 */
#define ECCB_DATA	3 /* b0023 -> b00218 */

#define ECCB_CTL_MAGIC		0xd000000000000000ul
#define ECCB_CTL_DATASZ		PPC_BITMASK(4,7)
#define ECCB_CTL_READ		PPC_BIT(15)
#define ECCB_CTL_ADDRLEN	PPC_BITMASK(23,25)
#define 	ECCB_ADDRLEN_4B	0x4
#define ECCB_CTL_ADDR		PPC_BITMASK(32,63)

#define ECCB_STAT_PIB_ERR	PPC_BITMASK(0,5)
#define ECCB_STAT_RD_DATA	PPC_BITMASK(6,37)
#define ECCB_STAT_BUSY		PPC_BIT(44)
#define ECCB_STAT_ERRORS1	PPC_BITMASK(45,51)
#define ECCB_STAT_OP_DONE	PPC_BIT(52)
#define ECCB_STAT_ERRORS2	PPC_BITMASK(53,55)

#define ECCB_STAT_ERR_MASK	(ECCB_STAT_PIB_ERR | \
				 ECCB_STAT_ERRORS1 | \
				 ECCB_STAT_ERRORS2)

#define ECCB_TIMEOUT	1000000

/* OPB Master LS registers */
#define OPB_MASTER_LS_IRQ_STAT	0x50
#define OPB_MASTER_LS_IRQ_MASK	0x54
#define OPB_MASTER_LS_IRQ_POL	0x58
#define   OPB_MASTER_IRQ_LPC	       	0x00000800

/* LPC HC registers */
#define LPC_HC_FW_SEG_IDSEL	0x24
#define LPC_HC_FW_RD_ACC_SIZE	0x28
#define   LPC_HC_FW_RD_1B		0x00000000
#define   LPC_HC_FW_RD_2B		0x01000000
#define   LPC_HC_FW_RD_4B		0x02000000
#define   LPC_HC_FW_RD_16B		0x04000000
#define   LPC_HC_FW_RD_128B		0x07000000
#define LPC_HC_IRQSER_CTRL	0x30
#define   LPC_HC_IRQSER_EN		0x80000000
#define   LPC_HC_IRQSER_QMODE		0x40000000
#define   LPC_HC_IRQSER_START_MASK	0x03000000
#define   LPC_HC_IRQSER_START_4CLK	0x00000000
#define   LPC_HC_IRQSER_START_6CLK	0x01000000
#define   LPC_HC_IRQSER_START_8CLK	0x02000000
#define LPC_HC_IRQMASK		0x34	/* same bit defs as LPC_HC_IRQSTAT */
#define LPC_HC_IRQSTAT		0x38
#define   LPC_HC_IRQ_SERIRQ0		0x80000000 /* all bits down to ... */
#define   LPC_HC_IRQ_SERIRQ16		0x00008000 /* IRQ16=IOCHK#, IRQ2=SMI# */
#define   LPC_HC_IRQ_SERIRQ_ALL		0xffff8000
#define   LPC_HC_IRQ_LRESET		0x00000400
#define   LPC_HC_IRQ_SYNC_ABNORM_ERR	0x00000080
#define   LPC_HC_IRQ_SYNC_NORESP_ERR	0x00000040
#define   LPC_HC_IRQ_SYNC_NORM_ERR	0x00000020
#define   LPC_HC_IRQ_SYNC_TIMEOUT_ERR	0x00000010
#define   LPC_HC_IRQ_TARG_TAR_ERR	0x00000008
#define   LPC_HC_IRQ_BM_TAR_ERR		0x00000004
#define   LPC_HC_IRQ_BM0_REQ		0x00000002
#define   LPC_HC_IRQ_BM1_REQ		0x00000001
#define   LPC_HC_IRQ_BASE_IRQS		(		     \
	LPC_HC_IRQ_LRESET |				     \
	LPC_HC_IRQ_SYNC_ABNORM_ERR |			     \
	LPC_HC_IRQ_SYNC_NORESP_ERR |			     \
	LPC_HC_IRQ_SYNC_NORM_ERR |			     \
	LPC_HC_IRQ_SYNC_TIMEOUT_ERR |			     \
	LPC_HC_IRQ_TARG_TAR_ERR |			     \
	LPC_HC_IRQ_BM_TAR_ERR)
#define LPC_HC_ERROR_ADDRESS	0x40


#define	LPC_BUS_DEGRADED_PERF_THRESHOLD		5

struct lpc_client_entry {
	struct list_node node;
	const struct lpc_client *clt;
};

/* Default LPC bus */
static int32_t lpc_default_chip_id = -1;

/*
 * These are expected to be the same on all chips and should probably
 * be read (or configured) dynamically. This is how things are configured
 * today on Tuletta.
 */
static uint32_t lpc_io_opb_base		= 0xd0010000;
static uint32_t lpc_mem_opb_base 	= 0xe0000000;
static uint32_t lpc_fw_opb_base 	= 0xf0000000;
static uint32_t lpc_reg_opb_base 	= 0xc0012000;
static uint32_t opb_master_reg_base 	= 0xc0010000;

static int64_t opb_mmio_write(struct proc_chip *chip, uint32_t addr, uint32_t data,
			      uint32_t sz)
{
	switch (sz) {
	case 1:
		out_8(chip->lpc_mbase + addr, data);
		return OPAL_SUCCESS;
	case 2:
		out_be16(chip->lpc_mbase + addr, data);
		return OPAL_SUCCESS;
	case 4:
		out_be32(chip->lpc_mbase + addr, data);
		return OPAL_SUCCESS;
	}
	prerror("LPC: Invalid data size %d\n", sz);
	return OPAL_PARAMETER;
}

static int64_t opb_write(struct proc_chip *chip, uint32_t addr, uint32_t data,
			 uint32_t sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC, stat;
	int64_t rc, tout;
	uint64_t data_reg;

	if (chip->lpc_mbase)
		return opb_mmio_write(chip, addr, data, sz);

	switch(sz) {
	case 1:
		data_reg = ((uint64_t)data) << 56;
		break;
	case 2:
		data_reg = ((uint64_t)data) << 48;
		break;
	case 4:
		data_reg = ((uint64_t)data) << 32;
		break;
	default:
		prerror("Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_DATA, data_reg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
			"LPC: XSCOM write to ECCB DATA error %lld\n", rc);
		return rc;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_CTL, ctl);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
			"LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		return rc;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(chip->id, chip->lpc_xbase + ECCB_STAT, &stat);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
				"LPC: XSCOM read from ECCB STAT err %lld\n",
									rc);
			return rc;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			if (stat & ECCB_STAT_ERR_MASK) {
				log_simple_error(&e_info(OPAL_RC_LPC_WRITE),
					"LPC: Error status: 0x%llx\n", stat);
				return OPAL_HARDWARE;
			}
			return OPAL_SUCCESS;
		}
		time_wait_nopoll(100);
	}
	log_simple_error(&e_info(OPAL_RC_LPC_WRITE), "LPC: Write timeout !\n");
	return OPAL_HARDWARE;
}

static int64_t opb_mmio_read(struct proc_chip *chip, uint32_t addr, uint32_t *data,
			     uint32_t sz)
{
	switch (sz) {
	case 1:
		*data = in_8(chip->lpc_mbase + addr);
		return OPAL_SUCCESS;
	case 2:
		*data = in_be16(chip->lpc_mbase + addr);
		return OPAL_SUCCESS;
	case 4:
		*data = in_be32(chip->lpc_mbase + addr);
		return OPAL_SUCCESS;
	}
	prerror("LPC: Invalid data size %d\n", sz);
	return OPAL_PARAMETER;
}

static int64_t opb_read(struct proc_chip *chip, uint32_t addr, uint32_t *data,
		        uint32_t sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC | ECCB_CTL_READ, stat;
	int64_t rc, tout;

	if (chip->lpc_mbase)
		return opb_mmio_read(chip, addr, data, sz);

	if (sz != 1 && sz != 2 && sz != 4) {
		prerror("Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_CTL, ctl);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LPC_READ),
			"LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		return rc;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(chip->id, chip->lpc_xbase + ECCB_STAT, &stat);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_LPC_READ),
				"LPC: XSCOM read from ECCB STAT err %lld\n",
									rc);
			return rc;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			uint32_t rdata = GETFIELD(ECCB_STAT_RD_DATA, stat);
			if (stat & ECCB_STAT_ERR_MASK) {
				log_simple_error(&e_info(OPAL_RC_LPC_READ),
					"LPC: Error status: 0x%llx\n", stat);
				return OPAL_HARDWARE;
			}
			switch(sz) {
			case 1:
				*data = rdata >> 24;
				break;
			case 2:
				*data = rdata >> 16;
				break;
			default:
				*data = rdata;
				break;
			}
			return 0;
		}
		time_wait_nopoll(100);
	}
	log_simple_error(&e_info(OPAL_RC_LPC_READ), "LPC: Read timeout !\n");
	return OPAL_HARDWARE;
}

static int64_t lpc_set_fw_idsel(struct proc_chip *chip, uint8_t idsel)
{
	uint32_t val;
	int64_t rc;

	if (idsel == chip->lpc_fw_idsel)
		return OPAL_SUCCESS;
	if (idsel > 0xf)
		return OPAL_PARAMETER;

	rc = opb_read(chip, lpc_reg_opb_base + LPC_HC_FW_SEG_IDSEL,
		      &val, 4);
	if (rc) {
		prerror("Failed to read HC_FW_SEG_IDSEL register !\n");
		return rc;
	}
	val = (val & 0xfffffff0) | idsel;
	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_FW_SEG_IDSEL,
		       val, 4);
	if (rc) {
		prerror("Failed to write HC_FW_SEG_IDSEL register !\n");
		return rc;
	}
	chip->lpc_fw_idsel = idsel;
	return OPAL_SUCCESS;
}

static int64_t lpc_set_fw_rdsz(struct proc_chip *chip, uint8_t rdsz)
{
	uint32_t val;
	int64_t rc;

	if (rdsz == chip->lpc_fw_rdsz)
		return OPAL_SUCCESS;
	switch(rdsz) {
	case 1:
		val = LPC_HC_FW_RD_1B;
		break;
	case 2:
		val = LPC_HC_FW_RD_2B;
		break;
	case 4:
		val = LPC_HC_FW_RD_4B;
		break;
	default:
		/*
		 * The HW supports 16 and 128 via a buffer/cache
		 * but I have never exprimented with it and am not
		 * sure it works the way we expect so let's leave it
		 * at that for now
		 */
		return OPAL_PARAMETER;
	}
	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_FW_RD_ACC_SIZE,
		       val, 4);
	if (rc) {
		prerror("Failed to write LPC_HC_FW_RD_ACC_SIZE !\n");
		return rc;
	}
	chip->lpc_fw_rdsz = rdsz;
	return OPAL_SUCCESS;
}

static int64_t lpc_opb_prepare(struct proc_chip *chip,
			       enum OpalLPCAddressType addr_type,
			       uint32_t addr, uint32_t sz,
			       uint32_t *opb_base, bool is_write)
{
	uint32_t top = addr + sz;
	uint8_t fw_idsel;
	int64_t rc;

	/* Address wraparound */
	if (top < addr)
		return OPAL_PARAMETER;

	/*
	 * Bound check access and get the OPB base address for
	 * the window corresponding to the access type
	 */
	switch(addr_type) {
	case OPAL_LPC_IO:
		/* IO space is 64K */
		if (top > 0x10000)
			return OPAL_PARAMETER;
		/* And only supports byte accesses */
		if (sz != 1)
			return OPAL_PARAMETER;
		*opb_base = lpc_io_opb_base;
		break;
	case OPAL_LPC_MEM:
		/* MEM space is 256M */
		if (top > 0x10000000)
			return OPAL_PARAMETER;
		/* And only supports byte accesses */
		if (sz != 1)
			return OPAL_PARAMETER;
		*opb_base = lpc_mem_opb_base;
		break;
	case OPAL_LPC_FW:
		/*
		 * FW space is in segments of 256M controlled
		 * by IDSEL, make sure we don't cross segments
		 */
		*opb_base = lpc_fw_opb_base;
		fw_idsel = (addr >> 28);
		if (((top - 1) >> 28) != fw_idsel)
			return OPAL_PARAMETER;

		/* Set segment */
		rc = lpc_set_fw_idsel(chip, fw_idsel);
		if (rc)
			return rc;
		/* Set read access size */
		if (!is_write) {
			rc = lpc_set_fw_rdsz(chip, sz);
			if (rc)
				return rc;
		}
		break;
	default:
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}

static int64_t __lpc_write(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			   uint32_t addr, uint32_t data, uint32_t sz)
{
	struct proc_chip *chip = get_chip(chip_id);
	uint32_t opb_base;
	int64_t rc;

	if (!chip || (!chip->lpc_xbase && !chip->lpc_mbase))
		return OPAL_PARAMETER;

	lock(&chip->lpc_lock);

	/*
	 * Convert to an OPB access and handle LPC HC configuration
	 * for FW accesses (IDSEL)
	 */
	rc = lpc_opb_prepare(chip, addr_type, addr, sz, &opb_base, true);
	if (rc)
		goto bail;

	/* Perform OPB access */
	rc = opb_write(chip, opb_base + addr, data, sz);

	/* XXX Add LPC error handling/recovery */
 bail:
	unlock(&chip->lpc_lock);
	return rc;
}

int64_t lpc_write(enum OpalLPCAddressType addr_type, uint32_t addr,
		  uint32_t data, uint32_t sz)
{
	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	return __lpc_write(lpc_default_chip_id, addr_type, addr, data, sz);
}

/*
 * The "OPAL" variant add the emulation of 2 and 4 byte accesses using
 * byte accesses for IO and MEM space in order to be compatible with
 * existing Linux expectations
 */
static int64_t opal_lpc_write(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			      uint32_t addr, uint32_t data, uint32_t sz)
{
	int64_t rc;

	if (addr_type == OPAL_LPC_FW || sz == 1)
		return __lpc_write(chip_id, addr_type, addr, data, sz);
	while(sz--) {
		rc = __lpc_write(chip_id, addr_type, addr, data & 0xff, 1);
		if (rc)
			return rc;
		addr++;
		data >>= 8;
	}
	return OPAL_SUCCESS;
}

static int64_t __lpc_read(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			  uint32_t addr, uint32_t *data, uint32_t sz)
{
	struct proc_chip *chip = get_chip(chip_id);
	uint32_t opb_base;
	int64_t rc;

	if (!chip || (!chip->lpc_xbase && !chip->lpc_mbase))
		return OPAL_PARAMETER;

	lock(&chip->lpc_lock);

	/*
	 * Convert to an OPB access and handle LPC HC configuration
	 * for FW accesses (IDSEL and read size)
	 */
	rc = lpc_opb_prepare(chip, addr_type, addr, sz, &opb_base, false);
	if (rc)
		goto bail;

	/* Perform OPB access */
	rc = opb_read(chip, opb_base + addr, data, sz);

	/* XXX Add LPC error handling/recovery */
 bail:
	unlock(&chip->lpc_lock);
	return rc;
}

int64_t lpc_read(enum OpalLPCAddressType addr_type, uint32_t addr,
		 uint32_t *data, uint32_t sz)
{
	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	return __lpc_read(lpc_default_chip_id, addr_type, addr, data, sz);
}

/*
 * The "OPAL" variant add the emulation of 2 and 4 byte accesses using
 * byte accesses for IO and MEM space in order to be compatible with
 * existing Linux expectations
 */
static int64_t opal_lpc_read(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			     uint32_t addr, uint32_t *data, uint32_t sz)
{
	int64_t rc;

	if (addr_type == OPAL_LPC_FW || sz == 1)
		return __lpc_read(chip_id, addr_type, addr, data, sz);
	*data = 0;
	while(sz--) {
		uint32_t byte;

		rc = __lpc_read(chip_id, addr_type, addr, &byte, 1);
		if (rc)
			return rc;
		*data = *data | (byte << (8 * sz));
		addr++;
	}
	return OPAL_SUCCESS;
}

bool lpc_present(void)
{
	return lpc_default_chip_id >= 0;
}

/* Called with LPC lock held */
static void lpc_setup_serirq(struct proc_chip *chip)
{
	struct lpc_client_entry *ent;
	uint32_t mask = LPC_HC_IRQ_BASE_IRQS;
	int rc;

	/* Collect serirq enable bits */
	list_for_each(&chip->lpc_clients, ent, node)
		mask |= ent->clt->interrupts & LPC_HC_IRQ_SERIRQ_ALL;

	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQMASK, mask, 4);
	if (rc) {
		prerror("Failed to update irq mask\n");
		return;
	}
	DBG_IRQ("LPC: IRQ mask set to 0x%08x\n", mask);

	/* Enable the LPC interrupt in the OPB Master */
	opb_write(chip, opb_master_reg_base + OPB_MASTER_LS_IRQ_POL, 0, 4);
	rc = opb_write(chip, opb_master_reg_base + OPB_MASTER_LS_IRQ_MASK,
		       OPB_MASTER_IRQ_LPC, 4);
	if (rc)
		prerror("Failed to enable IRQs in OPB\n");

	/* Check whether we should enable serirq */
	if (mask & LPC_HC_IRQ_SERIRQ_ALL) {
		rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL,
			       LPC_HC_IRQSER_EN | LPC_HC_IRQSER_START_4CLK, 4);
		DBG_IRQ("LPC: SerIRQ enabled\n");
	} else {
		rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL,
			       0, 4);
		DBG_IRQ("LPC: SerIRQ disabled\n");
	}
	if (rc)
		prerror("Failed to configure SerIRQ\n");
	{
		u32 val;
		rc = opb_read(chip, lpc_reg_opb_base + LPC_HC_IRQMASK, &val, 4);
		if (rc)
			prerror("Failed to readback mask");
		else
			DBG_IRQ("LPC: MASK READBACK=%x\n", val);

		rc = opb_read(chip, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL, &val, 4);
		if (rc)
			prerror("Failed to readback ctrl");
		else
			DBG_IRQ("LPC: CTRL READBACK=%x\n", val);
	}
}

static void lpc_init_interrupts(struct proc_chip *chip)
{
	int rc;

	/* First mask them all */
	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQMASK, 0, 4);
	if (rc) {
		prerror("Failed to init interrutps\n");
		return;
	}

	switch(chip->type) {
	case PROC_CHIP_P8_MURANO:
	case PROC_CHIP_P8_VENICE:
		/* On Murano/Venice, there is no SerIRQ, only enable error
		 * interrupts
		 */
		rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQMASK,
			       LPC_HC_IRQ_BASE_IRQS, 4);
		if (rc) {
			prerror("Failed to set interrupt mask\n");
			return;
		}
		opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQSER_CTRL, 0, 4);
		break;
	case PROC_CHIP_P8_NAPLES:
		/* On Naples, we support LPC interrupts, enable them based
		 * on what clients requests. This will setup the mask and
		 * enable processing
		 */
		lock(&chip->lpc_lock);
		lpc_setup_serirq(chip);
		unlock(&chip->lpc_lock);
		break;
	default:
		/* We aren't getting here, are we ? */
		return;
	}
}

static void lpc_dispatch_reset(struct proc_chip *chip)
{
	struct lpc_client_entry *ent;

	/* XXX We are going to hit this repeatedly while reset is
	 * asserted which might be sub-optimal. We should instead
	 * detect assertion and start a poller that will wait for
	 * de-assertion. We could notify clients of LPC being
	 * on/off rather than just reset
	 */

	prerror("Got LPC reset!\n");

	/* Collect serirq enable bits */
	list_for_each(&chip->lpc_clients, ent, node) {
		if (!ent->clt->reset)
			continue;
		unlock(&chip->lpc_lock);
		ent->clt->reset(chip->id);
		lock(&chip->lpc_lock);
	}

	/* Reconfigure serial interrupts */
	if (chip->type == PROC_CHIP_P8_NAPLES)
		lpc_setup_serirq(chip);
}

static void lpc_dispatch_err_irqs(struct proc_chip *chip, uint32_t irqs)
{
	int rc;
	struct opal_err_info *info;
	const char *sync_err = "Unknown LPC error";
	uint32_t err_addr;
	static int lpc_bus_err_count;

	/* Write back to clear error interrupts, we clear SerIRQ later
	 * as they are handled as level interrupts
	 */
	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQSTAT,
		       LPC_HC_IRQ_BASE_IRQS, 4);
	if (rc)
		prerror("Failed to clear IRQ error latches !\n");

	if (irqs & LPC_HC_IRQ_LRESET)
		lpc_dispatch_reset(chip);
	if (irqs & LPC_HC_IRQ_SYNC_ABNORM_ERR)
		sync_err = "LPC: Got SYNC abnormal error.";
	if (irqs & LPC_HC_IRQ_SYNC_NORESP_ERR)
		sync_err = "LPC: Got SYNC no-response error.";
	if (irqs & LPC_HC_IRQ_SYNC_NORM_ERR)
		sync_err = "LPC: Got SYNC normal error.";
	if (irqs & LPC_HC_IRQ_SYNC_TIMEOUT_ERR)
		sync_err = "LPC: Got SYNC timeout error.";
	if (irqs & LPC_HC_IRQ_TARG_TAR_ERR)
		sync_err = "LPC: Got abnormal TAR error.";
	if (irqs & LPC_HC_IRQ_BM_TAR_ERR)
		sync_err = "LPC: Got bus master TAR error.";

	rc = opb_read(chip, lpc_reg_opb_base + LPC_HC_ERROR_ADDRESS,
		      &err_addr, 4);

	lpc_bus_err_count++;
	if (manufacturing_mode && (lpc_bus_err_count > LPC_BUS_DEGRADED_PERF_THRESHOLD))
		info = &e_info(OPAL_RC_LPC_SYNC_PERF);
	else
		info = &e_info(OPAL_RC_LPC_SYNC);

	if (rc)
		log_simple_error(info, "%s Error address: Unknown\n",
					sync_err);
	else
		log_simple_error(info, "%s Error address: 0x%08x\n",
					sync_err, err_addr);
}

static void lpc_dispatch_ser_irqs(struct proc_chip *chip, uint32_t irqs,
				  bool clear_latch)
{
	struct lpc_client_entry *ent;
	uint32_t cirqs;
	int rc;

	irqs &= LPC_HC_IRQ_SERIRQ_ALL;

	/* Collect serirq enable bits */
	list_for_each(&chip->lpc_clients, ent, node) {
		if (!ent->clt->interrupt)
			continue;
		cirqs = ent->clt->interrupts & irqs;
		if (cirqs) {
			unlock(&chip->lpc_lock);
			ent->clt->interrupt(chip->id, cirqs);
			lock(&chip->lpc_lock);
		}
	}

	/* Our SerIRQ are level sensitive, we clear the latch after
	 * we call the handler.
	 */
	if (!clear_latch)
		return;

	rc = opb_write(chip, lpc_reg_opb_base + LPC_HC_IRQSTAT,
		       irqs, 4);
	if (rc)
		prerror("Failed to clear SerIRQ latches !\n");
}

void lpc_interrupt(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	uint32_t irqs, opb_irqs;
	int rc;

	/* No initialized LPC controller on that chip */
	if (!chip || (!chip->lpc_xbase && !chip->lpc_mbase))
		return;

	lock(&chip->lpc_lock);

	/* Grab OPB Master LS interrupt status */
	rc = opb_read(chip, opb_master_reg_base + OPB_MASTER_LS_IRQ_STAT,
		      &opb_irqs, 4);
	if (rc) {
		prerror("Failed to read OPB IRQ state\n");
		goto bail;
	}

	/* Check if it's an LPC interrupt */
	if (!(opb_irqs & OPB_MASTER_IRQ_LPC)) {
		/* Something we don't support ? Ack it anyway... */
		opb_write(chip, opb_master_reg_base + OPB_MASTER_LS_IRQ_STAT,
			  opb_irqs, 4);
		goto bail;
	}

	/* Handle the lpc interrupt source (errors etc...) */
	rc = opb_read(chip, lpc_reg_opb_base + LPC_HC_IRQSTAT, &irqs, 4);
	if (rc) {
		prerror("Failed to read LPC IRQ state\n");
		goto bail;
	}

	DBG_IRQ("LPC: IRQ on chip 0x%x, irqs=0x%08x\n", chip_id, irqs);

	/* Handle error interrupts */
	if (irqs & LPC_HC_IRQ_BASE_IRQS)
		lpc_dispatch_err_irqs(chip, irqs);

	/* Handle SerIRQ interrupts */
	if (irqs & LPC_HC_IRQ_SERIRQ_ALL)
		lpc_dispatch_ser_irqs(chip, irqs, true);

	/* Ack it at the OPB level */
	opb_write(chip, opb_master_reg_base + OPB_MASTER_LS_IRQ_STAT,
		  opb_irqs, 4);
 bail:
	unlock(&chip->lpc_lock);
}

void lpc_all_interrupts(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);

	/* Dispatch all */
	lock(&chip->lpc_lock);
	lpc_dispatch_ser_irqs(chip, LPC_HC_IRQ_SERIRQ_ALL, false);
	unlock(&chip->lpc_lock);
}

static void lpc_init_chip_p8(struct dt_node *xn)
 {
	uint32_t gcid = dt_get_chip_id(xn);
	struct proc_chip *chip;

	chip = get_chip(gcid);
	assert(chip);

	chip->lpc_xbase = dt_get_address(xn, 0, NULL);
	chip->lpc_fw_idsel = 0xff;
	chip->lpc_fw_rdsz = 0xff;
	init_lock(&chip->lpc_lock);

	if (lpc_default_chip_id < 0 ||
	    dt_has_node_property(xn, "primary", NULL)) {
		lpc_default_chip_id = chip->id;
	}

	prlog(PR_NOTICE, "Bus on chip %d, access via XSCOM, PCB_Addr=0x%x\n",
	      chip->id, chip->lpc_xbase);

	lpc_init_interrupts(chip);
	dt_add_property(xn, "interrupt-controller", NULL, 0);
	dt_add_property_cells(xn, "#interrupt-cells", 1);
	assert(dt_prop_get_u32(xn, "#address-cells") == 2);
}

static void lpc_init_chip_p9(struct dt_node *opb_node)
{
	uint32_t gcid = dt_get_chip_id(opb_node);
	struct proc_chip *chip;
	u64 addr;

	chip = get_chip(gcid);
	assert(chip);

	/* Grab OPB base address */
	addr = dt_prop_get_cell(opb_node, "ranges", 1);
	addr <<= 32;
	addr |= dt_prop_get_cell(opb_node, "ranges", 2);

	chip->lpc_mbase = (void *)addr;
	chip->lpc_fw_idsel = 0xff;
	chip->lpc_fw_rdsz = 0xff;
	init_lock(&chip->lpc_lock);

	if (lpc_default_chip_id < 0 ||
	    dt_has_node_property(opb_node, "primary", NULL)) {
		lpc_default_chip_id = chip->id;
	}

	prlog(PR_NOTICE, "Bus on chip %d, access via MMIO @%p\n",
	       chip->id, chip->lpc_mbase);

	// XXX TODO
	//lpc_init_interrupts(chip);
}

void lpc_init(void)
{
	struct dt_node *xn;
	bool has_lpc = false;

	dt_for_each_compatible(dt_root, xn, "ibm,power8-lpc") {
		lpc_init_chip_p8(xn);
		has_lpc = true;
	}
	dt_for_each_compatible(dt_root, xn, "ibm,power9-lpcm-opb") {
		lpc_init_chip_p9(xn);
		has_lpc = true;
	}
	if (lpc_default_chip_id >= 0)
		prlog(PR_NOTICE, "Default bus on chip %d\n",
					lpc_default_chip_id);

	if (has_lpc) {
		opal_register(OPAL_LPC_WRITE, opal_lpc_write, 5);
		opal_register(OPAL_LPC_READ, opal_lpc_read, 5);
	}
}

void lpc_used_by_console(void)
{
	struct proc_chip *chip;

	xscom_used_by_console();

	for_each_chip(chip) {
		chip->lpc_lock.in_con_path = true;
		lock(&chip->lpc_lock);
		unlock(&chip->lpc_lock);
	}
}

bool lpc_ok(void)
{
	struct proc_chip *chip;

	if (lpc_default_chip_id < 0)
		return false;
	if (!xscom_ok())
		return false;
	chip = get_chip(lpc_default_chip_id);
	return !lock_held_by_me(&chip->lpc_lock);
}

void lpc_register_client(uint32_t chip_id,
			 const struct lpc_client *clt)
{
	struct lpc_client_entry *ent;
	struct proc_chip *chip;

	chip = get_chip(chip_id);
	assert(chip);
	ent = malloc(sizeof(*ent));
	assert(ent);
	ent->clt = clt;
	lock(&chip->lpc_lock);
	list_add(&chip->lpc_clients, &ent->node);
	/* Re-evaluate ser irqs on Naples */
	if (chip->type == PROC_CHIP_P8_NAPLES)
		lpc_setup_serirq(chip);
	unlock(&chip->lpc_lock);
}
