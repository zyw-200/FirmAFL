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
 * IBM System P PSI (Processor Service Interface)
 */
#ifndef __PSI_H
#define __PSI_H

#include <skiboot.h>

/*
 * PSI Host Bridge Registers (MMIO)
 *
 * The PSI interface is the bridge to the FPS, it has its own
 * registers. The FSP registers appear at an offset within the
 * aperture defined by the PSI_FSPBAR
 */
/* Base address of the PSI MMIO space and LSB is the enable/valid bit */
#define PSIHB_BBAR			0x00

/* FSP MMIO region -- this is where the mbx regs are (offset defined below) */
#define PSIHB_FSPBAR			0x08

/* FSP MMIO region mask register -- determines size of region */
#define PSIHB_FSPMMR			0x10

/* TCE address register */
#define PSIHB_TAR			0x18
#define  PSIHB_TAR_8K_ENTRIES		0
#define  PSIHB_TAR_16K_ENTRIES		1
#define  PSIHB_TAR_256K_ENTRIES		2 /* P8 only */
#define  PSIHB_TAR_512K_ENTRIES		4 /* P8 only */

/* PSI Host Bridge Control Register
 *
 * note: TCE_ENABLE moved to the new PSIHB_PHBSCR on P8 but is
 * the same bit position
 */
#define PSIHB_CR			0x20
#define   PSIHB_CR_FSP_CMD_ENABLE	PPC_BIT(0)
#define   PSIHB_CR_FSP_MMIO_ENABLE	PPC_BIT(1)
#define   PSIHB_CR_TCE_ENABLE		PPC_BIT(2)	/* P7 only */
#define   PSIHB_CR_FSP_IRQ_ENABLE	PPC_BIT(3)
#define   PSIHB_CR_FSP_ERR_RSP_ENABLE	PPC_BIT(4)
#define   PSIHB_CR_PSI_LINK_ENABLE	PPC_BIT(5)
#define   PSIHB_CR_FSP_RESET		PPC_BIT(6)
#define   PSIHB_CR_PSIHB_RESET		PPC_BIT(7)
#define   PSIHB_CR_PSI_IRQ		PPC_BIT(16)	/* PSIHB interrupt */
#define   PSIHB_CR_FSP_IRQ		PPC_BIT(17)	/* FSP interrupt */
#define   PSIHB_CR_FSP_LINK_ACTIVE	PPC_BIT(18)	/* FSP link active */

/* Error conditions in the GXHB */
#define   PSIHB_CR_PSI_ERROR		PPC_BIT(32)	/* PSI error */
#define   PSIHB_CR_PSI_LINK_INACTIVE	PPC_BIT(33)	/* Link inactive */
#define   PSIHB_CR_FSP_ACK_TIMEOUT	PPC_BIT(34)	/* FSP ack timeout */
#define   PSIHB_CR_MMIO_LOAD_TIMEOUT	PPC_BIT(35)	/* MMIO load timeout */
#define   PSIHB_CR_MMIO_LENGTH_ERROR	PPC_BIT(36)	/* MMIO length error */
#define   PSIHB_CR_MMIO_ADDRESS_ERROR	PPC_BIT(37)	/* MMIO address error */
#define   PSIHB_CR_MMIO_TYPE_ERROR	PPC_BIT(38)	/* MMIO type error */
#define   PSIHB_CR_UE			PPC_BIT(39)	/* UE detected */
#define   PSIHB_CR_PARITY_ERROR		PPC_BIT(40)	/* Parity error */
#define   PSIHB_CR_SYNC_ERR_ALERT1	PPC_BIT(41)	/* Sync alert 1 */
#define   PSIHB_CR_SYNC_ERR_ALERT2	PPC_BIT(42)	/* Sync alert 2 */
#define   PSIHB_CR_FSP_COMMAND_ERROR	PPC_BIT(43)	/* FSP cmd error */

/* PSI Status / Error Mask Register */
#define PSIHB_SEMR			0x28

/* XIVR and BUID used for PSI interrupts on P7 */
#define PSIHB_XIVR			0x30

/* XIVR and BUID used for PSI interrupts on P8 */
#define PSIHB_XIVR_FSP			0x30
#define PSIHB_XIVR_OCC			0x60
#define PSIHB_XIVR_FSI			0x68
#define PSIHB_XIVR_LPC			0x70
#define PSIHB_XIVR_LOCAL_ERR		0x78
#define PSIHB_XIVR_HOST_ERR		0x80
#define PSIHB_IRSN			0x88
#define PSIHB_IRSN_COMP			PPC_BITMASK(0,18)
#define PSIHB_IRSN_IRQ_MUX		PPC_BIT(28)
#define PSIHB_IRSN_IRQ_RESET		PPC_BIT(29)
#define PSIHB_IRSN_DOWNSTREAM_EN	PPC_BIT(30)
#define PSIHB_IRSN_UPSTREAM_EN		PPC_BIT(31)
#define PSIHB_IRSN_MASK			PPC_BITMASK(32,50)

#define PSIHB_IRQ_STATUS		0x58
#define   PSIHB_IRQ_STAT_OCC		PPC_BIT(27)
#define   PSIHB_IRQ_STAT_FSI		PPC_BIT(28)
#define   PSIHB_IRQ_STAT_LPC		PPC_BIT(29)
#define   PSIHB_IRQ_STAT_LOCAL_ERR	PPC_BIT(30)
#define   PSIHB_IRQ_STAT_HOST_ERR	PPC_BIT(31)

/* Secure version of CR for P8 (TCE enable bit) */
#define PSIHB_PHBSCR			0x90

/*
 * PSI Host Bridge Registers (XSCOM)
 */
#define PSIHB_XSCOM_P7_HBBAR		0x9
#define   PSIHB_XSCOM_P7_HBBAR_EN	PPC_BIT(28)
#define PSIHB_XSCOM_P7_HBCSR		0xd
#define PSIHB_XSCOM_P7_HBCSR_SET	0x11
#define PSIHB_XSCOM_P7_HBCSR_CLR	0x12
#define   PSIHB_XSCOM_P7_HBSCR_FSP_IRQ 	PPC_BIT(13)

#define PSIHB_XSCOM_P8_BASE		0xa
#define   PSIHB_XSCOM_P8_HBBAR_EN	PPC_BIT(63)
#define PSIHB_XSCOM_P8_HBCSR		0xe
#define PSIHB_XSCOM_P8_HBCSR_SET	0x12
#define PSIHB_XSCOM_P8_HBCSR_CLR	0x13
#define   PSIHB_XSCOM_P8_HBSCR_FSP_IRQ 	PPC_BIT(17)


/*
 * Layout of the PSI DMA address space
 *
 * On P7, we instanciate a TCE table of 16K TCEs mapping 64M
 *
 * On P8, we use a larger mapping of 256K TCEs which provides
 * us with a 1G window in order to fit the trace buffers
 *
 * Currently we have:
 *
 *   - 4x256K serial areas (each divided in 2: in and out buffers)
 *   - 1M region for inbound buffers
 *   - 2M region for generic data fetches
 */
#define PSI_DMA_SER0_BASE		0x00000000
#define PSI_DMA_SER0_SIZE		0x00040000
#define PSI_DMA_SER1_BASE		0x00040000
#define PSI_DMA_SER1_SIZE		0x00040000
#define PSI_DMA_SER2_BASE		0x00080000
#define PSI_DMA_SER2_SIZE		0x00040000
#define PSI_DMA_SER3_BASE		0x000c0000
#define PSI_DMA_SER3_SIZE		0x00040000
#define PSI_DMA_INBOUND_BUF		0x00100000
#define PSI_DMA_INBOUND_SIZE		0x00100000
#define PSI_DMA_FETCH			0x00200000
#define PSI_DMA_FETCH_SIZE		0x00800000
#define PSI_DMA_NVRAM_BODY		0x00a00000
#define PSI_DMA_NVRAM_BODY_SZ		0x00100000
#define PSI_DMA_NVRAM_TRIPL		0x00b00000
#define PSI_DMA_NVRAM_TRIPL_SZ		0x00001000
#define PSI_DMA_OP_PANEL_MISC		0x00b01000
#define PSI_DMA_OP_PANEL_SIZE		0x00001000
#define PSI_DMA_GET_SYSPARAM		0x00b02000
#define PSI_DMA_GET_SYSPARAM_SZ		0x00001000
#define PSI_DMA_SET_SYSPARAM		0x00b03000
#define PSI_DMA_SET_SYSPARAM_SZ		0x00001000
#define PSI_DMA_ERRLOG_READ_BUF		0x00b04000
#define PSI_DMA_ERRLOG_READ_BUF_SZ	0x00040000
#define PSI_DMA_ELOG_PANIC_WRITE_BUF	0x00b44000
#define PSI_DMA_ELOG_PANIC_WRITE_BUF_SZ	0x00010000
#define PSI_DMA_ERRLOG_WRITE_BUF	0x00b54000
#define PSI_DMA_ERRLOG_WRITE_BUF_SZ	0x00040000
#define PSI_DMA_ELOG_WR_TO_HOST_BUF	0x00b94000	/* Unused */
#define PSI_DMA_ELOG_WR_TO_HOST_BUF_SZ	0x00010000
#define PSI_DMA_HBRT_LOG_WRITE_BUF	0x00ba4000
#define PSI_DMA_HBRT_LOG_WRITE_BUF_SZ	0x00001000
#define PSI_DMA_CODE_UPD		0x00c04000
#define PSI_DMA_CODE_UPD_SIZE		0x01001000
#define PSI_DMA_DUMP_DATA		0x01c05000
#define PSI_DMA_DUMP_DATA_SIZE		0x00500000
#define PSI_DMA_SENSOR_BUF		0x02105000
#define PSI_DMA_SENSOR_BUF_SZ		0x00080000
#define PSI_DMA_MDST_TABLE		0x02185000
#define PSI_DMA_MDST_TABLE_SIZE		0x00001000
#define PSI_DMA_HYP_DUMP		0x02186000
#define PSI_DMA_HYP_DUMP_SIZE		0x01000000
#define PSI_DMA_PCIE_INVENTORY		0x03186000
#define PSI_DMA_PCIE_INVENTORY_SIZE	0x00010000
#define PSI_DMA_LED_BUF			0x03196000
#define PSI_DMA_LED_BUF_SZ		0x00001000
#define PSI_DMA_LOC_COD_BUF		0x03197000
#define PSI_DMA_LOC_COD_BUF_SZ		0x00008000
#define PSI_DMA_MEMCONS			0x0319f000
#define PSI_DMA_MEMCONS_SZ		0x00001000
#define PSI_DMA_LOG_BUF			0x03200000
#define PSI_DMA_LOG_BUF_SZ		0x00100000 /* INMEM_CON_LEN */
#define PSI_DMA_PLAT_REQ_BUF		0x03300000
#define PSI_DMA_PLAT_REQ_BUF_SIZE	0x00001000
#define PSI_DMA_PLAT_RESP_BUF		0x03301000
#define PSI_DMA_PLAT_RESP_BUF_SIZE	0x00001000

/* P8 only mappings */
#define PSI_DMA_TRACE_BASE		0x04000000

struct psi {
	struct list_node	list;
	uint64_t		xscom_base;
	void			*regs;
	unsigned int		chip_id;
	unsigned int		interrupt;
	bool			working;
	bool			active;
};

extern void psi_set_link_polling(bool active);

extern struct psi *first_psi;
extern void psi_init(void);
extern struct psi *psi_find_link(uint32_t chip_id);
extern void psi_init_for_fsp(struct psi *psi);
extern void psi_disable_link(struct psi *psi);
extern void psi_reset_fsp(struct psi *psi);
extern bool psi_check_link_active(struct psi *psi);
extern bool psi_poll_fsp_interrupt(struct psi *psi);
extern struct psi *psi_find_functional_chip(void);

/* Interrupts */
extern void psi_irq_reset(void);
extern void psi_enable_fsp_interrupt(struct psi *psi);
extern void psi_fsp_link_in_use(struct psi *psi);

/*
 * Must be called by the platform probe() function as the policy
 * is established before platform.init
 *
 * This defines whether the external interrupt should be passed to
 * the OS or handled locally in skiboot. Return true for skiboot
 * handling. Default if not called is Linux.
 */
#define EXTERNAL_IRQ_POLICY_LINUX	false
#define EXTERNAL_IRQ_POLICY_SKIBOOT	true
extern void psi_set_external_irq_policy(bool policy);



#endif /* __PSI_H */
