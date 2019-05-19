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

#include <skiboot.h>
#include <p7ioc.h>
#include <p7ioc-regs.h>
#include <cec.h>
#include <opal.h>
#include <io.h>
#include <vpd.h>
#include <interrupts.h>
#include <ccan/str/str.h>

/*
 * Determine the base address of LEM registers according to
 * the indicated error source.
 */
static void *p7ioc_LEM_base(struct p7ioc *ioc, uint32_t err_src)
{
	uint32_t index;
	void *base = NULL;

	switch (err_src) {
	case P7IOC_ERR_SRC_RGC:
		base = ioc->regs + P7IOC_RGC_LEM_BASE;
		break;
	case P7IOC_ERR_SRC_BI_UP:
		base = ioc->regs + P7IOC_BI_UP_LEM_BASE;
		break;
	case P7IOC_ERR_SRC_BI_DOWN:
		base = ioc->regs + P7IOC_BI_DOWN_LEM_BASE;
		break;
	case P7IOC_ERR_SRC_CI_P0:
	case P7IOC_ERR_SRC_CI_P1:
	case P7IOC_ERR_SRC_CI_P2:
	case P7IOC_ERR_SRC_CI_P3:
	case P7IOC_ERR_SRC_CI_P4:
	case P7IOC_ERR_SRC_CI_P5:
	case P7IOC_ERR_SRC_CI_P6:
	case P7IOC_ERR_SRC_CI_P7:
		index = err_src - P7IOC_ERR_SRC_CI_P0;
		base = ioc->regs + P7IOC_CI_PORTn_LEM_BASE(index);
		break;
	case P7IOC_ERR_SRC_PHB0:
	case P7IOC_ERR_SRC_PHB1:
	case P7IOC_ERR_SRC_PHB2:
	case P7IOC_ERR_SRC_PHB3:
	case P7IOC_ERR_SRC_PHB4:
	case P7IOC_ERR_SRC_PHB5:
		index = err_src - P7IOC_ERR_SRC_PHB0;
		base = ioc->regs + P7IOC_PHBn_LEM_BASE(index);
		break;
	case P7IOC_ERR_SRC_MISC:
		base = ioc->regs + P7IOC_MISC_LEM_BASE;
		break;
	case P7IOC_ERR_SRC_I2C:
		base = ioc->regs + P7IOC_I2C_LEM_BASE;
		break;
	default:
		prerror("%s: Unknown error source %d\n",
			__func__, err_src);
	}

	return base;
}

static void p7ioc_get_diag_common(struct p7ioc *ioc,
				  void *base,
				  struct OpalIoP7IOCErrorData *data)
{
	/* GEM */
	data->gemXfir    = in_be64(ioc->regs + P7IOC_GEM_XFIR);
	data->gemRfir    = in_be64(ioc->regs + P7IOC_GEM_RFIR);
	data->gemRirqfir = in_be64(ioc->regs + P7IOC_GEM_RIRQFIR);
	data->gemMask    = in_be64(ioc->regs + P7IOC_GEM_MASK);
	data->gemRwof    = in_be64(ioc->regs + P7IOC_GEM_RWOF);

	/* LEM */
	data->lemFir     = in_be64(base + P7IOC_LEM_FIR_OFFSET);
	data->lemErrMask = in_be64(base + P7IOC_LEM_ERR_MASK_OFFSET);
	data->lemAction0 = in_be64(base + P7IOC_LEM_ACTION_0_OFFSET);
	data->lemAction1 = in_be64(base + P7IOC_LEM_ACTION_1_OFFSET);
	data->lemWof     = in_be64(base + P7IOC_LEM_WOF_OFFSET);
}

static int64_t p7ioc_get_diag_data(struct io_hub *hub,
				   void *diag_buffer,
				   uint64_t diag_buffer_len)
{
	struct p7ioc *ioc = iohub_to_p7ioc(hub);
	struct OpalIoP7IOCErrorData *data = diag_buffer;
	void *base;

	/* Make sure we have enough buffer */
	if (diag_buffer_len < sizeof(struct OpalIoP7IOCErrorData))
		return OPAL_PARAMETER;

	/* We need do nothing if there're no pending errors */
	if (!p7ioc_err_pending(ioc))
		return OPAL_CLOSED;

	/*
	 * We needn't collect diag-data for CI Port{2, ..., 7}
	 * and PHB{0, ..., 5} since their errors (except GXE)
	 * have been cached to the specific PHB.
	 */
	base = p7ioc_LEM_base(ioc, ioc->err.err_src);
	if (!base) {
		p7ioc_set_err_pending(ioc, false);
		return OPAL_INTERNAL_ERROR;
	}

	switch (ioc->err.err_src) {
	case P7IOC_ERR_SRC_RGC:
		data->type = OPAL_P7IOC_DIAG_TYPE_RGC;
		p7ioc_get_diag_common(ioc, base, data);

		data->rgc.rgcStatus	= in_be64(ioc->regs + 0x3E1C10);
		data->rgc.rgcLdcp	= in_be64(ioc->regs + 0x3E1C18);

		break;
	case P7IOC_ERR_SRC_BI_UP:
		data->type = OPAL_P7IOC_DIAG_TYPE_BI;
		data->bi.biDownbound = 0;
		p7ioc_get_diag_common(ioc, base, data);

		data->bi.biLdcp0	= in_be64(ioc->regs + 0x3C0100);
		data->bi.biLdcp1	= in_be64(ioc->regs + 0x3C0108);
		data->bi.biLdcp2	= in_be64(ioc->regs + 0x3C0110);
		data->bi.biFenceStatus	= in_be64(ioc->regs + 0x3C0130);

		break;
	case P7IOC_ERR_SRC_BI_DOWN:
		data->type = OPAL_P7IOC_DIAG_TYPE_BI;
		data->bi.biDownbound = 1;
		p7ioc_get_diag_common(ioc, base, data);

		data->bi.biLdcp0	= in_be64(ioc->regs + 0x3C0118);
		data->bi.biLdcp1	= in_be64(ioc->regs + 0x3C0120);
		data->bi.biLdcp2	= in_be64(ioc->regs + 0x3C0128);
		data->bi.biFenceStatus	= in_be64(ioc->regs + 0x3C0130);

		break;
	case P7IOC_ERR_SRC_CI_P0:
	case P7IOC_ERR_SRC_CI_P1:
		data->type = OPAL_P7IOC_DIAG_TYPE_CI;
		data->ci.ciPort = ioc->err.err_src - P7IOC_ERR_SRC_CI_P0;
		p7ioc_get_diag_common(ioc, base, data);

		data->ci.ciPortStatus	= in_be64(base + 0x008);
		data->ci.ciPortLdcp	= in_be64(base + 0x010);
		break;
	case P7IOC_ERR_SRC_MISC:
		data->type = OPAL_P7IOC_DIAG_TYPE_MISC;
		p7ioc_get_diag_common(ioc, base, data);
		break;
	case P7IOC_ERR_SRC_I2C:
		data->type = OPAL_P7IOC_DIAG_TYPE_I2C;
		p7ioc_get_diag_common(ioc, base, data);
		break;
	default:
		p7ioc_set_err_pending(ioc, false);
		return OPAL_CLOSED;
	}

	/* For errors of MAL class, we need mask it */
	if (ioc->err.err_class == P7IOC_ERR_CLASS_MAL)
		out_be64(base + P7IOC_LEM_ERR_MASK_OR_OFFSET,
			 PPC_BIT(63 - ioc->err.err_bit));
	p7ioc_set_err_pending(ioc, false);

	return OPAL_SUCCESS;
}

static const struct io_hub_ops p7ioc_hub_ops = {
	.get_diag_data	= p7ioc_get_diag_data,
	.reset		= p7ioc_reset,
};

static int64_t p7ioc_rgc_get_xive(struct irq_source *is, uint32_t isn,
				  uint16_t *server, uint8_t *prio)
{
	struct p7ioc *ioc = is->data;
	uint32_t irq = (isn & 0xf);
	uint32_t fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive;

	if (fbuid != ioc->rgc_buid)
		return OPAL_PARAMETER;

	xive = ioc->xive_cache[irq];
	*server = GETFIELD(IODA_XIVT_SERVER, xive);
	*prio = GETFIELD(IODA_XIVT_PRIORITY, xive);

	return OPAL_SUCCESS;
 }

static int64_t p7ioc_rgc_set_xive(struct irq_source *is, uint32_t isn,
				  uint16_t server, uint8_t prio)
{
	struct p7ioc *ioc = is->data;
	uint32_t irq = (isn & 0xf);
	uint32_t fbuid = P7_IRQ_FBUID(isn);
	uint64_t xive;
	uint64_t m_server, m_prio;

	if (fbuid != ioc->rgc_buid)
		return OPAL_PARAMETER;

	xive = SETFIELD(IODA_XIVT_SERVER, 0ull, server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, prio);
	ioc->xive_cache[irq] = xive;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		m_server = 0;
		m_prio = 0xff;
	} else {
		m_server = server >> 3;
		m_prio = (prio >> 3) | ((server & 7) << 5);
	}

	/* Update the XIVE. Don't care HRT entry on P7IOC */
	out_be64(ioc->regs + 0x3e1820, (0x0002000000000000UL | irq));
	xive = in_be64(ioc->regs + 0x3e1830);
	xive = SETFIELD(IODA_XIVT_SERVER, xive, m_server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, m_prio);
	out_be64(ioc->regs + 0x3e1830, xive);

	return OPAL_SUCCESS;
}

/*
 * The function is used to figure out the error class and error
 * bit according to LEM WOF.
 *
 * The bits of WOF register have been classified according to
 * the error severity. Of course, we should process those errors
 * with higher priority. For example, there have 2 errors (GXE, INF)
 * pending, we should process GXE, and INF is meaningless in face
 * of GXE.
 */
static bool p7ioc_err_bit(struct p7ioc *ioc, uint64_t wof)
{
	uint64_t val, severity[P7IOC_ERR_CLASS_LAST];
        int32_t class, bit, err_bit = -1;

	/* Clear severity array */
	memset(severity, 0, sizeof(uint64_t) * P7IOC_ERR_CLASS_LAST);

	/*
	 * The severity array has fixed values. However, it depends
	 * on the damage settings for individual components. We're
	 * using fixed values based on the assumption that damage settings
	 * are fixed for now. If we change it some day, we also need
	 * change the severity array accordingly. Anyway, it's something
	 * to improve in future so that we can figure out the severity
	 * array from hardware registers.
	 */
	switch (ioc->err.err_src) {
	case P7IOC_ERR_SRC_EI:
		/* EI won't create interrupt yet */
		break;
	case P7IOC_ERR_SRC_RGC:
		severity[P7IOC_ERR_CLASS_GXE] = 0xF00086E0F4FCFFFFUL;
		severity[P7IOC_ERR_CLASS_RGA] = 0x0000010000000000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0x0FFF781F0B030000UL;
		break;
	case P7IOC_ERR_SRC_BI_UP:
		severity[P7IOC_ERR_CLASS_GXE] = 0xF7FFFFFF7FFFFFFFUL;
		severity[P7IOC_ERR_CLASS_INF] = 0x0800000080000000UL;
		break;
	case P7IOC_ERR_SRC_BI_DOWN:
		severity[P7IOC_ERR_CLASS_GXE] = 0xDFFFF7F35F8000BFUL;
		severity[P7IOC_ERR_CLASS_INF] = 0x2000080CA07FFF40UL;
		break;
	case P7IOC_ERR_SRC_CI_P0:
		severity[P7IOC_ERR_CLASS_GXE] = 0xF5FF000000000000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0x0200FFFFFFFFFFFFUL;
		severity[P7IOC_ERR_CLASS_MAL] = 0x0800000000000000UL;
		break;
	case P7IOC_ERR_SRC_CI_P1:
		severity[P7IOC_ERR_CLASS_GXE] = 0xFFFF000000000000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0x0000FFFFFFFFFFFFUL;
		break;
	case P7IOC_ERR_SRC_CI_P2:
	case P7IOC_ERR_SRC_CI_P3:
	case P7IOC_ERR_SRC_CI_P4:
	case P7IOC_ERR_SRC_CI_P5:
	case P7IOC_ERR_SRC_CI_P6:
	case P7IOC_ERR_SRC_CI_P7:
		severity[P7IOC_ERR_CLASS_GXE] = 0x5B0B000000000000UL;
		severity[P7IOC_ERR_CLASS_PHB] = 0xA4F4000000000000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0x0000FFFFFFFFFFFFUL;
		break;
	case P7IOC_ERR_SRC_MISC:
		severity[P7IOC_ERR_CLASS_GXE] = 0x0000000310000000UL;
		severity[P7IOC_ERR_CLASS_PLL] = 0x0000000001C00000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0x555FFFF0EE3FFFFFUL;
		severity[P7IOC_ERR_CLASS_MAL] = 0xAAA0000C00000000UL;
		break;
	case P7IOC_ERR_SRC_I2C:
		severity[P7IOC_ERR_CLASS_GXE] = 0x1100000000000000UL;
		severity[P7IOC_ERR_CLASS_INF] = 0xEEFFFFFFFFFFFFFFUL;
		break;
	case P7IOC_ERR_SRC_PHB0:
	case P7IOC_ERR_SRC_PHB1:
	case P7IOC_ERR_SRC_PHB2:
	case P7IOC_ERR_SRC_PHB3:
	case P7IOC_ERR_SRC_PHB4:
	case P7IOC_ERR_SRC_PHB5:
		severity[P7IOC_ERR_CLASS_PHB] = 0xADB650CB808DD051UL;
		severity[P7IOC_ERR_CLASS_ER]  = 0x0000A0147F50092CUL;
		severity[P7IOC_ERR_CLASS_INF] = 0x52490F2000222682UL;
		break;
	}

        /*
         * The error class (ERR_CLASS) has been defined based on
         * their severity. The priority of those errors out of same
         * class should be defined based on the position of corresponding
         * bit in LEM (Local Error Macro) register.
         */
	for (class = P7IOC_ERR_CLASS_NONE + 1;
	     err_bit < 0 && class < P7IOC_ERR_CLASS_LAST;
	     class++) {
		val = wof & severity[class];
		if (!val) continue;

		for (bit = 0; bit < 64; bit++) {
			if (val & PPC_BIT(bit)) {
				err_bit = 63 - bit;
				break;
			}
		}
	}

	/* If we don't find the error bit, we needn't go on. */
	if (err_bit < 0)
		return false;

	ioc->err.err_class = class - 1;
	ioc->err.err_bit   = err_bit;
	return true;
}

/*
 * Check LEM to determine the detailed error information.
 * The function is expected to be called while OS calls
 * to OPAL API opal_pci_next_error(). Eventually, the errors
 * from CI Port{2, ..., 7} or PHB{0, ..., 5} would be cached
 * to the specific PHB, the left errors would be cached to
 * the IOC.
 */
bool p7ioc_check_LEM(struct p7ioc *ioc,
		     uint16_t *pci_error_type,
		     uint16_t *severity)
{
	void *base;
	uint64_t fir, wof, mask;
	struct p7ioc_phb *p;
	int32_t index;
	bool ret;

	/* Make sure we have error pending on IOC */
	if (!p7ioc_err_pending(ioc))
		return false;

	/*
	 * The IOC probably has been put to fatal error
	 * state (GXE) because of failure on reading on
	 * GEM FIR.
	 */
	if (ioc->err.err_src == P7IOC_ERR_SRC_NONE &&
	    ioc->err.err_class != P7IOC_ERR_CLASS_NONE)
		goto err;

	/*
	 * Get the base address of LEM registers according
	 * to the error source. If we failed to get that,
	 * the error pending flag would be cleared.
	 */
	base = p7ioc_LEM_base(ioc, ioc->err.err_src);
	if (!base) {
		p7ioc_set_err_pending(ioc, false);
		return false;
	}

	/* IOC would be broken upon broken FIR */
	fir = in_be64(base + P7IOC_LEM_FIR_OFFSET);
	if (fir == 0xffffffffffffffffUL) {
		ioc->err.err_src   = P7IOC_ERR_SRC_NONE;
		ioc->err.err_class = P7IOC_ERR_CLASS_GXE;
		goto err;
	}

	/* Read on ERR_MASK and WOF. However, we needn't do for PHBn */
	wof = in_be64(base + P7IOC_LEM_WOF_OFFSET);
	if (ioc->err.err_src >= P7IOC_ERR_SRC_PHB0 &&
	    ioc->err.err_src <= P7IOC_ERR_SRC_PHB5) {
		mask = 0x0ull;
	} else {
		mask = in_be64(base + P7IOC_LEM_ERR_MASK_OFFSET);
		in_be64(base + P7IOC_LEM_ACTION_0_OFFSET);
		in_be64(base + P7IOC_LEM_ACTION_1_OFFSET);
	}

        /*
         * We need process those unmasked error first. If we're
         * failing to get the error bit, we needn't proceed.
         */
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		p7ioc_set_err_pending(ioc, false);
		return false;
        }

	if (!p7ioc_err_bit(ioc, wof)) {
		p7ioc_set_err_pending(ioc, false);
		return false;
	}

err:
	/*
	 * We run into here because of valid error. Those errors
	 * from CI Port{2, ..., 7} and PHB{0, ..., 5} will be cached
	 * to the specific PHB. However, we will cache the global
	 * errors (e.g. GXE) to IOC directly. For the left errors,
	 * they will be cached to IOC.
	 */
	if (((ioc->err.err_src >= P7IOC_ERR_SRC_CI_P2  &&
	      ioc->err.err_src <= P7IOC_ERR_SRC_CI_P7) ||
	     (ioc->err.err_src >= P7IOC_ERR_SRC_PHB0   &&
	      ioc->err.err_src <= P7IOC_ERR_SRC_PHB5)) &&
	     ioc->err.err_class != P7IOC_ERR_CLASS_GXE) {
		index = (ioc->err.err_src >= P7IOC_ERR_SRC_PHB0 &&
			 ioc->err.err_src <= P7IOC_ERR_SRC_PHB5) ?
			(ioc->err.err_src - P7IOC_ERR_SRC_PHB0) :
			(ioc->err.err_src - P7IOC_ERR_SRC_CI_P2);
		p = &ioc->phbs[index];

		if (p7ioc_phb_enabled(ioc, index)) {
			p->err.err_src   = ioc->err.err_src;
			p->err.err_class = ioc->err.err_class;
			p->err.err_bit   = ioc->err.err_bit;
			p7ioc_phb_set_err_pending(p, true);
			p7ioc_set_err_pending(ioc, false);

			return false;
		}
	}

	/*
	 * Map the internal error class to that OS can recognize.
	 * Errors from PHB or the associated CI port would be
	 * GXE, PHB-fatal, ER, or INF. For the case, GXE will be
	 * cached to IOC and the left classes will be cached to
	 * the specific PHB.
	 */
	switch (ioc->err.err_class) {
	case P7IOC_ERR_CLASS_GXE:
	case P7IOC_ERR_CLASS_PLL:
	case P7IOC_ERR_CLASS_RGA:
		*pci_error_type = OPAL_EEH_IOC_ERROR;
		*severity = OPAL_EEH_SEV_IOC_DEAD;
		ret = true;
		break;
	case P7IOC_ERR_CLASS_INF:
	case P7IOC_ERR_CLASS_MAL:
		*pci_error_type = OPAL_EEH_IOC_ERROR;
		*severity = OPAL_EEH_SEV_INF;
		ret = false;
		break;
	default:
		p7ioc_set_err_pending(ioc, false);
		ret = false;
	}

	return ret;
}

/*
 * Check GEM to see if there has any problematic components.
 * The function is expected to be called in RGC interrupt
 * handler. Also, it's notable that failure on reading on
 * XFIR will cause GXE directly.
 */
static bool p7ioc_check_GEM(struct p7ioc *ioc)
{
	uint64_t xfir, rwof;

	/*
	 * Recov_5: Read GEM Xfir
	 * Recov_6: go to GXE recovery?
	 */
	xfir = in_be64(ioc->regs + P7IOC_GEM_XFIR);
	if (xfir == 0xffffffffffffffffUL) {
		ioc->err.err_src   = P7IOC_ERR_SRC_NONE;
		ioc->err.err_class = P7IOC_ERR_CLASS_GXE;
		p7ioc_set_err_pending(ioc, true);
		return true;
	}

	/*
	 * Recov_7: Read GEM Rfir
	 * Recov_8: Read GEM RIRQfir
	 * Recov_9: Read GEM RWOF
	 * Recov_10: Read Fence Shadow
	 * Recov_11: Read Fence Shadow WOF
	 */
        in_be64(ioc->regs + P7IOC_GEM_RFIR);
        in_be64(ioc->regs + P7IOC_GEM_RIRQFIR);
	rwof = in_be64(ioc->regs + P7IOC_GEM_RWOF);
	in_be64(ioc->regs + P7IOC_CHIP_FENCE_SHADOW);
	in_be64(ioc->regs + P7IOC_CHIP_FENCE_WOF);

	/*
	 * Check GEM RWOF to see which component has been
	 * put into problematic state.
	 */
	ioc->err.err_src = P7IOC_ERR_SRC_NONE;
	if	(rwof & PPC_BIT(1))  ioc->err.err_src = P7IOC_ERR_SRC_RGC;
	else if (rwof & PPC_BIT(2))  ioc->err.err_src = P7IOC_ERR_SRC_BI_UP;
	else if (rwof & PPC_BIT(3))  ioc->err.err_src = P7IOC_ERR_SRC_BI_DOWN;
	else if (rwof & PPC_BIT(4))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P0;
	else if (rwof & PPC_BIT(5))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P1;
	else if (rwof & PPC_BIT(6))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P2;
	else if (rwof & PPC_BIT(7))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P3;
	else if (rwof & PPC_BIT(8))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P4;
	else if (rwof & PPC_BIT(9))  ioc->err.err_src = P7IOC_ERR_SRC_CI_P5;
	else if (rwof & PPC_BIT(10)) ioc->err.err_src = P7IOC_ERR_SRC_CI_P6;
	else if (rwof & PPC_BIT(11)) ioc->err.err_src = P7IOC_ERR_SRC_CI_P7;
	else if (rwof & PPC_BIT(16)) ioc->err.err_src = P7IOC_ERR_SRC_PHB0;
	else if (rwof & PPC_BIT(17)) ioc->err.err_src = P7IOC_ERR_SRC_PHB1;
	else if (rwof & PPC_BIT(18)) ioc->err.err_src = P7IOC_ERR_SRC_PHB2;
	else if (rwof & PPC_BIT(19)) ioc->err.err_src = P7IOC_ERR_SRC_PHB3;
	else if (rwof & PPC_BIT(20)) ioc->err.err_src = P7IOC_ERR_SRC_PHB4;
	else if (rwof & PPC_BIT(21)) ioc->err.err_src = P7IOC_ERR_SRC_PHB5;
	else if (rwof & PPC_BIT(24)) ioc->err.err_src = P7IOC_ERR_SRC_MISC;
	else if (rwof & PPC_BIT(25)) ioc->err.err_src = P7IOC_ERR_SRC_I2C;

	/*
	 * If we detect any problematic components, the OS is
	 * expected to poll that for more details through OPAL
	 * interface.
	 */
        if (ioc->err.err_src != P7IOC_ERR_SRC_NONE) {
		p7ioc_set_err_pending(ioc, true);
		return true;
	}

	return false;
}

static void p7ioc_rgc_interrupt(struct irq_source *is, uint32_t isn)
{
	struct p7ioc *ioc = is->data;

	printf("Got RGC interrupt 0x%04x\n", isn);

	/* We will notify OS while getting error from GEM */
	if (p7ioc_check_GEM(ioc))
		/* This is a bit hacky but works - we raise the event
		on a downstream phb as the OS needs to call
		opal_pci_next_error for all phbs to ensure all events
		are cleared anyway. */
		opal_pci_eeh_set_evt(ioc->phbs[0].phb.opal_id);
}

static const struct irq_source_ops p7ioc_rgc_irq_ops = {
	.get_xive = p7ioc_rgc_get_xive,
	.set_xive = p7ioc_rgc_set_xive,
	.interrupt = p7ioc_rgc_interrupt,
};

static void p7ioc_create_hub(struct dt_node *np)
{
	struct p7ioc *ioc;
	unsigned int i, id;
	u64 bar1, bar2;
	u32 pdt;
	char *path;

	/* Use the BUID extension as ID and add it to device-tree */
	id = dt_prop_get_u32(np, "ibm,buid-ext");
	path = dt_get_path(np);
	printf("P7IOC: Found at %s ID 0x%x\n", path, id);
	free(path);

	/* Load VPD LID */
	vpd_preload(np);
	vpd_iohub_load(np);

	ioc = zalloc(sizeof(struct p7ioc));
	if (!ioc)
		return;
	ioc->hub.hub_id = id;
	ioc->hub.ops = &p7ioc_hub_ops;
	ioc->dt_node = np;

	bar1 = dt_prop_get_u64(np, "ibm,gx-bar-1");
	bar2 = dt_prop_get_u64(np, "ibm,gx-bar-2");

	ioc->regs = (void *)bar1;

	ioc->mmio1_win_start = bar1;
	ioc->mmio1_win_size = MWIN1_SIZE;
	ioc->mmio2_win_start = bar2;
	ioc->mmio2_win_size = MWIN2_SIZE;

	ioc->buid_base = id << 9;
	ioc->rgc_buid = ioc->buid_base + RGC_BUID_OFFSET;

	/* Add some DT properties */
	dt_add_property_cells(np, "ibm,opal-hubid", 0, id);

	/* XXX Fixme: how many RGC interrupts ? */
	dt_add_property_cells(np, "interrupt-parent", get_ics_phandle());
	dt_add_property_cells(np, "interrupts", ioc->rgc_buid << 4, 1);
	dt_add_property_cells(np, "interrupt-base", ioc->rgc_buid << 4);

	/* XXX What about ibm,opal-mmio-real ? */

	/* Clear the RGC XIVE cache */
	for (i = 0; i < 16; i++)
		ioc->xive_cache[i] = SETFIELD(IODA_XIVT_PRIORITY, 0ull, 0xff);

	/*
	 * Register RGC interrupts
	 *
	 * For now I assume only 0 is... to verify with Greg or HW guys,
	 * we support all 16
	 */
	register_irq_source(&p7ioc_rgc_irq_ops, ioc, ioc->rgc_buid << 4, 1);

	/* Check for presence detect from HDAT, we use only BR1 on P7IOC */
	pdt = dt_prop_get_u32_def(np, "ibm,br1-presence-detect", 0xffffffff);
	if (pdt != 0xffffffff)
		printf("P7IOC: Presence detect from HDAT : 0x%02x\n", pdt);
	else {
	}
	ioc->phb_pdt = pdt & 0xff;

	/* Setup PHB structures (no HW access yet) */
	for (i = 0; i < P7IOC_NUM_PHBS; i++) {
		if (p7ioc_phb_enabled(ioc, i))
			p7ioc_phb_setup(ioc, i);
		else
			ioc->phbs[i].state = P7IOC_PHB_STATE_OFF;
	}

	/* Now, we do the bulk of the inits */
	p7ioc_inits(ioc);

	printf("P7IOC: Initialization complete\n");

	cec_register(&ioc->hub);
}

void probe_p7ioc(void)
{
	struct dt_node *np;

	dt_for_each_compatible(dt_root, np, "ibm,p7ioc")
		p7ioc_create_hub(np);
}


