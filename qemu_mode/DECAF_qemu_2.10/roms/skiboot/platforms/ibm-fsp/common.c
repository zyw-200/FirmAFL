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
#include <fsp.h>
#include <fsp-sysparam.h>
#include <opal.h>
#include <console.h>
#include <hostservices.h>
#include <ipmi.h>

#include "ibm-fsp.h"

static void map_debug_areas(void)
{
	uint64_t t, i;

	/* Our memcons is in a section of its own and already
	 * aligned to 4K. The buffers are mapped as a whole
	 */
	fsp_tce_map(PSI_DMA_MEMCONS, &memcons, 0x1000);
	fsp_tce_map(PSI_DMA_LOG_BUF, (void*)INMEM_CON_START, INMEM_CON_LEN);

	debug_descriptor.memcons_tce = PSI_DMA_MEMCONS;
	t = memcons.obuf_phys - INMEM_CON_START + PSI_DMA_LOG_BUF;
	debug_descriptor.memcons_obuf_tce = t;
	t = memcons.ibuf_phys - INMEM_CON_START + PSI_DMA_LOG_BUF;
	debug_descriptor.memcons_ibuf_tce = t;

	/* We only have space in the TCE table for the trace
	 * areas on P8
	 */
	if (proc_gen != proc_gen_p8)
		return;

	t = PSI_DMA_TRACE_BASE;
	for (i = 0; i < debug_descriptor.num_traces; i++) {
		/*
		 * Trace buffers are misaligned by 0x10 due to the lock
		 * in the trace structure, and their size is also not
		 * completely aligned. (They are allocated so that with
		 * the lock included, they do cover entire multiple of
		 * a 4K page however).
		 *
		 * This means we have to map the lock into the TCEs and
		 * align everything. Not a huge deal but needs to be
		 * taken into account.
		 *
		 * Note: Maybe we should map them read-only...
		 */
		uint64_t tstart, tend, toff, tsize;

		tstart = ALIGN_DOWN(debug_descriptor.trace_phys[i], 0x1000);
		tend = ALIGN_UP(debug_descriptor.trace_phys[i] +
				debug_descriptor.trace_size[i], 0x1000);
		toff = debug_descriptor.trace_phys[i] - tstart;
		tsize = tend - tstart;

		fsp_tce_map(t, (void *)tstart, tsize);
		debug_descriptor.trace_tce[i] = t + toff;
		t += tsize;
	}
}


void ibm_fsp_init(void)
{
	/* Early initializations of the FSP interface */
	fsp_init();
	map_debug_areas();
	fsp_sysparam_init();

	/* Get ready to receive E0 class messages. We need to respond
	 * to some of these for the init sequence to make forward progress
	 */
	fsp_console_preinit();

	/* Get ready to receive OCC related messages */
	occ_fsp_init();

	/* Get ready to receive Memory [Un]corretable Error messages. */
	fsp_memory_err_init();

	/* Initialize elog access */
	fsp_elog_read_init();
	fsp_elog_write_init();

	/* Initiate dump service */
	fsp_dump_init();

	/* Start FSP/HV state controller & perform OPL */
	fsp_opl();

	/* Preload hostservices lids */
	hservices_lid_preload();

	/* Initialize SP attention area */
	fsp_attn_init();

	/* Initialize monitoring of TOD topology change event notification */
	fsp_chiptod_init();

	/* Send MDST table notification to FSP */
	op_display(OP_LOG, OP_MOD_INIT, 0x0000);
	fsp_mdst_table_init();

	/* Initialize the panel */
	op_display(OP_LOG, OP_MOD_INIT, 0x0001);
	fsp_oppanel_init();

	/* Start the surveillance process */
	op_display(OP_LOG, OP_MOD_INIT, 0x0002);
	fsp_init_surveillance();

	/* IPMI */
	fsp_ipmi_init();
	ipmi_opal_init();

	/* Initialize sensor access */
	op_display(OP_LOG, OP_MOD_INIT, 0x0003);
	fsp_init_sensor();

	/* LED */
	op_display(OP_LOG, OP_MOD_INIT, 0x0004);
	fsp_led_init();

	/* Monitor for DIAG events */
	op_display(OP_LOG, OP_MOD_INIT, 0x0005);
	fsp_init_diag();

	/* Finish initializing the console */
	op_display(OP_LOG, OP_MOD_INIT, 0x0006);
	fsp_console_init();

	/* Read our initial RTC value */
	op_display(OP_LOG, OP_MOD_INIT, 0x0008);
	fsp_rtc_init();

	/* Initialize code update access */
	op_display(OP_LOG, OP_MOD_INIT, 0x0009);
	fsp_code_update_init();

	/* EPOW */
	op_display(OP_LOG, OP_MOD_INIT, 0x000A);
	fsp_epow_init();

	/* EPOW */
	op_display(OP_LOG, OP_MOD_INIT, 0x000B);
	fsp_dpo_init();

	/* Setup console */
	if (fsp_present())
		fsp_console_add_nodes();
}

void ibm_fsp_exit(void)
{
	/*
	 * LED related SPCN commands might take a while to
	 * complete. Call this as late as possible to
	 * ensure we have all the LED information.
	 */
	create_led_device_nodes();
}

int64_t ibm_fsp_cec_reboot(void)
{
	uint32_t cmd = FSP_CMD_REBOOT;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Flash new firmware */
	if (fsp_flash_term_hook &&
	    fsp_flash_term_hook() == OPAL_SUCCESS)
		cmd = FSP_CMD_DEEP_REBOOT;

	printf("FSP: Sending 0x%02x reboot command to FSP...\n", cmd);

	/* If that failed, talk to the FSP */
	if (fsp_sync_msg(fsp_mkmsg(cmd, 0), true))
		return OPAL_INTERNAL_ERROR;

	return OPAL_SUCCESS;
}

int64_t ibm_fsp_cec_power_down(uint64_t request)
{
	/* Request is:
	 *
	 * 0 = normal
	 * 1 = immediate
	 * (we do not allow 2 for "pci cfg reset" just yet)
	 */

	if (request !=0 && request != 1)
		return OPAL_PARAMETER;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Flash new firmware */
	if (fsp_flash_term_hook)
		fsp_flash_term_hook();

	printf("FSP: Sending shutdown command to FSP...\n");

	if (fsp_sync_msg(fsp_mkmsg(FSP_CMD_POWERDOWN_NORM, 1, request), true))
		return OPAL_INTERNAL_ERROR;

	fsp_reset_links();
	return OPAL_SUCCESS;
}

int64_t ibm_fsp_sensor_read(uint32_t sensor_hndl, int token,
				uint32_t *sensor_data)
{
	return fsp_opal_read_sensor(sensor_hndl, token, sensor_data);
}
