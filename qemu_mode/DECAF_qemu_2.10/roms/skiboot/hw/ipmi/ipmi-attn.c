/* Copyright 2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errorlog.h>
#include <ipmi.h>
#include <pel.h>
#include <platform.h>
#include <processor.h>
#include <skiboot.h>
#include <stack.h>
#include <timebase.h>

/* Use same attention SRC for BMC based machine */
DEFINE_LOG_ENTRY(OPAL_RC_ATTN, OPAL_PLATFORM_ERR_EVT,
		 OPAL_ATTN, OPAL_PLATFORM_FIRMWARE,
		 OPAL_ERROR_PANIC, OPAL_ABNORMAL_POWER_OFF);

/* Maximum buffer size to capture backtrace and other useful information */
#define IPMI_TI_BUFFER_SIZE	(IPMI_MAX_PEL_SIZE - PEL_MIN_SIZE)
static char ti_buffer[IPMI_TI_BUFFER_SIZE];

#define STACK_BUF_ENTRIES       20
struct bt_entry bt_buf[STACK_BUF_ENTRIES];

/* Log eSEL event with OPAL backtrace */
static void ipmi_log_terminate_event(const char *msg)
{
	unsigned int bt_entry_cnt = STACK_BUF_ENTRIES;
	unsigned int ti_len;
	unsigned int ti_size;
	struct errorlog *elog_buf;

	/* Fill OPAL version */
	ti_len = snprintf(ti_buffer, IPMI_TI_BUFFER_SIZE,
			  "OPAL version : %s\n", version);

	/* File information */
	ti_len += snprintf(ti_buffer + ti_len, IPMI_TI_BUFFER_SIZE - ti_len,
			   "File info : %s\n", msg);
	ti_size = IPMI_TI_BUFFER_SIZE - ti_len;

	/* Backtrace */
	__backtrace(bt_buf, &bt_entry_cnt);
	__print_backtrace(mfspr(SPR_PIR), bt_buf, bt_entry_cnt,
			  ti_buffer + ti_len, &ti_size, true);

	/* Create eSEL event and commit */
	elog_buf = opal_elog_create(&e_info(OPAL_RC_ATTN), 0);
	log_append_data(elog_buf, (char *)&ti_buffer, ti_len + ti_size);
	log_commit(elog_buf);
}

void __attribute__((noreturn)) ipmi_terminate(const char *msg)
{
	/* Terminate called before initializing IPMI (early abort) */
	if (!ipmi_present()) {
		if (platform.cec_reboot())
			platform.cec_reboot();
		goto out;
	}

	/* Log eSEL event */
	ipmi_log_terminate_event(msg);

	/* Reboot call */
	if (platform.cec_reboot())
		platform.cec_reboot();

out:
	while (1)
		time_wait_ms(100);
}
