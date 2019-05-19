
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

#include <stdlib.h>
#include <ipmi.h>
#include <lock.h>
#include <opal.h>
#include <device.h>
#include <timer.h>
#include <timebase.h>
#include <pool.h>
#include <skiboot.h>

#define TIMER_USE_DONT_LOG	0x80
#define TIMER_USE_DONT_STOP	0x40
#define TIMER_USE_POST		0x02

/* WDT expiration actions */
#define WDT_PRETIMEOUT_SMI	0x10
#define WDT_POWER_CYCLE_ACTION 	0x01
#define WDT_NO_ACTION		0x00

/* How long to set the overall watchdog timeout for. In units of
 * 100ms. If the timer is not reset within this time the watchdog
 * expiration action will occur. */
#define WDT_TIMEOUT		600

/* How often to reset the timer using schedule_timer(). Too short and
we risk accidentally resetting the system due to opal_run_pollers() not
being called in time, too short and we waste time resetting the wdt
more frequently than necessary. */
#define WDT_MARGIN		300

static struct timer wdt_timer;
static bool wdt_stopped = false;

static void ipmi_wdt_complete(struct ipmi_msg *msg)
{
	if (msg->cmd == IPMI_CMD(IPMI_RESET_WDT) && !msg->user_data)
		schedule_timer(&wdt_timer, msecs_to_tb(
				       (WDT_TIMEOUT - WDT_MARGIN)*100));

	ipmi_free_msg(msg);
}

static void set_wdt(uint8_t action, uint16_t count, uint8_t pretimeout)
{
	struct ipmi_msg *ipmi_msg;

	ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_SET_WDT,
			      ipmi_wdt_complete, NULL, NULL, 6, 0);
	if (!ipmi_msg) {
		prerror("Unable to allocate set wdt message\n");
		return;
	}
	ipmi_msg->error = ipmi_wdt_complete;
	ipmi_msg->data[0] = TIMER_USE_POST |
		TIMER_USE_DONT_LOG; 			/* Timer Use */
	ipmi_msg->data[1] = action;			/* Timer Actions */
	ipmi_msg->data[2] = pretimeout;			/* Pre-timeout Interval */
	ipmi_msg->data[3] = 0;				/* Timer Use Flags */
	ipmi_msg->data[4] = count & 0xff;		/* Initial countdown (lsb) */
	ipmi_msg->data[5] = (count >> 8) & 0xff;	/* Initial countdown (msb) */
	ipmi_queue_msg(ipmi_msg);
}

static struct ipmi_msg *wdt_reset_mkmsg(void)
{
	struct ipmi_msg *ipmi_msg;

	ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_RESET_WDT,
			      ipmi_wdt_complete, NULL, NULL, 0, 0);
	if (!ipmi_msg) {
		prerror("Unable to allocate reset wdt message\n");
		return NULL;
	}

	return ipmi_msg;
}

static void sync_reset_wdt(void)
{
	struct ipmi_msg *ipmi_msg;

	if ((ipmi_msg = wdt_reset_mkmsg()))
		ipmi_queue_msg_sync(ipmi_msg);
}

static void reset_wdt(struct timer *t __unused, void *data __unused,
		      uint64_t now __unused)
{
	struct ipmi_msg *ipmi_msg;

	if ((ipmi_msg = wdt_reset_mkmsg()))
		ipmi_queue_msg_head(ipmi_msg);
}

void ipmi_wdt_stop(void)
{
	if (!wdt_stopped) {
		wdt_stopped = true;
		set_wdt(WDT_NO_ACTION, 100, 0);
	}
}

void ipmi_wdt_final_reset(void)
{
	/* todo: this is disabled while we're waiting on fixed watchdog
	 * behaviour */
#if 0
	set_wdt(WDT_POWER_CYCLE_ACTION | WDT_PRETIMEOUT_SMI, WDT_TIMEOUT,
		WDT_MARGIN/10);
	reset_wdt(NULL, (void *) 1);
#endif
	set_wdt(WDT_NO_ACTION, 100, 0);
	ipmi_set_boot_count();
	cancel_timer(&wdt_timer);
}

void ipmi_wdt_init(void)
{
	init_timer(&wdt_timer, reset_wdt, NULL);
	set_wdt(WDT_POWER_CYCLE_ACTION, WDT_TIMEOUT, 0);

	/* Start the WDT. We do it synchronously to make sure it has
	 * started before skiboot continues booting. Otherwise we
	 * could crash before the wdt has actually been started. */
	sync_reset_wdt();

	/* For some reason we have to reset it twice to get it to
	 * actually start the first time. */
	sync_reset_wdt();

	return;
}
