/* Copyright 2013-2014 IBM Corp.
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

#define pr_fmt(fmt)	"CHIPTOD: " fmt

#include <skiboot.h>
#include <chiptod.h>
#include <fsp.h>

/* Response status for fsp command 0xE6, s/c 0x06 (Enable/Disable Topology) */
#define FSP_STATUS_TOPO_IN_USE	0xb8		/* topology is in use */

static bool fsp_chiptod_update_topology(uint32_t cmd_sub_mod,
					struct fsp_msg *msg)
{
	struct fsp_msg *resp;
	enum chiptod_topology topo;
	bool action;
	uint8_t status = 0;

	switch (cmd_sub_mod) {
	case FSP_CMD_TOPO_ENABLE_DISABLE:
		/*
		 * Action Values: 0x00 = Disable, 0x01 = Enable
		 * Topology Values: 0x00 = Primary, 0x01 = Secondary
		 */
		action = !!msg->data.bytes[2];
		topo = msg->data.bytes[3];
		prlog(PR_DEBUG, "Topology update event:\n");
		prlog(PR_DEBUG, "  Action = %s, Topology = %s\n",
					action ? "Enable" : "Disable",
					topo ? "Secondary" : "Primary");

		if (!chiptod_adjust_topology(topo, action))
			status = FSP_STATUS_TOPO_IN_USE;
		else
			status = 0x00;

		resp = fsp_mkmsg(FSP_RSP_TOPO_ENABLE_DISABLE | status, 0);
		if (!resp) {
			prerror("Response allocation failed\n");
			return false;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("Failed to queue response msg\n");
		}
		return true;
	default:
		prlog(PR_DEBUG, "Unhandled sub cmd: %06x\n", cmd_sub_mod);
		break;
	}
	return false;
}

static struct fsp_client fsp_chiptod_client = {
		.message = fsp_chiptod_update_topology,
};

void fsp_chiptod_init(void)
{
	/* Register for Class E6 (HW maintanance) */
	fsp_register_client(&fsp_chiptod_client, FSP_MCLASS_HW_MAINT);
}
