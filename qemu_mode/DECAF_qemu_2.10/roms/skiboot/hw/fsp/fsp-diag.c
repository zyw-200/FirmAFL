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
 * Code for handling FSP_MCLASS_DIAG messages (cmd 0xee)
 * Receiving a high level ack timeout is likely indicative of a firmware bug
 */
#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <processor.h>
#include <timebase.h>
#include <opal.h>
#include <fsp-sysparam.h>

static bool fsp_diag_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{

	if (cmd_sub_mod == FSP_RSP_DIAG_LINK_ERROR) {
		printf("FIXME: Unhandled FSP_MCLASS_DIAG Link Error Report\n");
		return false;
	}

	if (cmd_sub_mod != FSP_RSP_DIAG_ACK_TIMEOUT) {
		printf("BUG: Unhandled subcommand: 0x%x (New FSP spec?)\n",
		       cmd_sub_mod);
		return false;
	}

	printf("BUG: High Level ACK timeout (FSP_MCLASS_DIAG) for 0x%x\n",
	       msg->data.words[0] & 0xffff0000);

	return true;
}

static struct fsp_client fsp_diag = {
	.message = fsp_diag_msg,
};

/* This is called at boot time */
void fsp_init_diag(void)
{
	/* Register for the diag event */
	fsp_register_client(&fsp_diag, FSP_MCLASS_DIAG);
}
