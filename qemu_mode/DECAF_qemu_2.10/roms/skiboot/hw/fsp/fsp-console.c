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
 * Service Processor serial console handling code
 */
#include <skiboot.h>
#include <processor.h>
#include <io.h>
#include <fsp.h>
#include <console.h>
#include <opal.h>
#include <timebase.h>
#include <device.h>
#include <fsp-sysparam.h>

struct fsp_serbuf_hdr {
	u16	partition_id;
	u8	session_id;
	u8	hmc_id;
	u16	data_offset;
	u16	last_valid;
	u16	ovf_count;
	u16	next_in;
	u8	flags;
	u8	reserved;
	u16	next_out;
	u8	data[];
};
#define SER_BUF_DATA_SIZE	(0x10000 - sizeof(struct fsp_serbuf_hdr))

struct fsp_serial {
	bool			available;
	bool			open;
	bool			has_part0;
	bool			has_part1;
	bool			log_port;
	bool			out_poke;
	char			loc_code[LOC_CODE_SIZE];
	u16			rsrc_id;
	struct fsp_serbuf_hdr	*in_buf;
	struct fsp_serbuf_hdr	*out_buf;
	struct fsp_msg		*poke_msg;
	u8			waiting;
};

#define SER_BUFFER_SIZE 0x00040000UL
#define MAX_SERIAL	4

static struct fsp_serial fsp_serials[MAX_SERIAL];
static bool got_intf_query;
static struct lock fsp_con_lock = LOCK_UNLOCKED;
static void* ser_buffer = NULL;

static void fsp_console_reinit(void)
{
	int i;
	void *base;
	struct fsp_msg *msg;

	/* Initialize out data structure pointers & TCE maps */
	base = ser_buffer;
	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *ser = &fsp_serials[i];

		ser->in_buf = base;
		ser->out_buf = base + SER_BUFFER_SIZE/2;
		base += SER_BUFFER_SIZE;
	}
	fsp_tce_map(PSI_DMA_SER0_BASE, ser_buffer,
			4 * PSI_DMA_SER0_SIZE);

	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];

		if (fs->rsrc_id == 0xffff)
			continue;
		prlog(PR_DEBUG, "FSP: Reassociating HVSI console %d\n", i);
		msg = fsp_mkmsg(FSP_CMD_ASSOC_SERIAL, 2,
				(fs->rsrc_id << 16) | 1, i);
		if (!msg) {
			prerror("FSPCON: Failed to allocate associate msg\n");
			return;
		}
		if (fsp_queue_msg(msg, fsp_freemsg)) {
			fsp_freemsg(msg);
			prerror("FSPCON: Failed to queue associate msg\n");
			return;
		}
	}
}

static void fsp_close_consoles(void)
{
	unsigned int i;

	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];

		if (!fs->available)
			continue;

		if (fs->rsrc_id == 0xffff)	/* Get clarity from benh */
			continue;

		lock(&fsp_con_lock);
		if (fs->open) {
			fs->open = false;
			fs->out_poke = false;
			if (fs->poke_msg->state != fsp_msg_unused)
				fsp_cancelmsg(fs->poke_msg);
			fsp_freemsg(fs->poke_msg);
			fs->poke_msg = NULL;
		}
		unlock(&fsp_con_lock);
	}
	prlog(PR_DEBUG, "FSPCON: Closed consoles due to FSP reset/reload\n");
}

static void fsp_pokemsg_reclaim(struct fsp_msg *msg)
{
	struct fsp_serial *fs = msg->user_data;

	/*
	 * The poke_msg might have been "detached" from the console
	 * in vserial_close, so we need to check whether it's current
	 * before touching the state, otherwise, just free it
	 */
	lock(&fsp_con_lock);
	if (fs->open && fs->poke_msg == msg) {
		if (fs->out_poke) {
			if (fsp_queue_msg(fs->poke_msg, fsp_pokemsg_reclaim)) {
				prerror("FSPCON: failed to queue poke msg\n");
				fsp_freemsg(msg);
			} else {
				fs->out_poke = false;
			}
		} else
			fs->poke_msg->state = fsp_msg_unused;
	} else
		fsp_freemsg(msg);
	unlock(&fsp_con_lock);
}

/* Called with the fsp_con_lock held */
static size_t fsp_write_vserial(struct fsp_serial *fs, const char *buf,
				size_t len)
{
	struct fsp_serbuf_hdr *sb = fs->out_buf;
	u16 old_nin = sb->next_in;
	u16 space, chunk;

	if (!fs->open)
		return 0;

	space = (sb->next_out + SER_BUF_DATA_SIZE - old_nin - 1)
		% SER_BUF_DATA_SIZE;
	if (space < len)
		len = space;
	if (!len)
		return 0;

	chunk = SER_BUF_DATA_SIZE - old_nin;
	if (chunk > len)
		chunk = len;
	memcpy(&sb->data[old_nin], buf, chunk);
	if (chunk < len)
		memcpy(&sb->data[0], buf + chunk, len - chunk);
	lwsync();
	sb->next_in = (old_nin + len) % SER_BUF_DATA_SIZE;
	sync();

	if (sb->next_out == old_nin && fs->poke_msg) {
		if (fs->poke_msg->state == fsp_msg_unused) {
			if (fsp_queue_msg(fs->poke_msg, fsp_pokemsg_reclaim))
				prerror("FSPCON: poke msg queuing failed\n");
		} else
			fs->out_poke = true;
	}
#ifndef DISABLE_CON_PENDING_EVT
	opal_update_pending_evt(OPAL_EVENT_CONSOLE_OUTPUT,
				OPAL_EVENT_CONSOLE_OUTPUT);
#endif
	return len;
}

#ifdef DVS_CONSOLE
static int fsp_con_port = -1;
static bool fsp_con_full;

/*
 * This is called by the code in console.c without the con_lock
 * held. However it can be called as the result of any printf
 * thus any other lock might be held including possibly the
 * FSP lock
 */
static size_t fsp_con_write(const char *buf, size_t len)
{
	size_t written;

	if (fsp_con_port < 0)
		return 0;

	lock(&fsp_con_lock);
	written = fsp_write_vserial(&fsp_serials[fsp_con_port], buf, len);
	fsp_con_full = (written < len);
	unlock(&fsp_con_lock);

	return written;
}

static struct con_ops fsp_con_ops = {
	.write = fsp_con_write,
};
#endif /* DVS_CONSOLE */

static void fsp_open_vserial(struct fsp_msg *msg)
{
	struct fsp_msg *resp;

	u16 part_id = msg->data.words[0] & 0xffff;
	u16 sess_id = msg->data.words[1] & 0xffff;
	u8 hmc_sess = msg->data.bytes[0];	
	u8 hmc_indx = msg->data.bytes[1];
	u8 authority = msg->data.bytes[4];
	u32 tce_in, tce_out;
	struct fsp_serial *fs;

	prlog(PR_INFO, "FSPCON: Got VSerial Open\n");
	prlog(PR_DEBUG, "  part_id   = 0x%04x\n", part_id);
	prlog(PR_DEBUG, "  sess_id   = 0x%04x\n", sess_id);
	prlog(PR_DEBUG, "  hmc_sess  = 0x%02x\n", hmc_sess);
	prlog(PR_DEBUG, "  hmc_indx  = 0x%02x\n", hmc_indx);
	prlog(PR_DEBUG, "  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		prlog(PR_WARNING, "FSPCON: 0x%04x  NOT AVAILABLE!\n", sess_id);
		resp = fsp_mkmsg(FSP_RSP_OPEN_VSERIAL | 0x2f, 0);
		if (!resp) {
			prerror("FSPCON: Response allocation failed\n");
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("FSPCON: Failed to queue response msg\n");
		}
		return;
	}

	fs = &fsp_serials[sess_id];

	/* Hack ! On blades, the console opened via the mm has partition 1
	 * while the debug DVS generally has partition 0 (though you can
	 * use what you want really).
	 * We don't want a DVS open/close to crap on the blademm console
	 * thus if it's a raw console, gets an open with partID 1, we
	 * set a flag that ignores the close of partid 0
	 */
	if (fs->rsrc_id == 0xffff) {
		if (part_id == 0)
			fs->has_part0 = true;
		if (part_id == 1)
			fs->has_part1 = true;
	}

	tce_in = PSI_DMA_SER0_BASE + PSI_DMA_SER0_SIZE * sess_id;
	tce_out = tce_in + SER_BUFFER_SIZE/2;

	lock(&fsp_con_lock);
	if (fs->open) {
		prlog(PR_DEBUG, "  already open, skipping init !\n");
		unlock(&fsp_con_lock);
		goto already_open;
	}

	fs->open = true;

	fs->poke_msg = fsp_mkmsg(FSP_CMD_VSERIAL_OUT, 2,
				 msg->data.words[0],
				 msg->data.words[1] & 0xffff);
	fs->poke_msg->user_data = fs;

	fs->in_buf->partition_id = fs->out_buf->partition_id = part_id;
	fs->in_buf->session_id	 = fs->out_buf->session_id   = sess_id;
	fs->in_buf->hmc_id       = fs->out_buf->hmc_id       = hmc_indx;
	fs->in_buf->data_offset  = fs->out_buf->data_offset  =
		sizeof(struct fsp_serbuf_hdr);
	fs->in_buf->last_valid   = fs->out_buf->last_valid   =
		SER_BUF_DATA_SIZE - 1;
	fs->in_buf->ovf_count    = fs->out_buf->ovf_count    = 0;
	fs->in_buf->next_in      = fs->out_buf->next_in      = 0;
	fs->in_buf->flags        = fs->out_buf->flags        = 0;
	fs->in_buf->reserved     = fs->out_buf->reserved     = 0;
	fs->in_buf->next_out     = fs->out_buf->next_out     = 0;
	unlock(&fsp_con_lock);

 already_open:
	resp = fsp_mkmsg(FSP_RSP_OPEN_VSERIAL, 6, msg->data.words[0],
			msg->data.words[1] & 0xffff, 0, tce_in, 0, tce_out);
	if (!resp) {
		prerror("FSPCON: Failed to allocate open msg response\n");
		return;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror("FSPCON: Failed to queue open msg response\n");
		return;
	}

#ifdef DVS_CONSOLE
	prlog(PR_DEBUG, "  log_port  = %d\n", fs->log_port);
	if (fs->log_port) {
		fsp_con_port = sess_id;
		sync();
		/*
		 * We mark the FSP lock as being in the console
		 * path. We do that only once, we never unmark it
		 * (there is really no much point)
		 */
		fsp_used_by_console();
		fsp_con_lock.in_con_path = true;
		/* See comment in fsp_used_by_console */
		lock(&fsp_con_lock);
		unlock(&fsp_con_lock);
		set_console(&fsp_con_ops);
	}
#endif
}

static void fsp_close_vserial(struct fsp_msg *msg)
{
	u16 part_id = msg->data.words[0] & 0xffff;
	u16 sess_id = msg->data.words[1] & 0xffff;
	u8 hmc_sess = msg->data.bytes[0];	
	u8 hmc_indx = msg->data.bytes[1];
	u8 authority = msg->data.bytes[4];
	struct fsp_serial *fs;
	struct fsp_msg *resp;

	prlog(PR_INFO, "FSPCON: Got VSerial Close\n");
	prlog(PR_DEBUG, "  part_id   = 0x%04x\n", part_id);
	prlog(PR_DEBUG, "  sess_id   = 0x%04x\n", sess_id);
	prlog(PR_DEBUG, "  hmc_sess  = 0x%02x\n", hmc_sess);
	prlog(PR_DEBUG, "  hmc_indx  = 0x%02x\n", hmc_indx);
	prlog(PR_DEBUG, "  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		prlog(PR_WARNING, "FSPCON: 0x%04x  NOT AVAILABLE!\n", sess_id);
		goto skip_close;
	}

	fs = &fsp_serials[sess_id];

	/* See "HACK" comment in open */
	if (fs->rsrc_id == 0xffff) {
		if (part_id == 0)
			fs->has_part0 = false;
		if (part_id == 1)
			fs->has_part1 = false;
		if (fs->has_part0 || fs->has_part1) {
			prlog(PR_DEBUG, "  skipping close !\n");
			goto skip_close;
		}
	}

#ifdef DVS_CONSOLE
	if (fs->log_port) {
		fsp_con_port = -1;
		set_console(NULL);
	}
#endif
	
	lock(&fsp_con_lock);
	if (fs->open) {
		fs->open = false;
		fs->out_poke = false;
		if (fs->poke_msg && fs->poke_msg->state == fsp_msg_unused) {
			fsp_freemsg(fs->poke_msg);
			fs->poke_msg = NULL;
		}
	}
	unlock(&fsp_con_lock);
 skip_close:
	resp = fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL, 2, msg->data.words[0],
			msg->data.words[1] & 0xffff);
	if (!resp) {
		prerror("FSPCON: Failed to allocate close msg response\n");
		return;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror("FSPCON: Failed to queue close msg response\n");
	}
}

static bool fsp_con_msg_hmc(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	struct fsp_msg *resp;

	/* Associate response */
	if ((cmd_sub_mod >> 8) == 0xe08a) {
		prlog(PR_TRACE, "FSPCON: Got associate response, status"
		      " 0x%02x\n", cmd_sub_mod & 0xff);
		return true;
	}
	if ((cmd_sub_mod >> 8) == 0xe08b) {
		prlog(PR_TRACE, "Got unassociate response, status 0x%02x\n",
		      cmd_sub_mod & 0xff);
		return true;
	}
	switch(cmd_sub_mod) {
	case FSP_CMD_OPEN_VSERIAL:
		fsp_open_vserial(msg);
		return true;
	case FSP_CMD_CLOSE_VSERIAL:
		fsp_close_vserial(msg);
		return true;
	case FSP_CMD_HMC_INTF_QUERY:
		prlog(PR_DEBUG, "FSPCON: Got HMC interface query\n");
		got_intf_query = true;
		resp = fsp_mkmsg(FSP_RSP_HMC_INTF_QUERY, 1,
				msg->data.words[0] & 0x00ffffff);
		if (!resp) {
			prerror("FSPCON: Failed to allocate hmc intf response\n");
			return true;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("FSPCON: Failed to queue hmc intf response\n");
		}
		return true;
	}
	return false;
}

static bool fsp_con_msg_vt(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u16 sess_id = msg->data.words[1] & 0xffff;

	if (cmd_sub_mod == FSP_CMD_VSERIAL_IN && sess_id < MAX_SERIAL) {
		struct fsp_serial *fs = &fsp_serials[sess_id];

		if (!fs->open)
			return true;

		/* FSP is signaling some incoming data. We take the console
		 * lock to avoid racing with a simultaneous read, though we
		 * might want to consider to simplify all that locking into
		 * one single lock that covers the console and the pending
		 * events.
		 */
		lock(&fsp_con_lock);
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
		unlock(&fsp_con_lock);
	}
	return true;
}

static bool fsp_con_msg_rr(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	assert(msg == NULL);

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		fsp_close_consoles();
		return true;
	case FSP_RELOAD_COMPLETE:
		fsp_console_reinit();
		return true;
	}
	return false;
}

static struct fsp_client fsp_con_client_hmc = {
	.message = fsp_con_msg_hmc,
};

static struct fsp_client fsp_con_client_vt = {
	.message = fsp_con_msg_vt,
};

static struct fsp_client fsp_con_client_rr = {
	.message = fsp_con_msg_rr,
};

static void fsp_serial_add(int index, u16 rsrc_id, const char *loc_code,
			   bool log_port)
{
	struct fsp_serial *ser;
	struct fsp_msg *msg;

	lock(&fsp_con_lock);
	ser = &fsp_serials[index];

	if (ser->available) {
		unlock(&fsp_con_lock);
		return;
	}

	ser->rsrc_id = rsrc_id;
	memset(ser->loc_code, 0x00, LOC_CODE_SIZE);
	strncpy(ser->loc_code, loc_code, LOC_CODE_SIZE - 1);
	ser->available = true;
	ser->log_port = log_port;
	unlock(&fsp_con_lock);

	/* DVS doesn't have that */
	if (rsrc_id != 0xffff) {
		msg = fsp_mkmsg(FSP_CMD_ASSOC_SERIAL, 2,
				(rsrc_id << 16) | 1, index);
		if (!msg) {
			prerror("FSPCON: Assoc serial alloc failed\n");
			return;
		}
		if (fsp_queue_msg(msg, fsp_freemsg)) {
			fsp_freemsg(msg);
			prerror("FSPCON: Assoc serial queue failed\n");
			return;
		}
	}
}

void fsp_console_preinit(void)
{
	int i;
	void *base;

	if (!fsp_present())
		return;

	ser_buffer = memalign(TCE_PSIZE, SER_BUFFER_SIZE * MAX_SERIAL);

	/* Initialize out data structure pointers & TCE maps */
	base = ser_buffer;
	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *ser = &fsp_serials[i];

		ser->in_buf = base;
		ser->out_buf = base + SER_BUFFER_SIZE/2;
		base += SER_BUFFER_SIZE;
	}
	fsp_tce_map(PSI_DMA_SER0_BASE, ser_buffer,
		    4 * PSI_DMA_SER0_SIZE);

	/* Register for class E0 and E1 */
	fsp_register_client(&fsp_con_client_hmc, FSP_MCLASS_HMC_INTFMSG);
	fsp_register_client(&fsp_con_client_vt, FSP_MCLASS_HMC_VT);
	fsp_register_client(&fsp_con_client_rr, FSP_MCLASS_RR_EVENT);

	/* Add DVS ports. We currently have session 0 and 3, 0 is for
	 * OS use. 3 is our debug port. We need to add those before
	 * we complete the OPL or we'll potentially miss the
	 * console setup on Firebird blades.
	 */
	fsp_serial_add(0, 0xffff, "DVS_OS", false);
	op_display(OP_LOG, OP_MOD_FSPCON, 0x0001);
	fsp_serial_add(3, 0xffff, "DVS_FW", true);
	op_display(OP_LOG, OP_MOD_FSPCON, 0x0002);

}

static int64_t fsp_console_write(int64_t term_number, int64_t *length,
				 const uint8_t *buffer)
{
	struct fsp_serial *fs;
	size_t written, requested;

	if (term_number < 0 || term_number >= MAX_SERIAL)
		return OPAL_PARAMETER;
	fs = &fsp_serials[term_number];
	if (!fs->available || fs->log_port)
		return OPAL_PARAMETER;
	lock(&fsp_con_lock);
	if (!fs->open) {
		unlock(&fsp_con_lock);
		return OPAL_CLOSED;
	}
	/* Clamp to a reasonable size */
	requested = *length;
	if (requested > 0x1000)
		requested = 0x1000;
	written = fsp_write_vserial(fs, buffer, requested);

#ifdef OPAL_DEBUG_CONSOLE_IO
	prlog(PR_TRACE, "OPAL: console write req=%ld written=%ld"
	      " ni=%d no=%d\n",
	      requested, written, fs->out_buf->next_in, fs->out_buf->next_out);
	prlog(PR_TRACE, "      %02x %02x %02x %02x "
	      "%02x \'%c\' %02x \'%c\' %02x \'%c\'.%02x \'%c\'..\n",
	      buffer[0], buffer[1], buffer[2], buffer[3],
	      buffer[4], buffer[4], buffer[5], buffer[5],
	      buffer[6], buffer[6], buffer[7], buffer[7]);
#endif /* OPAL_DEBUG_CONSOLE_IO */

	*length = written;
	unlock(&fsp_con_lock);

	return written ? OPAL_SUCCESS : OPAL_BUSY_EVENT;
}

static int64_t fsp_console_write_buffer_space(int64_t term_number,
					      int64_t *length)
{
	struct fsp_serial *fs;
	struct fsp_serbuf_hdr *sb;

	if (term_number < 0 || term_number >= MAX_SERIAL)
		return OPAL_PARAMETER;
	fs = &fsp_serials[term_number];
	if (!fs->available || fs->log_port)
		return OPAL_PARAMETER;
	lock(&fsp_con_lock);
	if (!fs->open) {
		unlock(&fsp_con_lock);
		return OPAL_CLOSED;
	}
	sb = fs->out_buf;
	*length = (sb->next_out + SER_BUF_DATA_SIZE - sb->next_in - 1)
		% SER_BUF_DATA_SIZE;
	unlock(&fsp_con_lock);

	return OPAL_SUCCESS;
}

static int64_t fsp_console_read(int64_t term_number, int64_t *length,
				uint8_t *buffer __unused)
{
	struct fsp_serial *fs;
	struct fsp_serbuf_hdr *sb;
	bool pending = false;
	uint32_t old_nin, n, i, chunk, req = *length;

	if (term_number < 0 || term_number >= MAX_SERIAL)
		return OPAL_PARAMETER;
	fs = &fsp_serials[term_number];
	if (!fs->available || fs->log_port)
		return OPAL_PARAMETER;
	lock(&fsp_con_lock);
	if (!fs->open) {
		unlock(&fsp_con_lock);
		return OPAL_CLOSED;
	}
	if (fs->waiting)
		fs->waiting = 0;
	sb = fs->in_buf;
	old_nin = sb->next_in;
	lwsync();
	n = (old_nin + SER_BUF_DATA_SIZE - sb->next_out)
		% SER_BUF_DATA_SIZE;
	if (n > req) {
		pending = true;
		n = req;
	}
	*length = n;

	chunk = SER_BUF_DATA_SIZE - sb->next_out;
	if (chunk > n)
		chunk = n;
	memcpy(buffer, &sb->data[sb->next_out], chunk);
	if (chunk < n)
		memcpy(buffer + chunk, &sb->data[0], n - chunk);
	sb->next_out = (sb->next_out + n) % SER_BUF_DATA_SIZE;

#ifdef OPAL_DEBUG_CONSOLE_IO
	prlog(PR_TRACE, "OPAL: console read req=%d read=%d ni=%d no=%d\n",
	      req, n, sb->next_in, sb->next_out);
	prlog(PR_TRACE, "      %02x %02x %02x %02x %02x %02x %02x %02x ...\n",
	       buffer[0], buffer[1], buffer[2], buffer[3],
	       buffer[4], buffer[5], buffer[6], buffer[7]);
#endif /* OPAL_DEBUG_CONSOLE_IO */

	/* Might clear the input pending flag */
	for (i = 0; i < MAX_SERIAL && !pending; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		struct fsp_serbuf_hdr *sb = fs->in_buf;

		if (fs->log_port || !fs->open)
			continue;
		if (sb->next_out != sb->next_in) {
			/*
			 * HACK: Some kernels (4.1+) may fail to properly
			 * register hvc1 and will never read it. This can lead
			 * to RCU stalls, so if we notice this console is not
			 * being read, do not set OPAL_EVENT_CONSOLE_INPUT even
			 * if it has data
			 */
			if (fs->waiting < 5) {
				pending = true;
				fs->waiting++;
			}
		}
	}
	if (!pending)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);

	unlock(&fsp_con_lock);

	return OPAL_SUCCESS;
}

void fsp_console_poll(void *data __unused)
{
#ifdef OPAL_DEBUG_CONSOLE_POLL
       	static int debug;
#endif

	/*
	 * We don't get messages for out buffer being consumed, so we
	 * need to poll. We also defer sending of poke messages from
	 * the sapphire console to avoid a locking nightmare with
	 * beging called from printf() deep into an existing lock nest
	 * stack.
	 */
	if (fsp_con_full ||
	    (opal_pending_events & OPAL_EVENT_CONSOLE_OUTPUT)) {
		unsigned int i;
		bool pending = false;

		/* We take the console lock. This is somewhat inefficient
		 * but it guarantees we aren't racing with a write, and
		 * thus clearing an event improperly
		 */
		lock(&fsp_con_lock);
		for (i = 0; i < MAX_SERIAL && !pending; i++) {
			struct fsp_serial *fs = &fsp_serials[i];
			struct fsp_serbuf_hdr *sb = fs->out_buf;

			if (!fs->open)
				continue;
			if (sb->next_out == sb->next_in)
				continue;
			if (fs->log_port)
				__flush_console(true);
			else {
#ifdef OPAL_DEBUG_CONSOLE_POLL
				if (debug < 5) {
					prlog(PR_DEBUG,"OPAL: %d still pending"
					      " ni=%d no=%d\n",
					      i, sb->next_in, sb->next_out);
					debug++;
				}
#endif /* OPAL_DEBUG_CONSOLE_POLL */
				pending = true;
			}
		}
		if (!pending) {
			opal_update_pending_evt(OPAL_EVENT_CONSOLE_OUTPUT, 0);
#ifdef OPAL_DEBUG_CONSOLE_POLL
			debug = 0;
#endif
		}
		unlock(&fsp_con_lock);
	}
}

void fsp_console_init(void)
{
	struct dt_node *serials, *ser;
	int i;

	if (!fsp_present())
		return;

	opal_register(OPAL_CONSOLE_READ, fsp_console_read, 3);
	opal_register(OPAL_CONSOLE_WRITE_BUFFER_SPACE,
		      fsp_console_write_buffer_space, 2);
	opal_register(OPAL_CONSOLE_WRITE, fsp_console_write, 3);

	/* Wait until we got the intf query before moving on */
	while (!got_intf_query)
		opal_run_pollers();

	op_display(OP_LOG, OP_MOD_FSPCON, 0x0000);

	/* Register poller */
	opal_add_poller(fsp_console_poll, NULL);

	/* Parse serial port data */
	serials = dt_find_by_path(dt_root, "ipl-params/fsp-serial");
	if (!serials) {
		prerror("FSPCON: No FSP serial ports in device-tree\n");
		return;
	}

	i = 1;
	dt_for_each_child(serials, ser) {
		u32 rsrc_id = dt_prop_get_u32(ser, "reg");
		const void *lc = dt_prop_get(ser, "ibm,loc-code");

		prlog(PR_NOTICE, "FSPCON: Serial %d rsrc: %04x loc: %s\n",
		      i, rsrc_id, (const char *)lc);
		fsp_serial_add(i++, rsrc_id, lc, false);
		op_display(OP_LOG, OP_MOD_FSPCON, 0x0010 + i);
	}

	op_display(OP_LOG, OP_MOD_FSPCON, 0x0005);
}

static void flush_all_input(void)
{
	unsigned int i;

	lock(&fsp_con_lock);
 	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		struct fsp_serbuf_hdr *sb = fs->in_buf;

		if (fs->log_port)
			continue;

		sb->next_out = sb->next_in;
	}
	unlock(&fsp_con_lock);
}
		
static bool send_all_hvsi_close(void)
{
	unsigned int i;
	bool has_hvsi = false;
	static const uint8_t close_packet[] = { 0xfe, 6, 0, 1, 0, 3 };

 	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		struct fsp_serbuf_hdr *sb = fs->out_buf;
		unsigned int space, timeout = 10;

		if (fs->log_port)
			continue;
		if (fs->rsrc_id == 0xffff)
			continue;
		has_hvsi = true;

		/* Do we have room ? Wait a bit if not */
		while(timeout--) {
			space = (sb->next_out + SER_BUF_DATA_SIZE -
				 sb->next_in - 1) % SER_BUF_DATA_SIZE;
			if (space >= 6)
				break;
			time_wait_ms(500);
		}
		lock(&fsp_con_lock);
		fsp_write_vserial(fs, close_packet, 6);
		unlock(&fsp_con_lock);
	}

	return has_hvsi;
}

static void reopen_all_hvsi(void)
{
	unsigned int i;

 	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		if (fs->rsrc_id == 0xffff)
			continue;
		prlog(PR_NOTICE, "FSP: Deassociating HVSI console %d\n", i);
		fsp_sync_msg(fsp_mkmsg(FSP_CMD_UNASSOC_SERIAL, 1,
				       (i << 16) | 1), true);
	}
 	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		if (fs->rsrc_id == 0xffff)
			continue;
		prlog(PR_NOTICE, "FSP: Reassociating HVSI console %d\n", i);
		fsp_sync_msg(fsp_mkmsg(FSP_CMD_ASSOC_SERIAL, 2,
				       (fs->rsrc_id << 16) | 1, i), true);
	}
}

void fsp_console_reset(void)
{
	prlog(PR_NOTICE, "FSP: Console reset !\n");

	/* This is called on a fast-reset. To work around issues with HVSI
	 * initial negotiation, before we reboot the kernel, we flush all
	 * input and send an HVSI close packet.
	 */
	flush_all_input();

	/* Returns false if there is no HVSI console */
	if (!send_all_hvsi_close())
		return;

	time_wait_ms(500);
	
	flush_all_input();

	reopen_all_hvsi();

}

void fsp_console_add_nodes(void)
{
	unsigned int i;
	struct dt_node *consoles;

	consoles = dt_new(opal_node, "consoles");
	dt_add_property_cells(consoles, "#address-cells", 1);
	dt_add_property_cells(consoles, "#size-cells", 0);
	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *fs = &fsp_serials[i];
		struct dt_node *fs_node;
		char name[32];

		if (fs->log_port || !fs->available)
			continue;

		snprintf(name, sizeof(name), "serial@%d", i);
		fs_node = dt_new(consoles, name);
		if (fs->rsrc_id == 0xffff)
			dt_add_property_string(fs_node, "compatible",
					       "ibm,opal-console-raw");
		else
			dt_add_property_string(fs_node, "compatible",
					       "ibm,opal-console-hvsi");
		dt_add_property_cells(fs_node,
				     "#write-buffer-size", SER_BUF_DATA_SIZE);
		dt_add_property_cells(fs_node, "reg", i);
		dt_add_property_string(fs_node, "device_type", "serial");
	}
}

void fsp_console_select_stdout(void)
{
	bool use_serial = false;

	if (!fsp_present())
		return;

	/* On P8, we have a sysparam ! yay ! */
	if (proc_gen >= proc_gen_p8) {
		int rc;
		u8 param;

		rc = fsp_get_sys_param(SYS_PARAM_CONSOLE_SELECT,
				       &param, 1, NULL, NULL);
		if (rc != 1)
			prerror("FSPCON: Failed to get console"
				" sysparam rc %d\n", rc);
		else {
			switch(param) {
			case 0:
				use_serial = false;
				break;
			case 1:
				use_serial = true;
				break;
			default:
				prerror("FSPCON: Unknown console"
					" sysparam %d\n", param);
			}
		}
	} else {
		struct dt_node *iplp;
		u32 ipl_mode = 0;

		/*
		 * We hijack the "os-ipl-mode" setting in iplparams to select
		 * out output console. This is the "i5/OS partition mode boot"
		 * setting in ASMI converted to an integer: 0=A, 1=B.
		 */
		iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
		if (iplp) {
			ipl_mode = dt_prop_get_u32_def(iplp, "os-ipl-mode", 0);
			use_serial = ipl_mode > 0;

			/*
			 * Now, if ipl_mode is > 0, we use serial port A else
			 * we use IPMI/SOL/DVS
			 */
		}
	}
	if (fsp_serials[1].open && use_serial) {
		dt_add_property_string(dt_chosen, "linux,stdout-path",
				       "/ibm,opal/consoles/serial@1");
		prlog(PR_NOTICE, "FSPCON: default console set to serial A\n");
	} else {
		dt_add_property_string(dt_chosen, "linux,stdout-path",
				       "/ibm,opal/consoles/serial@0");
		prlog(PR_NOTICE, "FSPCON: default console set to SOL/DVS\n");
	}
}

