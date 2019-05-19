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

#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include "../../ccan/endian/endian.h"
#include "../../ccan/short_types/short_types.h"
#include <trace_types.h>

/* Handles trace from debugfs (one record at a time) or file */ 
static bool get_trace(int fd, union trace *t, int *len)
{
	void *dest = t;
	int r;

	/* Move down any extra we read last time. */
	if (*len >= sizeof(t->hdr) && *len >= t->hdr.len_div_8 * 8) {
		u8 rlen = t->hdr.len_div_8 * 8;
		memmove(dest, dest + rlen, *len - rlen);
		*len -= rlen;
	}

	r = read(fd, dest + *len, sizeof(*t) - *len);
	if (r < 0)
		return false;

	*len += r;
	/* We should have a complete record. */
	return *len >= sizeof(t->hdr) && *len >= t->hdr.len_div_8 * 8;
}

static void display_header(const struct trace_hdr *h)
{
	static u64 prev_ts;
	u64 ts = be64_to_cpu(h->timestamp);

	printf("%16lx (+%8lx) [%03x] : ",
	       ts, prev_ts ? (ts - prev_ts) : 0, be16_to_cpu(h->cpu));
	prev_ts = ts;
}

static void dump_fsp_event(struct trace_fsp_event *t)
{
	printf("FSP_EVT [st=%d] ", be16_to_cpu(t->fsp_state));

	switch(be16_to_cpu(t->event)) {
	case TRACE_FSP_EVT_LINK_DOWN:
		printf("LINK DOWN");
		break;
	case TRACE_FSP_EVT_DISR_CHG:
		printf("DISR CHANGE (0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_SOFT_RR:
		printf("SOFT R&R (DISR=0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_RR_COMPL:
		printf("R&R COMPLETE");
		break;
	case TRACE_FSP_EVT_HDES_CHG:
		printf("HDES CHANGE (0x%08x)", be32_to_cpu(t->data[0]));
		break;
	case TRACE_FSP_EVT_POLL_IRQ:
		printf("%s HDIR=%08x CTL=%08x PSI_IRQ=%d",
		       t->data[0] ? "IRQ " : "POLL", be32_to_cpu(t->data[1]),
		       be32_to_cpu(t->data[2]), be32_to_cpu(t->data[3]));
		break;
	default:
		printf("Unknown %d (d: %08x %08x %08x %08x)",
		       be16_to_cpu(t->event), be32_to_cpu(t->data[0]),
		       be32_to_cpu(t->data[1]), be32_to_cpu(t->data[2]),
		       be32_to_cpu(t->data[3]));
	}
	printf("\n");
}

static void dump_opal_call(struct trace_opal *t)
{
	unsigned int i, n;

	printf("OPAL CALL %"PRIu64, be64_to_cpu(t->token));
	printf(" LR=0x%016"PRIx64" SP=0x%016"PRIx64,
	       be64_to_cpu(t->lr), be64_to_cpu(t->sp));
	n = (t->hdr.len_div_8 * 8 - offsetof(union trace, opal.r3_to_11))
		/ sizeof(u64);
	for (i = 0; i < n; i++)
		printf(" R%u=0x%016"PRIx64,
		       i+3, be64_to_cpu(t->r3_to_11[i]));
	printf("\n");
}

static void dump_fsp_msg(struct trace_fsp_msg *t)
{
	unsigned int i;

	printf("FSP_MSG: CMD %u SEQ %u MOD %u SUB %u DLEN %u %s [",
	       be32_to_cpu(t->word0) & 0xFFFF,
	       be32_to_cpu(t->word0) >> 16,
	       be32_to_cpu(t->word1) >> 8,
	       be32_to_cpu(t->word1) & 0xFF,
	       t->dlen,
	       t->dir == TRACE_FSP_MSG_IN ? "IN" :
	       (t->dir == TRACE_FSP_MSG_OUT ? "OUT" : "UNKNOWN"));

	for (i = 0; i < t->dlen; i++) 
		printf("%s%02x", i ? " " : "", t->data[i]);
	printf("]\n");
}

static void dump_uart(struct trace_uart *t)
{
	switch(t->ctx) {
	case TRACE_UART_CTX_IRQ:
		printf(": IRQ  IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	case TRACE_UART_CTX_POLL:
		printf(": POLL IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	case TRACE_UART_CTX_READ:
		printf(": READ IRQEN=%d IN_CNT=%d READ=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count), t->cnt);
		break;
	default:
		printf(": ???? IRQEN=%d IN_CNT=%d\n",
		       !t->irq_state, be16_to_cpu(t->in_count));
		break;
	}
}

int main(int argc, char *argv[])
{
	int fd, len = 0;
	union trace t;
	const char *in = "/sys/kernel/debug/powerpc/opal-trace";

	if (argc > 2)
		errx(1, "Usage: dump_trace [file]");

	if (argv[1])
		in = argv[1];
	fd = open(in, O_RDONLY);
	if (fd < 0)
		err(1, "Opening %s", in);

	while (get_trace(fd, &t, &len)) {
		display_header(&t.hdr);
		switch (t.hdr.type) {
		case TRACE_REPEAT:
			printf("REPEATS: %u times\n",
			       be32_to_cpu(t.repeat.num));
			break;
		case TRACE_OVERFLOW:
			printf("**OVERFLOW**: %"PRIu64" bytes missed\n",
			       be64_to_cpu(t.overflow.bytes_missed));
			break;
		case TRACE_OPAL:
			dump_opal_call(&t.opal);
			break;
		case TRACE_FSP_MSG:
			dump_fsp_msg(&t.fsp_msg);
			break;
		case TRACE_FSP_EVENT:
			dump_fsp_event(&t.fsp_evt);
			break;
		case TRACE_UART:
			dump_uart(&t.uart);
			break;
		default:
			printf("UNKNOWN(%u) CPU %u length %u\n",
			       t.hdr.type, be16_to_cpu(t.hdr.cpu),
			       t.hdr.len_div_8 * 8);
		}
	}
	return 0;
}
