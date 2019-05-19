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
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <interrupts.h>
#include <processor.h>
#include <errorlog.h>
#include <trace.h>
#include <timebase.h>
#include <cpu.h>
#include <chip.h>
#include <io.h>

DEFINE_LOG_ENTRY(OPAL_RC_UART_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_UART,
		 OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

/* UART reg defs */
#define REG_RBR		0
#define REG_THR		0
#define REG_DLL		0
#define REG_IER		1
#define REG_DLM		1
#define REG_FCR		2
#define REG_IIR		2
#define REG_LCR		3
#define REG_MCR		4
#define REG_LSR		5
#define REG_MSR		6
#define REG_SCR		7

#define LSR_DR		0x01  /* Data ready */
#define LSR_OE		0x02  /* Overrun */
#define LSR_PE		0x04  /* Parity error */
#define LSR_FE		0x08  /* Framing error */
#define LSR_BI		0x10  /* Break */
#define LSR_THRE	0x20  /* Xmit holding register empty */
#define LSR_TEMT	0x40  /* Xmitter empty */
#define LSR_ERR		0x80  /* Error */

#define LCR_DLAB 	0x80  /* DLL access */

#define IER_RX		0x01
#define IER_THRE	0x02
#define IER_ALL		0x0f

static struct lock uart_lock = LOCK_UNLOCKED;
static struct dt_node *uart_node;
static uint32_t uart_base;
static bool has_irq = false, irq_ok, rx_full, tx_full;
static uint8_t tx_room;
static uint8_t cached_ier;
static void *mmio_uart_base;

static void uart_trace(u8 ctx, u8 cnt, u8 irq_state, u8 in_count)
{
	union trace t;

	t.uart.ctx = ctx;
	t.uart.cnt = cnt;
	t.uart.irq_state = irq_state;
	t.uart.in_count = cpu_to_be16(in_count);
	trace_add(&t, TRACE_UART, sizeof(struct trace_uart));
}

static inline uint8_t uart_read(unsigned int reg)
{
	if (mmio_uart_base)
		return in_8(mmio_uart_base + reg);
	else
		return lpc_inb(uart_base + reg);
}

static inline void uart_write(unsigned int reg, uint8_t val)
{
	if (mmio_uart_base)
		out_8(mmio_uart_base + reg, val);
	else
		lpc_outb(val, uart_base + reg);
}

static void uart_check_tx_room(void)
{
	if (uart_read(REG_LSR) & LSR_THRE) {
		/* FIFO is 16 entries */
		tx_room = 16;
		tx_full = false;
	}
}

static void uart_wait_tx_room(void)
{
	while(!tx_room) {
		uart_check_tx_room();
		if (!tx_room)
			cpu_relax();
	}
}

static void uart_update_ier(void)
{
	uint8_t ier = 0;

	if (!has_irq)
		return;

	/* If we have never got an interrupt, enable them all,
	 * the first interrupt received will tell us if interrupts
	 * are functional (some boards are missing an EC or FPGA
	 * programming causing LPC interrupts not to work).
	 */
	if (!irq_ok)
		ier = IER_ALL;
	if (!rx_full)
		ier |= IER_RX;
	if (tx_full)
		ier |= IER_THRE;
	if (ier != cached_ier) {
		uart_write(REG_IER, ier);
		cached_ier = ier;
	}
}

bool uart_enabled(void)
{
	return mmio_uart_base || uart_base;
}

/*
 * Internal console driver (output only)
 */
static size_t uart_con_write(const char *buf, size_t len)
{
	size_t written = 0;

	/* If LPC bus is bad, we just swallow data */
	if (!lpc_ok() && !mmio_uart_base)
		return written;

	lock(&uart_lock);
	while(written < len) {
		if (tx_room == 0) {
			uart_wait_tx_room();
			if (tx_room == 0)
				goto bail;
		} else {
			uart_write(REG_THR, buf[written++]);
			tx_room--;
		}
	}
 bail:
	unlock(&uart_lock);
	return written;
}

static int64_t uart_con_flush(void);

static struct con_ops uart_con_driver = {
	.write = uart_con_write,
	.flush = uart_con_flush
};

/*
 * OPAL console driver
 */

/*
 * We implement a simple buffer to buffer input data as some bugs in
 * Linux make it fail to read fast enough after we get an interrupt.
 *
 * We use it on non-interrupt operations as well while at it because
 * it doesn't cost us much and might help in a few cases where Linux
 * is calling opal_poll_events() but not actually reading.
 *
 * Most of the time I expect we'll flush it completely to Linux into
 * it's tty flip buffers so I don't bother with a ring buffer.
 */
#define IN_BUF_SIZE	0x1000
static uint8_t	*in_buf;
static uint32_t	in_count;

/*
 * We implement a ring buffer for output data as well to speed things
 * up a bit. This allows us to have interrupt driven sends. This is only
 * for the output data coming from the OPAL API, not the internal one
 * which is already bufferred.
 */
#define OUT_BUF_SIZE	0x1000
static uint8_t *out_buf;
static uint32_t out_buf_prod;
static uint32_t out_buf_cons;

/* Asynchronous flush */
static int64_t uart_con_flush(void)
{
	bool tx_was_full = tx_full;
	uint32_t out_buf_cons_initial = out_buf_cons;

	while(out_buf_prod != out_buf_cons) {
		if (tx_room == 0) {
			/*
			 * If the interrupt is not functional,
			 * we force a full synchronous flush,
			 * otherwise the Linux console isn't
			 * usable (too slow).
			 */
			if (irq_ok)
				uart_check_tx_room();
			else
				uart_wait_tx_room();
		}
		if (tx_room == 0) {
			tx_full = true;
			break;
		}
		uart_write(REG_THR, out_buf[out_buf_cons++]);
		out_buf_cons %= OUT_BUF_SIZE;
		tx_room--;
	}
	if (tx_full != tx_was_full)
		uart_update_ier();
	if (out_buf_prod != out_buf_cons) {
		/* Return busy if nothing was flushed this call */
		if (out_buf_cons == out_buf_cons_initial)
			return OPAL_BUSY;
		/* Return partial if there's more to flush */
		return OPAL_PARTIAL;
	}

	return OPAL_SUCCESS;
}

static uint32_t uart_tx_buf_space(void)
{
	return OUT_BUF_SIZE - 1 -
		(out_buf_prod + OUT_BUF_SIZE - out_buf_cons) % OUT_BUF_SIZE;
}

static int64_t uart_opal_write(int64_t term_number, int64_t *length,
			       const uint8_t *buffer)
{
	size_t written = 0, len = *length;

	if (term_number != 0)
		return OPAL_PARAMETER;

	lock(&uart_lock);

	/* Copy data to out buffer */
	while (uart_tx_buf_space() && len--) {
		out_buf[out_buf_prod++] = *(buffer++);
		out_buf_prod %= OUT_BUF_SIZE;
		written++;
	}

	/* Flush out buffer again */
	uart_con_flush();

	unlock(&uart_lock);

	*length = written;

	return OPAL_SUCCESS;
}

static int64_t uart_opal_write_buffer_space(int64_t term_number,
					    int64_t *length)
{
	if (term_number != 0)
		return OPAL_PARAMETER;

	lock(&uart_lock);
	*length = uart_tx_buf_space();
	unlock(&uart_lock);

	return OPAL_SUCCESS;
}

/* Must be called with UART lock held */
static void uart_read_to_buffer(void)
{
	/* As long as there is room in the buffer */
	while(in_count < IN_BUF_SIZE) {
		/* Read status register */
		uint8_t lsr = uart_read(REG_LSR);

		/* Nothing to read ... */
		if ((lsr & LSR_DR) == 0)
			break;

		/* Read and add to buffer */
		in_buf[in_count++] = uart_read(REG_RBR);
	}

	/* If the buffer is full disable the interrupt */
	rx_full = (in_count == IN_BUF_SIZE);
	uart_update_ier();
}

static void uart_adjust_opal_event(void)
{
	if (in_count)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
	else
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);
}

/* This is called with the console lock held */
static int64_t uart_opal_read(int64_t term_number, int64_t *length,
			      uint8_t *buffer)
{
	size_t req_count = *length, read_cnt = 0;
	uint8_t lsr = 0;

	if (term_number != 0)
		return OPAL_PARAMETER;
	if (!in_buf)
		return OPAL_INTERNAL_ERROR;

	lock(&uart_lock);

	/* Read from buffer first */
	if (in_count) {
		read_cnt = in_count;
		if (req_count < read_cnt)
			read_cnt = req_count;
		memcpy(buffer, in_buf, read_cnt);
		req_count -= read_cnt;
		if (in_count != read_cnt)
			memmove(in_buf, in_buf + read_cnt, in_count - read_cnt);
		in_count -= read_cnt;
	}

	/*
	 * If there's still room in the user buffer, read from the UART
	 * directly
	 */
	while(req_count) {
		lsr = uart_read(REG_LSR);
		if ((lsr & LSR_DR) == 0)
			break;
		buffer[read_cnt++] = uart_read(REG_RBR);
		req_count--;
	}

	/* Finally, flush whatever's left in the UART into our buffer */
	uart_read_to_buffer();

	uart_trace(TRACE_UART_CTX_READ, read_cnt, tx_full, in_count);

	unlock(&uart_lock);

	/* Adjust the OPAL event */
	uart_adjust_opal_event();

	*length = read_cnt;
	return OPAL_SUCCESS;
}

static void __uart_do_poll(u8 trace_ctx)
{
	if (!in_buf)
		return;

	lock(&uart_lock);
	uart_read_to_buffer();
	uart_con_flush();
	uart_trace(trace_ctx, 0, tx_full, in_count);
	unlock(&uart_lock);

	uart_adjust_opal_event();
}

static void uart_console_poll(void *data __unused)
{
	__uart_do_poll(TRACE_UART_CTX_POLL);
}

static void uart_irq(uint32_t chip_id __unused, uint32_t irq_mask __unused)
{
	if (!irq_ok) {
		prlog(PR_DEBUG, "UART: IRQ functional !\n");
		irq_ok = true;
	}
	__uart_do_poll(TRACE_UART_CTX_IRQ);
}

/*
 * Common setup/inits
 */

void uart_setup_linux_passthrough(void)
{
	char *path;

	dt_add_property_strings(uart_node, "status", "ok");
	path = dt_get_path(uart_node);
	dt_add_property_string(dt_chosen, "linux,stdout-path", path);
	free(path);
	prlog(PR_DEBUG, "UART: Enabled as OS pass-through\n");
}

void uart_setup_opal_console(void)
{
	struct dt_node *con, *consoles;

	/* Create OPAL console node */
	consoles = dt_new(opal_node, "consoles");
	assert(consoles);
	dt_add_property_cells(consoles, "#address-cells", 1);
	dt_add_property_cells(consoles, "#size-cells", 0);

	con = dt_new_addr(consoles, "serial", 0);
	assert(con);
	dt_add_property_string(con, "compatible", "ibm,opal-console-raw");
	dt_add_property_cells(con, "#write-buffer-size", INMEM_CON_OUT_LEN);
	dt_add_property_cells(con, "reg", 0);
	dt_add_property_string(con, "device_type", "serial");

	dt_add_property_string(dt_chosen, "linux,stdout-path",
			       "/ibm,opal/consoles/serial@0");

	/*
	 * We mark the UART as reserved since we don't want the
	 * kernel to start using it with its own 8250 driver
	 */
	dt_add_property_strings(uart_node, "status", "reserved");

	/*
	 * If the interrupt is enabled, turn on RX interrupts (and
	 * only these for now
	 */
	tx_full = rx_full = false;
	uart_update_ier();

	/* Allocate an input buffer */
	in_buf = zalloc(IN_BUF_SIZE);
	out_buf = zalloc(OUT_BUF_SIZE);
	prlog(PR_DEBUG, "UART: Enabled as OS console\n");

	/* Register OPAL APIs */
	opal_register(OPAL_CONSOLE_READ, uart_opal_read, 3);
	opal_register(OPAL_CONSOLE_WRITE_BUFFER_SPACE,
		      uart_opal_write_buffer_space, 2);
	opal_register(OPAL_CONSOLE_WRITE, uart_opal_write, 3);

	opal_add_poller(uart_console_poll, NULL);
}

static bool uart_init_hw(unsigned int speed, unsigned int clock)
{
	unsigned int dll = (clock / 16) / speed;

	/* Clear line control */
	uart_write(REG_LCR, 0x00);

	/* Check if the UART responds */
	uart_write(REG_IER, 0x01);
	if (uart_read(REG_IER) != 0x01)
		goto detect_fail;
	uart_write(REG_IER, 0x00);
	if (uart_read(REG_IER) != 0x00)
		goto detect_fail;

	uart_write(REG_LCR, LCR_DLAB);
	uart_write(REG_DLL, dll & 0xff);
	uart_write(REG_DLM, dll >> 8);
	uart_write(REG_LCR, 0x03); /* 8N1 */
	uart_write(REG_MCR, 0x03); /* RTS/DTR */
	uart_write(REG_FCR, 0x07); /* clear & en. fifos */
	return true;

 detect_fail:
	prerror("UART: Presence detect failed !\n");
	return false;
}

static struct lpc_client uart_lpc_client = {
	.interrupt = uart_irq,
};

void uart_init(void)
{
	const struct dt_property *prop;
	struct dt_node *n;
	char *path __unused;
	uint32_t chip_id;
	const uint32_t *irqp;

	/* UART lock is in the console path and thus must block
	 * printf re-entrancy
	 */
	uart_lock.in_con_path = true;

	/* We support only one */
	uart_node = n = dt_find_compatible_node(dt_root, NULL, "ns16550");
	if (!n)
		return;

	/* Read the interrupts property if any */
	irqp = dt_prop_get_def(n, "interrupts", NULL);

	/* Now check if the UART is on the root bus. This is the case of
	 * directly mapped UARTs in simulation environments
	 */
	if (n->parent == dt_root) {
		printf("UART: Found at root !\n");
		mmio_uart_base = (void *)dt_translate_address(n, 0, NULL);
		if (!mmio_uart_base) {
			printf("UART: Failed to translate address !\n");
			return;
		}

		/* If it has an interrupt properly, we consider this to be
		 * a direct XICS/XIVE interrupt
		 */
		if (irqp)
			has_irq = true;

	} else {
		if (!lpc_present())
			return;

		/* Get IO base */
		prop = dt_find_property(n, "reg");
		if (!prop) {
			log_simple_error(&e_info(OPAL_RC_UART_INIT),
					 "UART: Can't find reg property\n");
			return;
		}
		if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
			log_simple_error(&e_info(OPAL_RC_UART_INIT),
					 "UART: Only supports IO addresses\n");
			return;
		}
		uart_base = dt_property_get_cell(prop, 1);

		if (irqp) {
			uint32_t irq = be32_to_cpu(*irqp);

			chip_id = dt_get_chip_id(uart_node);
			uart_lpc_client.interrupts = LPC_IRQ(irq);
			lpc_register_client(chip_id, &uart_lpc_client);
			prlog(PR_DEBUG, "UART: Using LPC IRQ %d\n", irq);
			has_irq = true;
		}
	}


	if (!uart_init_hw(dt_prop_get_u32(n, "current-speed"),
			  dt_prop_get_u32(n, "clock-frequency"))) {
		prerror("UART: Initialization failed\n");
		dt_add_property_strings(n, "status", "bad");
		return;
	}

	/*
	 * Mark LPC used by the console (will mark the relevant
	 * locks to avoid deadlocks when flushing the console)
	 */
	lpc_used_by_console();

	/* Install console backend for printf() */
	set_console(&uart_con_driver);
}

