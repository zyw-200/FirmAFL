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
#include <device.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <psi.h>

static void qemu_init(void)
{
	/* Setup UART console for use by Linux via OPAL API */
	if (!dummy_console_enabled())
		uart_setup_opal_console();

	/* Setup LPC RTC and use it as time source. Call after
	 * chiptod_init()
	 */
	lpc_rtc_init();
}

static void qemu_dt_fixup_uart(struct dt_node *lpc)
{
	/*
	 * The official OF ISA/LPC binding is a bit odd, it prefixes
	 * the unit address for IO with "i". It uses 2 cells, the first
	 * one indicating IO vs. Memory space (along with bits to
	 * represent aliasing).
	 *
	 * We pickup that binding and add to it "2" as a indication
	 * of FW space.
	 *
	 * TODO: Probe the UART instead if the LPC bus allows for it
	 */
	struct dt_node *uart;
	char namebuf[32];
#define UART_IO_BASE	0x3f8
#define UART_IO_COUNT	8
#define UART_LPC_IRQ	4

	snprintf(namebuf, sizeof(namebuf), "serial@i%x", UART_IO_BASE);
	uart = dt_new(lpc, namebuf);

	dt_add_property_cells(uart, "reg",
			      1, /* IO space */
			      UART_IO_BASE, UART_IO_COUNT);
	dt_add_property_strings(uart, "compatible",
				"ns16550",
				"pnpPNP,501");
	dt_add_property_cells(uart, "clock-frequency", 1843200);
	dt_add_property_cells(uart, "current-speed", 115200);
	dt_add_property_cells(uart, "interrupts", UART_LPC_IRQ);
	dt_add_property_cells(uart, "interrupt-parent", lpc->phandle);

	/*
	 * This is needed by Linux for some obscure reasons,
	 * we'll eventually need to sanitize it but in the meantime
	 * let's make sure it's there
	 */
	dt_add_property_strings(uart, "device_type", "serial");
}

/*
 * This adds the legacy RTC device to the device-tree
 * for Linux to use
 */
static void qemu_dt_fixup_rtc(struct dt_node *lpc)
{
	struct dt_node *rtc;
	char namebuf[32];

	/*
	 * Follows the structure expected by the kernel file
	 * arch/powerpc/sysdev/rtc_cmos_setup.c
	 */
	snprintf(namebuf, sizeof(namebuf), "rtc@i%x", 0x70);
	rtc = dt_new(lpc, namebuf);
	dt_add_property_string(rtc, "compatible", "pnpPNP,b00");
	dt_add_property_cells(rtc, "reg",
			      1, /* IO space */
			      0x70, 2);
}

static void qemu_dt_fixup(void)
{
	struct dt_node *n, *primary_lpc = NULL;

	/* Find the primary LPC bus */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
	}

	if (!primary_lpc)
		return;

	qemu_dt_fixup_rtc(primary_lpc);
	qemu_dt_fixup_uart(primary_lpc);
}

static void qemu_ext_irq_serirq_cpld(unsigned int chip_id)
{
	lpc_all_interrupts(chip_id);
}

static bool qemu_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "qemu,powernv"))
		return false;

	/* Add missing bits of device-tree such as the UART */
	qemu_dt_fixup();

	psi_set_external_irq_policy(EXTERNAL_IRQ_POLICY_SKIBOOT);

	/* Setup UART and use it as console */
	uart_init();

	return true;
}

DECLARE_PLATFORM(qemu) = {
	.name		= "Qemu",
	.probe		= qemu_probe,
	.init		= qemu_init,
	.external_irq   = qemu_ext_irq_serirq_cpld,
};
