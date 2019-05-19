
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

#include <timebase.h>
#include <opal.h>
#include <cpu.h>
#include <chip.h>

unsigned long tb_hz = 512000000;

static void time_wait_poll(unsigned long duration)
{
	unsigned long remaining = duration;
	unsigned long end = mftb() + duration;
	unsigned long period = msecs_to_tb(5);

	if (this_cpu()->tb_invalid) {
		cpu_relax();
		return;
	}

	while (tb_compare(mftb(), end) != TB_AAFTERB) {
		/* Call pollers periodically but not continually to avoid
		 * bouncing cachelines due to lock contention. */
		if (remaining >= period) {
			opal_run_pollers();
			time_wait_nopoll(period);
			remaining -= period;
		}

		cpu_relax();
	}
}

void time_wait(unsigned long duration)
{
	struct cpu_thread *c = this_cpu();

	if (this_cpu()->lock_depth) {
		time_wait_nopoll(duration);
		return;
	}

	if (c != boot_cpu)
		time_wait_nopoll(duration);
	else
		time_wait_poll(duration);
}

void time_wait_nopoll(unsigned long duration)
{
	unsigned long end = mftb() + duration;

	if (this_cpu()->tb_invalid) {
		cpu_relax();
		return;
	}

	while(tb_compare(mftb(), end) != TB_AAFTERB)
		cpu_relax();
}

void time_wait_ms(unsigned long ms)
{
	time_wait(msecs_to_tb(ms));
}

void time_wait_ms_nopoll(unsigned long ms)
{
	time_wait_nopoll(msecs_to_tb(ms));
}

void time_wait_us(unsigned long us)
{
	time_wait(usecs_to_tb(us));
}

void time_wait_us_nopoll(unsigned long us)
{
	time_wait_nopoll(usecs_to_tb(us));
}

unsigned long timespec_to_tb(const struct timespec *ts)
{
	unsigned long ns;

	/* First convert to ns */
	ns = ts->tv_sec * 1000000000ul;
	ns += ts->tv_nsec;

	/*
	 * This is a very rough approximation, it works provided
	 * we never try to pass too long delays here and the TB
	 * frequency isn't significantly lower than 512Mhz.
	 *
	 * We could improve the precision by shifting less bits
	 * at the expense of capacity or do 128 bit math which
	 * I'm not eager to do :-)
	 */
	if (chip_quirk(QUIRK_SLOW_SIM))
		return (ns * (tb_hz >> 16)) / (1000000000ul >> 16);
	else
		return (ns * (tb_hz >> 24)) / (1000000000ul >> 24);
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	time_wait(timespec_to_tb(req));

	if (rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}
	return 0;
}

int nanosleep_nopoll(const struct timespec *req, struct timespec *rem)
{
	time_wait_nopoll(timespec_to_tb(req));

	if (rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}
	return 0;
}
