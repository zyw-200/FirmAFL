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

#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <stack.h>

	.section ".text","ax"
	.balign	0x10

	/* void set_hid0(unsigned long hid0) */
.global set_hid0
set_hid0:
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	blr

.global __trigger_attn
__trigger_attn:
	sync
	isync
	attn
	blr

#ifdef STACK_CHECK_ENABLED
.global _mcount
_mcount:
	mr	%r3,%r1
	mflr	%r4
	b	__mcount_stack_check
#endif

.global mambo_read
mambo_read:
#define SIM_READ_CONSOLE_CODE 60
	li	%r3,SIM_READ_CONSOLE_CODE
	.long	0x000eaeb0
	extsw	%r3,%r3
	blr

.global mambo_write
mambo_write:
#define SIM_WRITE_CONSOLE_CODE 0
	li	%r6,0
	mr	%r5,%r4
	mr	%r4,%r3
	li	%r3,SIM_WRITE_CONSOLE_CODE
	.long	0x000eaeb0
	blr

.global mambo_sim_exit
mambo_sim_exit:
	li	%r3, 31	/* aka. SimExitCode */
	.long	0x000eaeb0
	b	.

.global mambo_get_time
mambo_get_time:
#define SIM_GET_TIME_CODE 70
	li	%r3,SIM_GET_TIME_CODE
	.long	0x000eaeb0
	blr

