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
	hello_kernel.S!
	---------------

	Because skiboot has its own stack, we don't even need that!
	All we need to do is make an OPAL call to write to the console.

*/

	. = 0x0
	.globl _start
_start:
/*
 * Save some values passed in from skiboot into registers that are
 * non-volatile over OPAL calls.
 *   r8 is the OPAL base
 *   r9 is the OPAL entry point point
 */
	mr	%r13, %r8
	mr	%r14, %r9

	bl	here
here:	mflr	%r8 /* work out where we are running */

	li	%r0, 1 /* OPAL_CONSOLE_WRITE */
	li	%r3, 0 /* terminal 0 */
	addi	%r4, %r8, len - here /* ptr to length of string */
	addi	%r5, %r8, str - here /* ptr to string start */
	mr	%r2, %r13
	mtctr	%r14
	bctrl

	li	%r0, 5 /* OPAL_CEC_POWER_DOWN */
	li	%r3, 0 /* normal shutdown */
	mr	%r2, %r13
	mtctr	%r14
	bctrl

	/* We shouldn't get here but if we do, just wait here */
	b	.

len:
	.long 0x00
	.long (strend - str)
str:
	.string "Hello World!\n"
strend:
