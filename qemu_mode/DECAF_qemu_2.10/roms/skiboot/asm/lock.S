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

	.section ".text","ax"
	.balign	0x10

	/* bool try_lock(struct lock *lock) */
.global __try_lock
__try_lock:
	ld	%r0,0(%r3)
	andi.	%r10,%r0,1
	bne	2f
	lwz	%r9,CPUTHREAD_PIR(%r13)
1:	ldarx	%r0,0,%r3
	andi.	%r10,%r0,1
	bne-	2f
	ori	%r0,%r0,1
	rldimi	%r0,%r9,32,0
	stdcx.	%r0,0,%r3
	bne	1b
	sync
	li	%r3,-1
	blr
2:	li	%r3,0
	blr

