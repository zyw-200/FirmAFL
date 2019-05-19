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
#include <lock.h>
#include <fsp.h>
#include <platform.h>
#include <processor.h>
#include <cpu.h>
#include <stack.h>

extern unsigned long __stack_chk_guard;
unsigned long __stack_chk_guard = 0xdeadf00dbaad300dULL;

void __noreturn assert_fail(const char *msg)
{
	/**
	 * @fwts-label FailedAssert
	 * @fwts-advice OPAL hit an assert(). During normal usage (even
	 * testing) we should never hit an assert. There are other code
	 * paths for controlled shutdown/panic in the event of catastrophic
	 * errors.
	 */
	prlog(PR_EMERG, "Assert fail: %s\n", msg);
	_abort(msg);
}

void __noreturn _abort(const char *msg)
{
	static bool in_abort = false;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	prlog(PR_EMERG, "Aborting!\n");
	backtrace();

	if (platform.terminate)
		platform.terminate(msg);

	for (;;) ;
}

char __attrconst tohex(uint8_t nibble)
{
	static const char __tohex[] = {'0','1','2','3','4','5','6','7','8','9',
				       'A','B','C','D','E','F'};
	if (nibble > 0xf)
		return '?';
	return __tohex[nibble];
}

unsigned long get_symbol(unsigned long addr, char **sym, char **sym_end)
{
	unsigned long prev = 0, next;
	char *psym = NULL, *p = __sym_map_start;

	*sym = *sym_end = NULL;
	while(p < __sym_map_end) {
		next = strtoul(p, &p, 16) | SKIBOOT_BASE;
		if (next > addr && prev <= addr) {
			p = psym + 3;;
			if (p >= __sym_map_end)
				return 0;
			*sym = p;
			while(p < __sym_map_end && *p != 10)
				p++;
			*sym_end = p;
			return prev;
		}
		prev = next;
		psym = p;
		while(p < __sym_map_end && *p != 10)
			p++;
		p++;
	}
	return 0;
}

