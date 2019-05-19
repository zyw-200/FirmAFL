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
#include <processor.h>
#include <cpu.h>
#include <stack.h>
#include <mem_region.h>
#include <unistd.h>

#define STACK_BUF_ENTRIES	60
static struct bt_entry bt_buf[STACK_BUF_ENTRIES];

extern uint32_t _stext, _etext;

/* Dumps backtrace to buffer */
void __nomcount __backtrace(struct bt_entry *entries, unsigned int *count)
{
	unsigned int room = *count;
	unsigned long *fp = __builtin_frame_address(0);
	unsigned long top_adj = top_of_ram;

	/* Assume one stack for early backtraces */
	if (top_of_ram == SKIBOOT_BASE + SKIBOOT_SIZE)
		top_adj = top_of_ram + STACK_SIZE;

	*count = 0;
	while(room) {
		fp = (unsigned long *)fp[0];
		if (!fp || (unsigned long)fp > top_adj)
			break;
		entries->sp = (unsigned long)fp;
		entries->pc = fp[2];
		entries++;
		*count = (*count) + 1;
		room--;
	}
}

void __print_backtrace(unsigned int pir,
		       struct bt_entry *entries, unsigned int count,
		       char *out_buf, unsigned int *len, bool symbols)
{
	static char bt_text_buf[4096];
	int i, l = 0, max;
	char *buf = out_buf;
	unsigned long bottom, top, tbot, ttop, saddr = 0;
	char *sym = NULL, *sym_end = NULL;
	char mark;

	if (!out_buf) {
		buf = bt_text_buf;
		max = sizeof(bt_text_buf) - 16;
	} else
		max = *len - 1;

	bottom = cpu_stack_bottom(pir);
	top = cpu_stack_top(pir);
	tbot = SKIBOOT_BASE;
	ttop = (unsigned long)&_etext;

	l += snprintf(buf, max, "CPU %04x Backtrace:\n", pir);
	for (i = 0; i < count && l < max; i++) {
		if (entries->sp < bottom || entries->sp > top)
			mark = '!';
		else if (entries->pc < tbot || entries->pc > ttop)
			mark = '*';
		else
			mark = ' ';
		if (symbols)
			saddr = get_symbol(entries->pc, &sym, &sym_end);
		else
			saddr = 0;
		l += snprintf(buf + l, max - l,
			      " S: %016lx R: %016lx %c ",
			      entries->sp, entries->pc, mark);
		while(saddr && sym < sym_end && l < max)
			buf[l++] = *(sym++);
		if (sym && l < max)
			l += snprintf(buf + l, max - l, "+0x%lx\n",
				      entries->pc - saddr);
		else
			l += snprintf(buf + l, max - l, "\n");
		entries++;
	}
	if (!out_buf)
		write(stdout->fd, bt_text_buf, l);
	buf[l++] = 0;
	if (len)
		*len = l;
}

void backtrace(void)
{
	unsigned int ents = STACK_BUF_ENTRIES;

	__backtrace(bt_buf, &ents);
	__print_backtrace(mfspr(SPR_PIR), bt_buf, ents, NULL, NULL, true);
}

void __noreturn __nomcount __stack_chk_fail(void);
void __noreturn __nomcount __stack_chk_fail(void)
{
	prlog(PR_EMERG, "Stack corruption detected !\n");
	abort();
}

#ifdef STACK_CHECK_ENABLED

static int64_t lowest_stack_mark = LONG_MAX;
static struct lock stack_check_lock = LOCK_UNLOCKED;

void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr);
void __nomcount __mcount_stack_check(uint64_t sp, uint64_t lr)
{
	struct cpu_thread *c = this_cpu();
	uint64_t base = (uint64_t)c;
	uint64_t bot = base + sizeof(struct cpu_thread);
	int64_t mark = sp - bot;
	uint64_t top = base + NORMAL_STACK_SIZE;

	/*
	 * Don't re-enter on this CPU or don't enter at all if somebody
	 * has spotted an overflow
	 */
	if (c->in_mcount)
		return;
	c->in_mcount = true;

	/* Capture lowest stack for this thread */
	if (mark < c->stack_bot_mark) {
		unsigned int count = CPU_BACKTRACE_SIZE;
		lock(&stack_check_lock);
		c->stack_bot_mark = mark;
		c->stack_bot_pc = lr;
		c->stack_bot_tok = c->current_token;
		__backtrace(c->stack_bot_bt, &count);
		c->stack_bot_bt_count = count;
		unlock(&stack_check_lock);
	}

	/* Stack is within bounds ? check for warning and bail */
	if (sp >= (bot + STACK_SAFETY_GAP) && sp < top) {
		if (mark < STACK_WARNING_GAP) {
			prlog(PR_EMERG, "CPU %04x Stack usage danger !"
			      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
			      c->pir, lr, sp, mark, c->current_token);
			backtrace();
		}
		c->in_mcount = false;
		return;
	}
	
	prlog(PR_EMERG, "CPU %04x Stack overflow detected !"
	      " pc=%08llx sp=%08llx (gap=%lld) token=%lld\n",
	      c->pir, lr, sp, mark, c->current_token);
	abort();
}

void check_stacks(void)
{
	struct cpu_thread *c, *lowest = NULL;

	/* We should never call that from mcount */
	assert(!this_cpu()->in_mcount);

	/* Mark ourselves "in_mcount" to avoid deadlock on stack
	 * check lock
	 */
	this_cpu()->in_mcount = true;

	for_each_cpu(c) {
		if (!c->stack_bot_mark ||
		    c->stack_bot_mark >= lowest_stack_mark)
			continue;
		lock(&stack_check_lock);
		if (c->stack_bot_mark < lowest_stack_mark) {
			lowest = c;
			lowest_stack_mark = c->stack_bot_mark;
		}
		unlock(&stack_check_lock);
	}
	if (lowest) {
		lock(&stack_check_lock);
		prlog(PR_NOTICE, "CPU %04x lowest stack mark %lld bytes left"
		      " pc=%08llx token=%lld\n",
		      lowest->pir, lowest->stack_bot_mark, lowest->stack_bot_pc,
		      lowest->stack_bot_tok);
		__print_backtrace(lowest->pir, lowest->stack_bot_bt,
				  lowest->stack_bot_bt_count, NULL, NULL, true);
		unlock(&stack_check_lock);
	}

	this_cpu()->in_mcount = false;
}
#endif /* STACK_CHECK_ENABLED */
