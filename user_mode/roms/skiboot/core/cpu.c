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
 * TODO: Index array by PIR to be able to catch them easily
 * from assembly such as machine checks etc...
 */
#include <skiboot.h>
#include <cpu.h>
#include <device.h>
#include <mem_region.h>
#include <opal.h>
#include <stack.h>
#include <trace.h>
#include <affinity.h>
#include <chip.h>
#include <timebase.h>
#include <ccan/str/str.h>
#include <ccan/container_of/container_of.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_stack {
	union {
		uint8_t	stack[STACK_SIZE];
		struct cpu_thread cpu;
	};
} __align(STACK_SIZE);

static struct cpu_stack *cpu_stacks = (struct cpu_stack *)CPU_STACKS_BASE;
unsigned int cpu_thread_count;
unsigned int cpu_max_pir;
struct cpu_thread *boot_cpu;
static struct lock reinit_lock = LOCK_UNLOCKED;
static bool hile_supported;
static unsigned long hid0_hile;
static unsigned long hid0_attn;

unsigned long cpu_secondary_start __force_data = 0;

struct cpu_job {
	struct list_node	link;
	void			(*func)(void *data);
	void			*data;
	const char		*name;
	bool			complete;
	bool		        no_return;
};

static struct lock global_job_queue_lock = LOCK_UNLOCKED;
static struct list_head	global_job_queue;

/* attribute const as cpu_stacks is constant. */
unsigned long __attrconst cpu_stack_bottom(unsigned int pir)
{
	return ((unsigned long)&cpu_stacks[pir]) +
		sizeof(struct cpu_thread) + STACK_SAFETY_GAP;
}

unsigned long __attrconst cpu_stack_top(unsigned int pir)
{
	/* This is the top of the MC stack which is above the normal
	 * stack, which means a SP between cpu_stack_bottom() and
	 * cpu_stack_top() can either be a normal stack pointer or
	 * a Machine Check stack pointer
	 */
	return ((unsigned long)&cpu_stacks[pir]) +
		NORMAL_STACK_SIZE - STACK_TOP_GAP;
}

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return)
{
	struct cpu_job *job;

#ifdef DEBUG_SERIALIZE_CPU_JOBS
	if (cpu == NULL)
		cpu = this_cpu();
#endif

	if (cpu && !cpu_is_available(cpu)) {
		prerror("CPU: Tried to queue job on unavailable CPU 0x%04x\n",
			cpu->pir);
		return NULL;
	}

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->name = name;
	job->complete = false;
	job->no_return = no_return;

	if (cpu == NULL) {
		lock(&global_job_queue_lock);
		list_add_tail(&global_job_queue, &job->link);
		unlock(&global_job_queue_lock);
	} else if (cpu != this_cpu()) {
		lock(&cpu->job_lock);
		list_add_tail(&cpu->job_queue, &job->link);
		unlock(&cpu->job_lock);
	} else {
		func(data);
		job->complete = true;
	}

	/* XXX Add poking of CPU with interrupt */

	return job;
}

bool cpu_poll_job(struct cpu_job *job)
{
	lwsync();
	return job->complete;
}

void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	unsigned long ticks = usecs_to_tb(5);
	unsigned long period = msecs_to_tb(5);
	unsigned long time_waited = 0;

	if (!job)
		return;

	while(!job->complete) {
		time_wait(ticks);
		time_waited+=ticks;
		if (time_waited % period == 0)
			opal_run_pollers();
		lwsync();
	}
	lwsync();
	smt_medium();

	if (time_waited > msecs_to_tb(1000))
		prlog(PR_DEBUG, "cpu_wait_job(%s) for %lu\n",
		      job->name, tb_to_msecs(time_waited));

	if (free_it)
		free(job);
}

void cpu_free_job(struct cpu_job *job)
{
	if (!job)
		return;

	assert(job->complete);
	free(job);
}

void cpu_process_jobs(void)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_job *job = NULL;
	void (*func)(void *);
	void *data;

	sync();
	if (list_empty(&cpu->job_queue) && list_empty(&global_job_queue))
		return;

	lock(&cpu->job_lock);
	while (true) {
		bool no_return;

		if (list_empty(&cpu->job_queue)) {
			smt_medium();
			if (list_empty(&global_job_queue))
				break;
			lock(&global_job_queue_lock);
			job = list_pop(&global_job_queue, struct cpu_job, link);
			unlock(&global_job_queue_lock);
		} else {
			smt_medium();
			job = list_pop(&cpu->job_queue, struct cpu_job, link);
		}

		if (!job)
			break;

		func = job->func;
		data = job->data;
		no_return = job->no_return;
		unlock(&cpu->job_lock);
		prlog(PR_TRACE, "running job %s on %x\n", job->name, cpu->pir);
		if (no_return)
			free(job);
		func(data);
		lock(&cpu->job_lock);
		if (!no_return) {
			lwsync();
			job->complete = true;
		}
	}
	unlock(&cpu->job_lock);
}

void cpu_process_local_jobs(void)
{
	struct cpu_thread *cpu = first_available_cpu();

	while (cpu) {
		if (cpu != this_cpu())
			return;

		cpu = next_available_cpu(cpu);
	}

	if (!cpu)
		cpu = first_available_cpu();

	/* No CPU to run on, just run synchro */
	if (cpu == this_cpu()) {
		prlog_once(PR_DEBUG, "Processing jobs synchronously\n");
		cpu_process_jobs();
	}
}


struct dt_node *get_cpu_node(u32 pir)
{
	struct cpu_thread *t = find_cpu_by_pir(pir);

	return t ? t->node : NULL;
}

/* This only covers primary, active cpus */
struct cpu_thread *find_cpu_by_chip_id(u32 chip_id)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->is_secondary)
			continue;
		if (t->chip_id == chip_id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_node(struct dt_node *cpu)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->node == cpu)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_pir(u32 pir)
{
	if (pir > cpu_max_pir)
		return NULL;
	return &cpu_stacks[pir].cpu;
}

struct cpu_thread *find_cpu_by_server(u32 server_no)
{
	struct cpu_thread *t;

	for_each_cpu(t) {
		if (t->server_no == server_no)
			return t;
	}
	return NULL;
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	struct cpu_stack *s = container_of(cpu, struct cpu_stack, cpu);
	unsigned int index;

	if (cpu == NULL)
		index = 0;
	else
		index = s - cpu_stacks + 1;
	for (; index <= cpu_max_pir; index++) {
		cpu = &cpu_stacks[index].cpu;
		if (cpu->state != cpu_state_no_cpu)
			return cpu;
	}
	return NULL;
}

struct cpu_thread *first_cpu(void)
{
	return next_cpu(NULL);
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && !cpu_is_available(cpu));

	return cpu;
}

struct cpu_thread *first_available_cpu(void)
{
	return next_available_cpu(NULL);
}

u8 get_available_nr_cores_in_chip(u32 chip_id)
{
	struct cpu_thread *core;
	u8 nr_cores = 0;

	for_each_available_core_in_chip(core, chip_id)
		nr_cores++;

	return nr_cores;
}

struct cpu_thread *next_available_core_in_chip(struct cpu_thread *core,
					       u32 chip_id)
{
	do {
		core = next_cpu(core);
	} while(core && (!cpu_is_available(core) ||
			 core->chip_id != chip_id ||
			 core->is_secondary));
	return core;
}

struct cpu_thread *first_available_core_in_chip(u32 chip_id)
{
	return next_available_core_in_chip(NULL, chip_id);
}

uint32_t cpu_get_core_index(struct cpu_thread *cpu)
{
	return pir_to_core_id(cpu->pir);
}

void cpu_remove_node(const struct cpu_thread *t)
{
	struct dt_node *i;

	/* Find this cpu node */
	dt_for_each_node(dt_root, i) {
		const struct dt_property *p;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;
		p = dt_find_property(i, "ibm,pir");
		if (!p)
			continue;
		if (dt_property_get_cell(p, 0) == t->pir) {
			dt_free(i);
			return;
		}
	}
	prerror("CPU: Could not find cpu node %i to remove!\n", t->pir);
	abort();
}

void cpu_disable_all_threads(struct cpu_thread *cpu)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_stacks[i].cpu;

		if (t->primary == cpu->primary)
			t->state = cpu_state_disabled;
	}

	/* XXX Do something to actually stop the core */
}

static void init_cpu_thread(struct cpu_thread *t,
			    enum cpu_thread_state state,
			    unsigned int pir)
{
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	t->state = state;
	t->pir = pir;
#ifdef STACK_CHECK_ENABLED
	t->stack_bot_mark = LONG_MAX;
#endif
	assert(pir == container_of(t, struct cpu_stack, cpu) - cpu_stacks);
}

static void enable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 |= hid0_attn;
	set_hid0(hid0);
}

static void disable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 &= ~hid0_attn;
	set_hid0(hid0);
}

extern void __trigger_attn(void);
void trigger_attn(void)
{
	enable_attn();
	__trigger_attn();
}

void init_hid(void)
{
	/* attn is enabled even when HV=0, so make sure it's off */
	disable_attn();
}

void pre_init_boot_cpu(void)
{
	struct cpu_thread *cpu = this_cpu();

	memset(cpu, 0, sizeof(struct cpu_thread));
}

void init_boot_cpu(void)
{
	unsigned int i, pir, pvr;

	pir = mfspr(SPR_PIR);
	pvr = mfspr(SPR_PVR);

	/* Get CPU family and other flags based on PVR */
	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		proc_gen = proc_gen_p7;
		break;
	case PVR_TYPE_P8E:
	case PVR_TYPE_P8:
		proc_gen = proc_gen_p8;
		hile_supported = PVR_VERS_MAJ(mfspr(SPR_PVR)) >= 2;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P8NVL:
		proc_gen = proc_gen_p8;
		hile_supported = true;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P9:
		proc_gen = proc_gen_p9;
		hile_supported = true;
		hid0_hile = SPR_HID0_POWER9_HILE;
		hid0_attn = SPR_HID0_POWER9_ENABLE_ATTN;
		break;
	default:
		proc_gen = proc_gen_unknown;
	}

	/* Get a CPU thread count and an initial max PIR based on family */
	switch(proc_gen) {
	case proc_gen_p7:
		cpu_thread_count = 4;
		cpu_max_pir = SPR_PIR_P7_MASK;
		prlog(PR_INFO, "CPU: P7 generation processor"
		      "(max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p8:
		cpu_thread_count = 8;
		cpu_max_pir = SPR_PIR_P8_MASK;
		prlog(PR_INFO, "CPU: P8 generation processor"
		      "(max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p9:
		cpu_thread_count = 4;
		cpu_max_pir = SPR_PIR_P9_MASK;
		prlog(PR_INFO, "CPU: P9 generation processor"
		      "(max %d threads/core)\n", cpu_thread_count);
		break;
	default:
		prerror("CPU: Unknown PVR, assuming 1 thread\n");
		cpu_thread_count = 1;
		cpu_max_pir = mfspr(SPR_PIR);
	}

	prlog(PR_DEBUG, "CPU: Boot CPU PIR is 0x%04x PVR is 0x%08x\n",
	      pir, pvr);
	prlog(PR_DEBUG, "CPU: Initial max PIR set to 0x%x\n", cpu_max_pir);

	/* Clear the CPU structs */
	for (i = 0; i <= cpu_max_pir; i++)
		memset(&cpu_stacks[i].cpu, 0, sizeof(struct cpu_thread));

	/* Setup boot CPU state */
	boot_cpu = &cpu_stacks[pir].cpu;
	init_cpu_thread(boot_cpu, cpu_state_active, pir);
	init_boot_tracebuf(boot_cpu);
	assert(this_cpu() == boot_cpu);
	init_hid();

	list_head_init(&global_job_queue);
}

static void enable_large_dec(bool on)
{
	u64 lpcr = mfspr(SPR_LPCR);

	if (on)
		lpcr |= SPR_LPCR_P9_LD;
	else
		lpcr &= ~SPR_LPCR_P9_LD;

	mtspr(SPR_LPCR, lpcr);
}

#define HIGH_BIT (1ull << 63)

static int find_dec_bits(void)
{
	int bits = 65; /* we always decrement once */
	u64 mask = ~0ull;

	if (proc_gen < proc_gen_p9)
		return 32;

	/* The ISA doesn't specify the width of the decrementer register so we
	 * need to discover it. When in large mode (LPCR.LD = 1) reads from the
	 * DEC SPR are sign extended to 64 bits and writes are truncated to the
	 * physical register width. We can use this behaviour to detect the
	 * width by starting from an all 1s value and left shifting until we
	 * read a value from the DEC with it's high bit cleared.
	 */

	enable_large_dec(true);

	do {
		bits--;
		mask = mask >> 1;
		mtspr(SPR_DEC, mask);
	} while (mfspr(SPR_DEC) & HIGH_BIT);

	enable_large_dec(false);

	prlog(PR_DEBUG, "CPU: decrementer bits %d\n", bits);
	return bits;
}

void init_all_cpus(void)
{
	struct dt_node *cpus, *cpu;
	unsigned int thread, new_max_pir = 0;
	int dec_bits = find_dec_bits();

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int pir, server_no, chip_id;
		enum cpu_thread_state state;
		const struct dt_property *p;
		struct cpu_thread *t, *pt;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/* If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		/* We should always have an ibm,chip-id property */
		chip_id = dt_get_chip_id(cpu);

		/* Only use operational CPUs */
		if (!strcmp(dt_prop_get(cpu, "status"), "okay"))
			state = cpu_state_present;
		else
			state = cpu_state_unavailable;

		prlog(PR_INFO, "CPU: CPU from DT PIR=0x%04x Server#=0x%x"
		      " State=%d\n", pir, server_no, state);

		/* Setup thread 0 */
		assert(pir <= cpu_max_pir);
		t = pt = &cpu_stacks[pir].cpu;
		if (t != boot_cpu) {
			init_cpu_thread(t, state, pir);
			/* Each cpu gets its own later in init_trace_buffers */
			t->trace = boot_cpu->trace;
		}
		t->server_no = server_no;
		t->primary = t;
		t->node = cpu;
		t->chip_id = chip_id;
		t->icp_regs = NULL; /* Will be set later */
		t->core_hmi_state = 0;
		t->core_hmi_state_ptr = &t->core_hmi_state;
		t->thread_mask = 1;

		/* Add associativity properties */
		add_core_associativity(t);

		/* Add the decrementer width property */
		dt_add_property_cells(cpu, "ibm,dec-bits", dec_bits);

		/* Adjust max PIR */
		if (new_max_pir < (pir + cpu_thread_count - 1))
			new_max_pir = pir + cpu_thread_count - 1;

		/* Iterate threads */
		p = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		if (!p)
			continue;
		for (thread = 1; thread < (p->len / 4); thread++) {
			prlog(PR_TRACE, "CPU:   secondary thread %d found\n",
			      thread);
			t = &cpu_stacks[pir + thread].cpu;
			init_cpu_thread(t, state, pir + thread);
			t->trace = boot_cpu->trace;
			t->server_no = ((const u32 *)p->prop)[thread];
			t->is_secondary = true;
			t->primary = pt;
			t->node = cpu;
			t->chip_id = chip_id;
			t->core_hmi_state_ptr = &pt->core_hmi_state;
			t->thread_mask = 1 << thread;
		}
		prlog(PR_INFO, "CPU:  %d secondary threads\n", thread);
	}
	cpu_max_pir = new_max_pir;
	prlog(PR_DEBUG, "CPU: New max PIR set to 0x%x\n", new_max_pir);
	adjust_cpu_stacks_alloc();
}

void cpu_bringup(void)
{
	struct cpu_thread *t;

	prlog(PR_INFO, "CPU: Setting up secondary CPU state\n");

	op_display(OP_LOG, OP_MOD_CPU, 0x0000);

	/* Tell everybody to chime in ! */	
	prlog(PR_INFO, "CPU: Calling in all processors...\n");
	cpu_secondary_start = 1;
	sync();

	op_display(OP_LOG, OP_MOD_CPU, 0x0002);

	for_each_cpu(t) {
		if (t->state != cpu_state_present &&
		    t->state != cpu_state_active)
			continue;

		/* Add a callin timeout ?  If so, call cpu_remove_node(t). */
		while (t->state != cpu_state_active) {
			smt_very_low();
			sync();
		}
		smt_medium();
	}

	prlog(PR_INFO, "CPU: All processors called in...\n");

	op_display(OP_LOG, OP_MOD_CPU, 0x0003);
}

void cpu_callin(struct cpu_thread *cpu)
{
	cpu->state = cpu_state_active;
}

static void opal_start_thread_job(void *data)
{
	cpu_give_self_os();

	/* We do not return, so let's mark the job as
	 * complete
	 */
	start_kernel_secondary((uint64_t)data);
}

static int64_t opal_start_cpu_thread(uint64_t server_no, uint64_t start_address)
{
	struct cpu_thread *cpu;
	struct cpu_job *job;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Start invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	prlog(PR_DEBUG, "OPAL: Start CPU 0x%04llx (PIR 0x%04x) -> 0x%016llx\n",
	       server_no, cpu->pir, start_address);

	lock(&reinit_lock);
	if (!cpu_is_available(cpu)) {
		unlock(&reinit_lock);
		prerror("OPAL: CPU not active in OPAL !\n");
		return OPAL_WRONG_STATE;
	}
	if (cpu->in_reinit) {
		unlock(&reinit_lock);
		prerror("OPAL: CPU being reinitialized !\n");
		return OPAL_WRONG_STATE;
	}
	job = __cpu_queue_job(cpu, "start_thread",
			      opal_start_thread_job, (void *)start_address,
			      true);
	unlock(&reinit_lock);
	if (!job) {
		prerror("OPAL: Failed to create CPU start job !\n");
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_START_CPU, opal_start_cpu_thread, 2);

static int64_t opal_query_cpu_status(uint64_t server_no, uint8_t *thread_status)
{
	struct cpu_thread *cpu;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Query invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	if (!cpu_is_available(cpu) && cpu->state != cpu_state_os) {
		prerror("OPAL: CPU not active in OPAL nor OS !\n");
		return OPAL_PARAMETER;
	}
	switch(cpu->state) {
	case cpu_state_os:
		*thread_status = OPAL_THREAD_STARTED;
		break;
	case cpu_state_active:
		/* Active in skiboot -> inactive in OS */
		*thread_status = OPAL_THREAD_INACTIVE;
		break;
	default:
		*thread_status = OPAL_THREAD_UNAVAILABLE;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_QUERY_CPU_STATUS, opal_query_cpu_status, 2);

static int64_t opal_return_cpu(void)
{
	prlog(PR_DEBUG, "OPAL: Returning CPU 0x%04x\n", this_cpu()->pir);

	__secondary_cpu_entry();

	return OPAL_HARDWARE; /* Should not happen */
}
opal_call(OPAL_RETURN_CPU, opal_return_cpu, 0);

static void cpu_change_hile(void *hilep)
{
	bool hile = *(bool *)hilep;
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	if (hile)
		hid0 |= hid0_hile;
	else
		hid0 &= ~hid0_hile;
	prlog(PR_DEBUG, "CPU: [%08x] HID0 set to 0x%016lx\n",
	      this_cpu()->pir, hid0);
	set_hid0(hid0);

	this_cpu()->current_hile = hile;
}

static int64_t cpu_change_all_hile(bool hile)
{
	struct cpu_thread *cpu;

	prlog(PR_INFO, "CPU: Switching HILE on all CPUs to %d\n", hile);

	for_each_available_cpu(cpu) {
		if (cpu->current_hile == hile)
			continue;
		if (cpu == this_cpu()) {
			cpu_change_hile(&hile);
			continue;
		}
		cpu_wait_job(cpu_queue_job(cpu, "cpu_change_hile",
					   cpu_change_hile, &hile), true);
	}
	return OPAL_SUCCESS;
}

static int64_t opal_reinit_cpus(uint64_t flags)
{
	struct cpu_thread *cpu;
	int64_t rc = OPAL_SUCCESS;
	int i;

	prlog(PR_INFO, "OPAL: Trying a CPU re-init with flags: 0x%llx\n", flags);

 again:
	lock(&reinit_lock);

	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu)) {
		if (cpu == this_cpu() || cpu->in_reinit)
			continue;
		if (cpu->state == cpu_state_os) {
			unlock(&reinit_lock);
			/*
			 * That might be a race with return CPU during kexec
			 * where we are still, wait a bit and try again
			 */
			for (i = 0; (i < 1000) &&
				     (cpu->state == cpu_state_os); i++) {
				time_wait_ms(1);
			}
			if (cpu->state == cpu_state_os) {
				prerror("OPAL: CPU 0x%x not in OPAL !\n", cpu->pir);
				return OPAL_WRONG_STATE;
			}
			goto again;
		}
		cpu->in_reinit = true;
	}
	/*
	 * Now we need to mark ourselves "active" or we'll be skipped
	 * by the various "for_each_active_..." calls done by slw_reinit()
	 */
	this_cpu()->state = cpu_state_active;
	this_cpu()->in_reinit = true;
	unlock(&reinit_lock);

	/*
	 * If the flags affect endianness and we are on P8 DD2 or later, then
	 * use the HID bit. We use the PVR (we could use the EC level in
	 * the chip but the PVR is more readily available).
	 */
	if (hile_supported &&
	    (flags & (OPAL_REINIT_CPUS_HILE_BE | OPAL_REINIT_CPUS_HILE_LE))) {
		bool hile = !!(flags & OPAL_REINIT_CPUS_HILE_LE);

		flags &= ~(OPAL_REINIT_CPUS_HILE_BE | OPAL_REINIT_CPUS_HILE_LE);
		rc = cpu_change_all_hile(hile);
	}

	/* If we have a P7, error out for LE switch, do nothing for BE */
	if (proc_gen < proc_gen_p8) {
		if (flags & OPAL_REINIT_CPUS_HILE_LE)
			rc = OPAL_UNSUPPORTED;
		flags &= ~(OPAL_REINIT_CPUS_HILE_BE | OPAL_REINIT_CPUS_HILE_LE);
	}

	/* Any flags left ? */
	if (flags != 0 && proc_gen == proc_gen_p8)
		rc = slw_reinit(flags);
	else if (flags != 0)
		rc = OPAL_UNSUPPORTED;

	/* And undo the above */
	lock(&reinit_lock);
	this_cpu()->state = cpu_state_os;
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))
		cpu->in_reinit = false;
	unlock(&reinit_lock);

	return rc;
}
opal_call(OPAL_REINIT_CPUS, opal_reinit_cpus, 1);
