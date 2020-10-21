/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include "qemu/osdep.h"
#include "cpu.h"


#include <sys/shm.h>
#include "../../config.h"

//FILE *file_log=NULL;
//int iteration_times = 0;


/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#ifdef TARGET_MIPS
#define AFL_QEMU_CPU_SNIPPET2 do { \
    afl_maybe_log(env->active_tc.PC); \
  } while (0)
#endif

#ifdef TARGET_ARM
#define AFL_QEMU_CPU_SNIPPET2 do { \
    afl_maybe_log(env->regs[15]); \
  } while (0)
#endif
  
/*
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(itb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(cpu); \
    } \
    afl_maybe_log(itb->pc); \
  } while (0)
*/

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

target_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

//static void afl_setup(void);
//static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(target_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

//static void afl_setup(void) {
void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (target_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}


void normal_forkserver(CPUArchState *env){
#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

//zyw
    afl_user_fork = 1;
//
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      return;

    }

    /* Parent. */
    afl_user_fork = 0;

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);

  }

}

/* Fork server logic, invoked once we hit _start. */
//static void afl_forkserver(CPUState *cpu) {
void afl_forkserver(CPUArchState *env){

//zyw
#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif

//

  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {
    /*
    iteration_times++;
    char items[20];
    sprintf(items, "%d", iteration_times);
    char log_file_name[25];
    strcpy(log_file_name, "/root/log/");
    strcat(log_file_name, items);
    file_log = fopen(log_file_name, "w+");
    */

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

//zyw
    afl_user_fork = 1;
    print_loop_count++;
//
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */
//zyw
      //memset(afl_area_ptr, 0, 65536*sizeof(unsigned char));

      //DECAF_printf("new iteration\n");
      gettimeofday(&loop_begin, NULL);
//     
      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;
      

    }
    /* Parent. */
//zyw
    if(print_loop_count == print_loop_times)
    {
      print_loop_count = 0;
    }
    afl_user_fork = 0;
//
    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */
    //afl_wait_tsl(cpu, t_fd[0]);
    /* Get and relay exit status to parent. */
    //status = WEXITSTATUS(status);//zyw
    //printf("exit status:%d\n", status);
    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

    //fclose(file_log);
  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(target_ulong cur_loc) {

  static __thread target_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;
  /*
  if (file_log!=NULL)
  {
    fprintf(file_log, "pc:%x\n", cur_loc);
  }
  */
  
  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;
  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}


//zyw add
#ifdef TARGET_MIPS
r4k_tlb_t saved_tlb[MIPS_TLB_MAX];

void store_tlb(CPUMIPSState * env)
{
    for(int i =0; i<MIPS_TLB_MAX; i++)
    {
        saved_tlb[i] = env->tlb->mmu.r4k.tlb[i];
    }
}

void reload_tlb(CPUMIPSState * env)
{
    for(int i =0; i<MIPS_TLB_MAX; i++)
    {
        env->tlb->mmu.r4k.tlb[i] = saved_tlb[i];
    }
}
#endif

/*
target_ulong record_read_tlb[256];
target_ulong record_write_tlb[256];
int read_index = 0;
int write_index = 0;

//qemu_handle_addr_thread_fn may calls it.

void record_tlb_ind(int ind, int flag) // not index
{
	if (flag == 0)
	{
		record_read_tlb[read_index++] = ind;

	}
	else if(flag == 1)
	{
		record_write_tlb[write_index++] = ind;
	}
	else
	{
		record_read_tlb[read_index++] = ind;
	}
}

void recover_tlb(CPUArchState *env)
{
	for(int i = 0; i < read_index ; i++)
	{
		int ind = record_read_tlb[i];
		env->tlb_table[2][ind].addr_read = 0xffffffff;
	}
	for(int j = 0; j < write_index ; j++)
	{
		int ind = record_write_tlb[j];
		env->tlb_table[2][ind].addr_write = 0xffffffff;
	}
	read_index = 0;
	write_index = 0;
}

*/
typedef struct 
{
	int ind;
	target_ulong addr_code;
    target_ulong addr_read;
    target_ulong addr_write;
    uintptr_t addend;
    struct TLB_BACKUP * next;
} TLB_BACKUP;

TLB_BACKUP *tlb_backup_head =NULL;

void record_tlb(target_ulong ind, target_ulong addr_code, target_ulong addr_read, target_ulong addr_write, uintptr_t addend)
{
	//printf("&&&&&&&&&&&&&&&&&&& record_tlb: %x\n", ind);
	TLB_BACKUP * tlb_backup = (TLB_BACKUP *)malloc(sizeof(TLB_BACKUP));
	tlb_backup -> ind =ind;
	tlb_backup -> addr_code =addr_code;
	tlb_backup -> addr_read =addr_read;
	tlb_backup -> addr_write =addr_write;
	tlb_backup -> addend =addend;
	if(tlb_backup_head == NULL)
	{
		tlb_backup_head = tlb_backup;
		tlb_backup -> next =NULL;
	}
	else
	{
		TLB_BACKUP * tmp = tlb_backup_head;
		tlb_backup_head = tlb_backup;
		tlb_backup -> next = tmp;
	}

}

bool find_tlb_backup(target_ulong ind)
{
	//printf("&&&&&&&&&&&&&&&&&&& find tlb: %x\n", ind);
	for(TLB_BACKUP * curr = tlb_backup_head; curr!=NULL; curr = curr->next)
	{
		target_ulong tmp_ind = curr->ind;
		if(tmp_ind == ind)
		{
			return true;
		}
	}
	return false;
}


void recover_tlb(CPUArchState *env)
{
	for(TLB_BACKUP * curr = tlb_backup_head; curr!=NULL; curr = curr->next)
	{
		target_ulong tmp_ind = curr->ind;
#ifdef TARGET_MIPS
		env->tlb_table[2][tmp_ind].addr_code =  curr->addr_code;
		env->tlb_table[2][tmp_ind].addr_read =  curr->addr_read;
		env->tlb_table[2][tmp_ind].addr_write =  curr->addr_write;
		env->tlb_table[2][tmp_ind].addend =  curr->addend;
		//printf("&&&&&&&&&&&&&&&&&&& recover tlb:%x,%x,%x,%x,%x\n", tmp_ind, curr->addr_code, curr->addr_read, curr->addr_write, curr->addend);
#elif defined(TARGET_ARM)
		env->tlb_table[0][tmp_ind].addr_code =  curr->addr_code;
		env->tlb_table[0][tmp_ind].addr_read =  curr->addr_read;
		env->tlb_table[0][tmp_ind].addr_write =  curr->addr_write;
		env->tlb_table[0][tmp_ind].addend =  curr->addend;
#endif
	}
}



CPUArchState backup_cpu;
CPUState backup_cpu0;
CPUTLBEntry backup_tlb_table[4][256];

#ifdef TARGET_MIPS
void storeCPUState(CPUState* cpu, CPUArchState *env)
{
  for(int i=0; i<32; i++)
  {
    backup_cpu.active_tc.gpr[i] = env->active_tc.gpr[i];
  }
  backup_cpu.active_tc.PC = env->active_tc.PC;
  backup_cpu.CP0_EPC = env->CP0_EPC;
  backup_cpu.CP0_Status = env->CP0_Status;
  backup_cpu.CP0_Cause = env->CP0_Cause;
  backup_cpu0.exception_index = cpu->exception_index;
  backup_cpu0.interrupt_request = cpu->interrupt_request;

    for(int i=0; i<4; i++)
    {
        for(int j=0; j<256; j++)
        {
            backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
            backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
            backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
            backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
        }
    }
}

void loadCPUState(CPUState *cpu, CPUArchState *env)
{
  for(int i=0; i<32; i++)
  {
    env->active_tc.gpr[i] = backup_cpu.active_tc.gpr[i];
  }
  env->active_tc.PC = backup_cpu.active_tc.PC;
  env->CP0_EPC = backup_cpu.CP0_EPC;
  env->CP0_Status = backup_cpu.CP0_Status;
  env->CP0_Cause = backup_cpu.CP0_Cause;
  cpu->exception_index = backup_cpu0.exception_index;
  cpu->interrupt_request = backup_cpu0.interrupt_request;

  for(int i=0; i<4; i++)
  {
      for(int j=0; j<256; j++)
      {
          env->tlb_table[i][j].addr_code = backup_tlb_table[i][j].addr_code;
          env->tlb_table[i][j].addr_write = backup_tlb_table[i][j].addr_write;
          env->tlb_table[i][j].addr_read = backup_tlb_table[i][j].addr_read;
          env->tlb_table[i][j].addend = backup_tlb_table[i][j].addend;
      }
  }
}

#elif defined(TARGET_ARM)
void storeCPUState(CPUArchState *env)
{
  for(int i=0; i<16; i++)
  {
    backup_cpu.regs[i] =  env->regs[i];
  }


  for(int i=0; i<4; i++)
  {
      for(int j=0; j<256; j++)
      {
          backup_tlb_table[i][j].addr_code = env->tlb_table[i][j].addr_code;
          backup_tlb_table[i][j].addr_write = env->tlb_table[i][j].addr_write;
          backup_tlb_table[i][j].addr_read = env->tlb_table[i][j].addr_read;
          backup_tlb_table[i][j].addend = env->tlb_table[i][j].addend;
      }
  }
}

void loadCPUState(CPUArchState *env)
{
  for(int i=0; i<16; i++)
  {
    env->regs[i] = backup_cpu.regs[i];
  }

  for(int i=0; i<4; i++)
  {
      for(int j=0; j<256; j++)
      {
          env->tlb_table[i][j].addr_code = backup_tlb_table[i][j].addr_code;
          env->tlb_table[i][j].addr_write = backup_tlb_table[i][j].addr_write;
          env->tlb_table[i][j].addr_read = backup_tlb_table[i][j].addr_read;
          env->tlb_table[i][j].addend = backup_tlb_table[i][j].addend;
      }
  }
}
#endif


static ssize_t uninterrupted_read(int fd, void *buf, size_t cnt)
{
    ssize_t n;
    while((n = read(fd, buf, cnt)) == -1 && errno == EINTR)
        continue;
    return n;
}


static target_ulong startTrace(CPUArchState *env, target_ulong start, target_ulong end)
{
    afl_start_code = start;
    afl_end_code   = end;
    return 0;
}

static target_ulong stopTrace()
{
    afl_start_code = 0;
    afl_end_code   = 0;
    return 0;
}

static target_ulong doneWork(target_ulong val)
{
#ifdef LETSNOT 
    if(aflGotLog)
        exit(64 | val);
#endif
    exit(val); /* exit forkserver child */
}



target_ulong afl_noforkserver(CPUArchState *env, int status)
{

  #ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif


// need reload vmi, reset afl data.
    //DECAF_printf("afl_endWork_restart\n");
  //int status = 0; //?WEXITSTATUS;
  static unsigned char tmp[4];

//write status crash or not?
  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
//restart from parent
  //if (uninterrupted_read(FORKSRV_FD, tmp, 4) != 4) exit(2);
  if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);
//reset afl_area_ptr, afl_start
  //memset(afl_area_ptr, 0, 65536*sizeof(unsigned char));


  afl_forksrv_pid = getpid() + 1;

  if (write(FORKSRV_FD + 1, &afl_forksrv_pid, 4) != 4) exit(5);

  gettimeofday(&loop_begin, NULL);
#ifdef TARGET_MIPS
  storeCPUState(cpu, env);
  store_tlb(env);
#endif
  print_loop_count++;
  if(print_debug)
  {
    DECAF_printf("new iteration\n");
  }
  //restore_page(1);
  afl_user_fork = 1;
  return 0;
}

int delta = 0;
int feed_times = 0;
target_ulong afl_noforkserver_restart(CPUArchState *env, int status)
{

#ifdef TARGET_MIPS
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);
#elif defined(TARGET_ARM)
  ARMCPU *arm_cpu = arm_env_get_cpu(env);
  CPUState *cpu = CPU(arm_cpu);
#endif
// need reload vmi, reset afl data.
    //DECAF_printf("afl_endWork_restart\n");
    //int status = 0; //?WEXITSTATUS;
    static unsigned char tmp[4];

//write status crash or not?
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
//restart from parent
    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);
//reset afl_area_ptr, afl_start
    //memset(afl_area_ptr, 0, 65536*sizeof(unsigned char));


    afl_forksrv_pid = getpid() + delta;
    delta++;

    if (write(FORKSRV_FD + 1, &afl_forksrv_pid, 4) != 4) exit(5);

    gettimeofday(&loop_begin, NULL);


#ifdef TARGET_MIPS
    loadCPUState(cpu, env);
    reload_tlb(env);
#endif
    print_loop_count++;

    if(print_debug)
    {
      DECAF_printf("new iteration\n");
    }
    feed_times = 0;
    afl_user_fork = 1;
    //restore_page(1);
    return 0;
}

