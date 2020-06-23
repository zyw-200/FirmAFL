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
#include "zyw_config.h"

int run_time = 0;




int print_debug = 0;
int libuclibc_addr;

#ifdef MEM_MAPPING
void * snapshot_shmem_start;
void * snapshot_shmem_pt;
int snapshot_shmem_id;

extern void exception_exit(int syscall_num);
extern void bug_exit(target_ulong addr);


target_ulong pre_map_page[2048];//jjhttpd 0x31000 //0x1000// 0x56000 //0x51000
int pre_map_index = 0;


extern int pipe_read_fd;
extern int pipe_write_fd;

void add_premap_page(target_ulong pc);
int if_premap_page(target_ulong pc);
int if_page_pc(target_ulong pc);

void add_premap_page(target_ulong pc)
{
  assert(pc!=0);
  assert(pre_map_index < (2048 - 1));
  pre_map_page[pre_map_index++] = (pc & 0xfffff000);
}
int if_premap_page(target_ulong pc)
{
  assert(pc!=0);
  for(int i=0; i< 2048; i++)
  {
    if(pre_map_page[i] == (pc & 0xfffff000))
      return 1;
  }
  return 0;
}

int if_page_pc(target_ulong pc)
{
  assert(pc!=0);
  if((pc & 0xfff) == 0)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}
int read_content(int pipe_fd, char *buf, int total_len);
void write_aflcmd(int cmd, USER_MODE_TIME *user_mode_time);
void write_aflcmd_complete(int cmd, USER_MODE_TIME *user_mode_time);
int read_aflcmd(void);
target_ulong startTrace(target_ulong start, target_ulong end);
extern void exception_exit(int syscall_num);
void cross_process_mutex_first_init(void);
void cross_process_mutex_init(void);
void cross_shamem_disconn(void);

//zyw fix the all the pipe read error: no data, data is wrong;
int read_content(int pipe_fd, char *buf, int total_len)
{
    int rest_len = total_len;
    int read_len = 0;
    int read_len_once = 0;
    do
    {
        //printf("read_len:%x, rest_len:%x\n", read_len, rest_len);
        read_len_once = read(pipe_fd, buf + read_len, rest_len);
        if(read_len_once == -1)
        {
            continue;
        }
        rest_len -= read_len_once;
        read_len += read_len_once;
    }
    while(rest_len!=0);
    return read_len;

}

int read_aflcmd(void)
{
  int res = 0;
  if(pipe_read_fd != -1)  
  {    
      int is_loop_over;
      res = read_content(pipe_read_fd, &is_loop_over, sizeof(int));
      if(res == -1)  
      {  
          fprintf(stderr, "read_aflcmd error on pipe\n");  sleep(1000);
          exit(EXIT_FAILURE);  
      }
      printf("write aflcmd %d\n", is_loop_over); 
      return is_loop_over;
  }  
  else {
      printf("read pipe not open\n");
      sleep(1000);
      exit(EXIT_FAILURE);  
  }
}


/*
int write_aflcmd(int cmd, USER_MODE_TIME *user_mode_time)  
{  
    const char *fifo_name_user = "./user_cpu_state";  
    int pipe_fd = -1;  
    int res = 0;  
    const int open_mode_user = O_WRONLY;  
  
    if(access(fifo_name_user, F_OK) == -1)  
    {  
        res = mkfifo(fifo_name_user, 0777);  
        if(res != 0)  
        { 
            fprintf(stderr, "Could not create fifo %s\n", fifo_name_user);  
            exit(EXIT_FAILURE);  
        }  
    } 

    pipe_fd = open(fifo_name_user, open_mode_user);    
    if(pipe_fd != -1)  
    { 
      int type = 2; 
      res = write(pipe_fd, &type, sizeof(int));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write type on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      res = write(pipe_fd, &cmd, sizeof(int));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write error on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      res = write(pipe_fd, user_mode_time, sizeof(USER_MODE_TIME));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write error on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      if(print_debug)
      {
        printf("write cmd ok:%x\n", cmd);  
      }
      printf("write cmd ok:%x\n", cmd);  
      close(pipe_fd);   
    }  
    else  
        exit(EXIT_FAILURE);  
  
    return 1;  
}  
*/

void write_aflcmd(int cmd, USER_MODE_TIME *user_mode_time)  
{  
    int res = 0;  
  
    if(pipe_write_fd != -1)  
    { 
      int type = 2; 
      res = write(pipe_write_fd, &type, sizeof(int));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write type on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      res = write(pipe_write_fd, &cmd, sizeof(int));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write error on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      res = write(pipe_write_fd, user_mode_time, sizeof(USER_MODE_TIME));  
      if(res == -1)  
      {  
        fprintf(stderr, "Write error on pipe\n");  
        exit(EXIT_FAILURE);  
      }
      if(print_debug)
      {
        printf("write cmd ok:%x\n", cmd);  
      }
      printf("write cmd ok:%x\n", cmd);
    }  
    else
    {
      printf("write aflcmd pipe_write_fd -1\n");
      sleep(1000);
      exit(EXIT_FAILURE);  
    }
} 

void write_aflcmd_complete(int cmd, USER_MODE_TIME *user_mode_time) 
{
  int count = 0;
  int not_ready = 1;
  while(not_ready)
  {
    write_aflcmd(cmd, user_mode_time);
    int is_loop_over = read_aflcmd();
    printf("read aflcmd:%d\n", is_loop_over);
    if(cmd == 0x10 && is_loop_over)
    {
      not_ready = 0;
    }
    else if(cmd == 0x20 && !is_loop_over)
    {
      not_ready = 0;
    }
    else
    {
      count++;
      not_ready = 1;
      printf("not ready:%d,%d\n", cmd, is_loop_over);
      if(count == 5)
      {
        sleep(100000);
      }
    }
  }
}





#ifdef SNAPSHOT_SYNC

char *phys_addr_stored_bitmap;
int syn_shmem_id = 0; 

#endif

#endif


#if defined(MAPPING_WITHOUT_FUZZ)
static void start_run(void) {
  if(run_time == 0)
  {
    run_time = 1;
    int cmd = 0x10;// start mem write callback
    USER_MODE_TIME user_mode_time;
    write_aflcmd_complete(cmd,  &user_mode_time);
    rcu_disable_atfork();
  }
 
}
#endif


#include <sys/shm.h>
#include "../../config.h"

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

extern void get_input(CPUState *env);
int fork_times = 0;
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(pc == afl_entry_point && fork_times==0) { \
      fork_times=1; \
      afl_setup(); \
      afl_forkserver(cpu); \
      get_input(cpu); \
    } \
    afl_maybe_log(pc); \
  } while (0)


#define AFL_QEMU_CPU_SNIPPET3 do { \
    if(pc == afl_entry_point && fork_times==0) { \
      fork_times=1; \
      start_run(); \
    } \
    afl_maybe_log(pc); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */


#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */
abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */
/* Set in the child process in forkserver mode: */

unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(abi_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

//TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

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
    afl_end_code   = (abi_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}




/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, new_status, t_fd[2];

    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

#ifdef MEM_MAPPING
      int cmd = 0x10;// start mem write callback
      USER_MODE_TIME user_mode_time;
      //write_aflcmd(cmd,  &user_mode_time);
      write_aflcmd_complete(cmd,  &user_mode_time);
//SHMAT
      //snapshot_shmem_start = shmat(snapshot_shmem_id, guest_base + 0x182000000 ,  1); //zyw 
      //snapshot_shmem_start = shmat(snapshot_shmem_id, 0x80200000 ,  0); //zyw 
      //snapshot_shmem_start = shmat(snapshot_shmem_id, NULL,  1); //zyw 

      //memset(snapshot_shmem_start, 0, 1024*1024*16); // oh, it takes lots of time here !!!!!!!!!!!!, the most time cost in user mode; memset 16M

      //snapshot_shmem_pt = snapshot_shmem_start + 8 * 0x1000;
      afl_fork_child = 1;
#endif

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      printf("new child:%d\n",getpid());
      //printf("*********t_fd:%d,%d,%d,%d\n", t_fd[0], t_fd[1], TSL_FD, FORKSRV_FD);
      return;

    }

    /* Parent. */
    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */
    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    new_status = WEXITSTATUS(status);//zyw
    printf("wait child:%d, status:%d,%d\n", child_pid, status, new_status); 
    if(new_status!=32)
    {
      if(status!=0)
      {
        exception_exit(new_status);
      }
    }
    if (write(FORKSRV_FD + 1, &new_status, 4) != 4) exit(7);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;
  //printf("%lx, %lx. %lx\n",afl_area_ptr, cur_loc ^ prev_loc, MAP_SIZE);
  //printf("%x", *(afl_area_ptr + (cur_loc ^ prev_loc)));
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

pthread_mutex_t *p_mutex_shared = NULL;
int shmid = -1;



void cross_process_mutex_first_init(void)
{
    key_t key_id = ftok(".", 1);
    //printf("???????????? key_id:%d\n", key_id);
    //shmid = shmget(key_id, sizeof(pthread_mutex_t), IPC_CREAT | IPC_EXCL | 0644);
    shmid = shmget(key_id, sizeof(pthread_mutex_t), IPC_CREAT );
    if (shmid < 0)
    {
        perror("shmget() create failed");
        sleep(1000); 
    }
    printf("shmget() create success, shmid is %d.\n", shmid);
 
    p_mutex_shared = shmat(shmid, NULL, 0);
    if (p_mutex_shared == (void *)-1)
    {
      shmctl(shmid, IPC_RMID, 0);
      perror("shmat() failed");
      sleep(1000); 
    }
    printf("shmat() success.\n");
 
    pthread_mutexattr_t mutextattr;
    pthread_mutexattr_init(&mutextattr);

    pthread_mutexattr_setpshared(&mutextattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(p_mutex_shared, &mutextattr);
}

void cross_process_mutex_init(void)
{
    key_t key_id = ftok(".", 1);
    shmid = shmget(key_id, 0, 0);
    if (shmid < 0)
    {
        perror("shmget() failed");
        sleep(1000); 
    }
    p_mutex_shared = shmat(shmid, NULL, 0);
    if (p_mutex_shared == NULL)
    {
        perror("shmat() failed");
        sleep(1000); 
    }
}


void cross_shamem_disconn(void)
{
    if (shmdt(p_mutex_shared) == -1)
    {
      printf("share mem disconnect");
    }
    p_mutex_shared = NULL;

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
      if(!if_page_pc(t.pc) && if_premap_page(t.pc))
      {
        pthread_mutex_lock(p_mutex_shared);
        //printf("afl_wait_tsl lock:%x\n",t.pc);
        tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
        //printf("afl_wait_tsl unlock\n");
        pthread_mutex_unlock(p_mutex_shared);
      }
      mmap_unlock();
      tb_unlock();
       
    }

  }

  close(fd);

}

target_ulong startTrace(target_ulong start, target_ulong end)
{
    afl_start_code = start;
    afl_end_code   = end;
    return 0;
}

