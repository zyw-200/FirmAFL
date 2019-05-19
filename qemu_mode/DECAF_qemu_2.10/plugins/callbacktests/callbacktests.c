/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Lok Yan
 * @date Oct 18 2012
 */
#include "zyw_config1.h"
#include "zyw_config2.h"
#include "qemu/osdep.h"
#include "cpu.h"

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"

//http socket
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/time.h>
#include "function_map.h"
 

#ifdef STORE_PAGE_FUNC

int in_httpd = 0;
struct timeval store_page_start;
struct timeval store_page_end;
double full_store_page_time;
#endif

#define MAX_STACK_SIZE 5000
uint32_t sys_call_ret_stack[2][MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[2][MAX_STACK_SIZE];
uint32_t cr3_stack[2][MAX_STACK_SIZE];
uint32_t stack_top[2];




static struct timeval tv_api;
static char old_api[100];
static float sec_delta = 0.0;

//basic stub for plugins

char * VMI_find_process_name_by_pgd(uint32_t pgd);

static plugin_interface_t callbacktests_interface;
static int bVerboseTest = 0;
static int enableTimer = 0;
static int afl_begin = 0;
static int afl_fork = 0;
//static char *current_data = NULL;
static int rest_len = 0;
static int network_read_block = 0;
static int open_block = 0;
static int accept_block = 0;
static int current_fd = 0;
static int write_fd = 0;
static int start_debug = 0;
static int tmp_pc = 0;
static int httpd_pid[100]; //httpd will fork itself
static int current_pid = 0;
static char current_program[50];
static int pid_index = 0;
static target_ulong kernel_sp = 0;
static int run_test = 0;
static int http_request = 0;
static int main_start = 0;


static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_end_handle = DECAF_NULL_HANDLE;
static DECAF_Handle mem_write_cb_handle = DECAF_NULL_HANDLE;
#define PRO_MAX_NUM 10
static char targetname[PRO_MAX_NUM][512];// 10 program, such as httpd, hedwig.cig
static uint32_t targetcr3[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static uint32_t targetpid[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static int target_main_address[PRO_MAX_NUM];

static int target_index = 0; //the number of target program

int first_pgd = 0;

target_ulong program_pgd[100];
int pgd_index = -1;

void pgd_push(target_ulong pgd)
{
	pgd_index++;
	program_pgd[pgd_index] = pgd;

}

target_ulong pgd_pop()
{
	target_ulong pgd =  program_pgd[pgd_index];
	pgd_index--;
	return pgd;
}

target_ulong get_current_pgd()
{	
	if(pgd_index==-1)
	{
		return 0xffffffff;
	}
	else
	{
		return program_pgd[pgd_index];
	}
	
}



int target_exist(char *name){
	for(int i=0; i<target_index; i++){
		if (strcmp(targetname[i], name) == 0){
			return i;
		}
	}
	return -1;
}

int targetpid_exist(uint32_t pid){
	for(int i=0; i<target_index; i++){
		if (pid == targetpid[i]){
			return i;
		}
	}
	return -1;
}

int targetcr3_exist(uint32_t cr3){
	for(int i=0; i<target_index; i++){
		if (cr3 == targetcr3[i]){
			return i;
		}
	}
	return -1;
}

static void runTests(void);

static void callbacktests_printSummary(void);
static void callbacktests_resetTests(void);


static int count = 0;
static int poll = 0;
static int api_time = 0;


static plugin_interface_t keylogger_interface;

DECAF_Handle handle_ins_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_begin_cb = DECAF_NULL_HANDLE;
FILE * keylogger_log=DECAF_NULL_HANDLE;

#define MAX_STACK_SIZE 5000
char modname_t[512];
char func_name_t[512];


void check_call(DECAF_Callback_Params *param, int index)
{
	//DECAF_printf("check_call:%d\n", index);
	CPUState *env=param->be.env;
	CPUArchState *mips_env = env->env_ptr;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;
	if(stack_top[index] == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack[index],&sys_call_ret_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack[index],&sys_call_entry_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top[index] = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}

	//DECAF_read_mem(env,mips_env->active_tc.gpr[28],4,&sys_call_ret_stack[stack_top]);
	sys_call_entry_stack[index][stack_top[index]] = pc;
	cr3_stack[index][stack_top[index]] = cr3;
	stack_top[index]++;




}


void check_ret(DECAF_Callback_Params *param, int index)
{
	//DECAF_printf("check_ret:%d\n", index);
	if(!stack_top[index])
		return;
	if(stack_top[index] > 0){
		if(param->be.next_pc == sys_call_entry_stack[index][stack_top[index]-1])
		{
			stack_top[index]--;
		}
		else if(param->be.next_pc > 0x80000000){
			DECAF_printf("jump into kernel, maybe not overflow\n");
		} 
		else{
			DECAF_printf("stack overflow(%d):%x, %x, %d\n", index, param->be.next_pc, sys_call_entry_stack[index][stack_top[index]-1], stack_top[index] - 1);

			for(int i=0;i< stack_top[index];i++){
				DECAF_printf("%d:%x\n",i,sys_call_entry_stack[index][i]);
				sleep(10000);
			}
			//DECAF_printf("checke ret done work\n");
			//snapshot_endWork(32);
			//endWork(32);
			//doneWork(32);
		}
	}
	
}



extern int afl_user_fork;
extern struct timeval loop_begin;
extern struct timeval loop_end;
extern struct timeval restore_begin;
extern struct timeval restore_end;
extern int into_syscall;
target_ulong feed_input_addr = 0;
int feed_input_time = 0;

extern int libuclibc_addr;
static void do_block_begin(DECAF_Callback_Params* param)
{
	CPUState *cpu = param->bb.env;
	CPUArchState *env = cpu->env_ptr;
	target_ulong pc = param->bb.tb->pc;
#ifdef TARGET_MIPS
	target_ulong ra = env->active_tc.gpr[31];
#elif defined(TARGET_ARM)
	target_ulong ra = 0;
#endif


#ifdef SNAPSHOT_SYNC
	if(afl_user_fork)
	{
		target_ulong pgd = DECAF_getPGD(cpu);
		if(pgd == httpd_pgd)
		{
			in_httpd = 1;
		}
		else
		{
			in_httpd = 0;
		}
	}
#endif
#ifdef TARGET_MIPS
	/*
	if(afl_user_fork && (pc == 0x8018da50 || pc == 0x8018dc38))
    {
    	DECAF_printf("do_sys_open : %x\n", pc);
    	if(pc == 0x8018da50)
    	{
    		char name[100];
    		DECAF_read_mem(cpu, env->active_tc.gpr[5], 100, name);
    		DECAF_printf("do_sys_open: %s\n", name);
    	}
    }

    else if(afl_user_fork && (pc == 0x8019bb4c || pc == 0x8019bbd8))
    {
    	DECAF_printf("do_filp_open : %x\n", pc);
    	if(pc == 0x8019bb4c)
    	{
    		char name[100];
    		DECAF_read_mem(cpu, env->active_tc.gpr[5], 100, name);
    		DECAF_printf("do_flip_open: %s\n", name);
    	}
    }

    else if(afl_user_fork && (pc == 0x8019b6e0 || pc == 0x8019ba68))
    {
    	DECAF_printf("path_openat : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x8019ae08 || pc == 0x8019b57c))
    {
    	DECAF_printf("do_last_isra_37 : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x80197ecc || pc == 0x8019825c))
    {
    	DECAF_printf("do_lookup : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x80197c1c))
    {
    	DECAF_printf("not to d_alloc_and_lookup : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x80197bb0 || pc == 0x80197c34))
    {
    	DECAF_printf("d_alloc_and_lookup : %x\n", pc);
    	
    }
    else if(afl_user_fork && pc == 0x80197be8)
	{
		int next_addr;
    	int addr2;
    	int addr1 = env->active_tc.gpr[17] + 0x10;
    	DECAF_read_ptr(cpu, addr1, &addr2);
    	DECAF_read_ptr(cpu, addr2, &next_addr);
    	DECAF_printf("d_alloc_and_lookup ########next addr %x, %x,%x\n", addr1, addr2, next_addr);
	}

    else if(afl_user_fork && (pc == 0x801a1ee0 || pc == 0x801a1f38))
    {
    	DECAF_printf("d_alloc : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801a1c10 || pc == 0x801a1d4c))
    {
    	DECAF_printf("__d_alloc : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801ff554 || pc == 0x801ff5f8))
    {
    	DECAF_printf("ext2_lookup : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801fe0f4 || pc == 0x801fe6b0))
    {
    	DECAF_printf("ext2_iget : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801fd750 || pc == 0x801fd8f0))
    {
    	DECAF_printf("ext2_get_inode : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801b6a90 || pc == 0x801b6b7c))
    {
    	DECAF_printf("_bread : %x\n", pc);
    }
    
    else if(afl_user_fork && (pc == 0x801b44bc))
    {
    	DECAF_printf("wait_on_buffer : %x\n", pc);
    }

    else if(afl_user_fork && (pc == 0x801b44d0))
    {
    	DECAF_printf("buffer locked then sleep on : %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x805709a0 && pc <= 0x80570a24))
    {
    	DECAF_printf("out of line wait on bit : %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x805708b8 && pc <= 0x8057099c))
    {
    	DECAF_printf("wait on bit : %x\n", pc);
    }
    else if(afl_user_fork && (pc == 0x801b441c))
    {
    	DECAF_printf("sleep_on_buffer : %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x8057049c && pc <= 0x8057052c))
    {
    	DECAF_printf("io_schedule : %x\n", pc);
    }
	if(afl_user_fork && pc > tmp_libuclibc_addr && pc  < tmp_libuclibc_addr + 0x60000)
	{
		DECAF_printf("lib pc: %x\n", pc - tmp_libuclibc_addr);
	}
    else if(afl_user_fork && (pc >= 0x80128264 && pc <= 0x80128348))
    {
    	DECAF_printf("sys_wait4 : %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x80127288 && pc <= 0x80127448))
    {
    	DECAF_printf("do_wait : %x\n", pc);
    }
  	else if(afl_user_fork && (pc >= 0x80570fbc && pc <= 0x805710c8))
    {
    	DECAF_printf("do_nanosleep : %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x80143234 && pc <= 0x8014336c))
    {
    	DECAF_printf("hrtimer_nanosleep: %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x80143370 && pc <= 0x801433ec))
    {
    	DECAF_printf("sys_nanosleep: %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x80570434 && pc <= 0x8057049c))
    {
    	DECAF_printf("schedule: %x\n", pc);
    }
    else if(afl_user_fork && (pc >= 0x8056f6ec && pc <= 0x80570384))
    {
    	DECAF_printf("__schedule: %x\n", pc);
    }
	
    if(afl_user_fork && pc == 0x8057035c)
    {
    	DECAF_printf("########__schedule next pc %x\n", env->active_tc.gpr[31]);
    }
    if(afl_user_fork && pc == 0x801037bc)
    {
    	DECAF_printf("TIF_NEED_RESCHED set\n", pc);
    }
     if(afl_user_fork && pc == 0x80103794)
    {
    	DECAF_printf("TIF_NEED_RESCHED not set\n", pc);
    }
    */	
 #endif   
	return;
	target_ulong pgd = DECAF_getPGD(param->bb.env);
	int index = targetcr3_exist(pgd);
	char cur_process[512];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 512, &pid);
	if(index == -1)
	{
		int index = target_exist(cur_process);
		if(index != -1)
		{
			targetcr3[index] = pgd;
			targetpid[index] = pid;
#ifdef STORE_PAGE_FUNC
			in_httpd = 1;
#endif
		}
		else{
#ifdef STORE_PAGE_FUNC
			in_httpd = 0;
#endif
			return;
		}
	}
	else{
		index = target_exist(cur_process); //sometimes the pgd of child program is the same as parent program. need to recalculate the index
		if(index == -1) 
		{
#ifdef STORE_PAGE_FUNC
			in_httpd = 0;
#endif
			return; // cur_process is null, pid is 0
		}
	}

#ifdef STORE_PAGE_FUNC
	in_httpd = 1;
#endif
	
	char modname[512];
	char functionname[512];


	if(pc > 0x80000000)	
		return;

//feed input
/*
	if(cpu->active_tc.PC == 0x407d10)// cgibin after getenv HTTP_COOKIE
	{
		DECAF_printf("afl_user_fork:%d\n",afl_user_fork);
		feed_input_addr = cpu->active_tc.gpr[2];
		DECAF_printf("feed_input_addr:%lx\n", feed_input_addr);

		char modname[512];
		char functionname[512];
		//funcmap_get_name_c(pc, pgd, &modname, &functionname);
	}

	if(afl_user_fork && feed_input_time == 0)
	{
		feed_input_time = 1;
		//DECAF_printf("fork already,feed input\n");
		char buf[500];
		int len = getWork(cpu, buf, 500);
		//DECAF_printf("Buf:%d, %s\n", len, buf);
		cpu_memory_rw_debug(param->bb.env, feed_input_addr, buf, len, 1);

	}
*/
//

/*
	if(pc == start_fork_pc && afl_user_fork == 0 && fork_times == 0) //cgibin main)
	{

		startTrace(cpu, 0x400000L, 0x500000L);
		fork_times = 1;

#ifndef NO_FORKSERVER
#ifdef QEMU_SNAPSHOT
		startQemusnapshot(cpu, enableTimer);
#else
		DECAF_printf("ready to fork:%x\n", pgd);
		startForkserver(cpu, enableTimer);
#endif
#else
		startnoForkserver(cpu, enableTimer);
#endif
	}
*/


}

static void do_block_end(DECAF_Callback_Params* param){	

	return;
	CPUArchState *cpu = param->be.env->env_ptr;
	target_ulong pc = param->be.cur_pc;
	target_ulong bk_pc = param->be.tb->pc;
	target_ulong pgd = DECAF_getPGD(param->be.env);
	int index = targetcr3_exist(pgd);
	char cur_process[512];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 512, &pid);
	if(index == -1)
	{
		index = target_exist(cur_process);
		if(index != -1)
		{
			targetcr3[index] = pgd;
			targetpid[index] = pid;
		}
		else{
			return;
		}
	}
	else{
		index = target_exist(cur_process); //sometimes the pgd of child program is the same as parent program. need to recalculate the index
		if(index == -1) return; // cur_process is null, pid is 0
	}

	if(pc > 0x80000000)
		return;


//NEED CHANGE
	if(index == 1){

		if(pc >= 0x419470 && pc <= 0x41991c) //.MIPS.stubs for hedwig.cgi(cgibin)
			return;
	}
	if(index == 0){
		if(pc >= 0x411910 && pc <= 0x411f7c)//.MIPS.stubs for httpd
			return;
	}

//

	unsigned char insn_buf[4];
	int is_call = 0, is_ret = 0;

	DECAF_read_mem(param->be.env,pc - 4 ,sizeof(char)*4,insn_buf);
	if(insn_buf[0] == 9 && (insn_buf[1]&7) == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){ //jalr
		param->be.next_pc = param->be.cur_pc + 4;
		int jump_reg = (insn_buf[3] * 8) + (insn_buf[2]/32);
		int next_reg = insn_buf[1]/8;			
		
		int jump_addr = cpu->active_tc.gpr[jump_reg];
		if(jump_addr > 0x80000000)
			return;
		
		int jump_value = ((CPUArchState *)param->be.env->env_ptr)->active_tc.gpr[25];
		//DECAF_printf("jalr ins:%x, next pc:%x, jalr reg:%d, jalr next reg:%d\n",param->be.cur_pc, param->be.next_pc, jump_reg, next_reg);
		if(next_reg == 31){
			is_call = 1;
		}
	}else if((insn_buf[3] & 252) == 12){ //jal
		param->be.next_pc = param->be.cur_pc + 4;
		int jump_addr = insn_buf[0] + insn_buf[1]*256 + insn_buf[2]* 256*256;
		if(jump_addr > 0x80000000)
			//DECAF_printf("jal:%x\n", jump_addr);
			return;
		//DECAF_printf("jal ins:%x, next pc:%x\n",param->be.cur_pc, param->be.next_pc);
		is_call = 1;
	}else if((insn_buf[0] & 63) == 8 && insn_buf[1] == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
		int reg = (insn_buf[3] *8) + (insn_buf[2]/32);
		if(reg == 31){ 
			//jr $ra, not jr other(such as jr $t9, jump at the end of function)
			int jump_addr = cpu->active_tc.gpr[reg];
			if(jump_addr > 0x80000000)
				return;	
			//DECAF_printf("jr ins:%x, next pc:%x, jr reg:%d\n",param->be.cur_pc, param->be.next_pc, reg);	
			is_ret = 1;
		}
		else if(reg == 25){
			//jr $ra happens in lib function
			//if(param->be.cur_pc < 0x70000000){
			//DECAF_printf("jr ins:%x, next pc:%x, jr reg:%d\n",param->be.cur_pc, param->be.next_pc, reg);
			//}



/*
			if(stack_top > 0){
				stack_top --;
			}
*/
		}	
	}else if((insn_buf[3] == 0x04) && (insn_buf[2] == 0x11)){ //bal;
		param->be.next_pc = param->be.cur_pc + 4;
		int offset = insn_buf[1] * 1024 + insn_buf[0] * 4;
		int jump_addr =  param->be.cur_pc + offset;
		if(jump_addr > 0x80000000)
			//DECAF_printf("jal:%x\n", jump_addr);
			return;
		if(offset <= 4) //bal the next pc
			return;
		//DECAF_printf("bal ins:%x, next pc:%x, jmp pc:%x\n",param->be.cur_pc, param->be.next_pc, offset);
		is_call = 1;	
	}

	//if (is_call)
	//check_call(param, index);
	//else if (is_ret)
	//check_ret(param, index);

}

int data_length(unsigned long value)
{
    int data_len = 0; //byte
    if((value & 0xffffff00) == 0)
    {
        data_len = 1;
    }
    else if((value & 0xffff0000) == 0)
    {
        data_len = 2;
    }
    else
    {
        data_len = 4;
    }
    return data_len;    
}


int phys_addr_stored[1000]; 
int phys_addr_stored_index = 0;

int serach_phys_addr(int phys_addr)
{
    for(int i=0; i< phys_addr_stored_index; i++)
    {
        if(phys_addr_stored[i] == phys_addr)
        {
            return i;
        }
    }
    return -1;
}

int add_and_show(int phys_addr)
{
    int index = serach_phys_addr(phys_addr);
    if(index == -1)
    {
        phys_addr_stored[phys_addr_stored_index] = phys_addr;
        phys_addr_stored_index++;
        printf("physical:%x\n", phys_addr);
    }
}


#ifdef STORE_PAGE_FUNC


static void fuzz_mem_write(DECAF_Callback_Params *dcp)
{
	if(afl_user_fork == 1)
	{
		uint32_t next_page = 0;
		uint32_t virt_addr = dcp->mw.vaddr;
		uint32_t phys_addr = dcp->mw.paddr; 
		uintptr_t host_addr = dcp->mw.haddr; //64bit
		int dt = dcp->mw.dt;
		unsigned long value = dcp->mw.value;
		uintptr_t page_host_addr = host_addr & 0xfffffffffffff000;
		int dl = data_length(value);
		if(dl>0x1000)
		{
			printf("data too long, cross page\n");
			exit(32);
		}
		if ((virt_addr & 0xfff) + dl > 0x1000)
	    { 
	        DECAF_printf("cross page:%lx, len:%d\n\n\n\n\n", virt_addr, dl);
	        next_page = (virt_addr & 0xfffff000) + 0x1000;
	        //exit(32);
	       	
	    } 
// memory consistence
#ifdef SNAPSHOT_SYNC
	    if(in_httpd && (virt_addr<0x80000000))
	    {

	    	int ifexist = if_physical_exist(phys_addr & 0xfffff000);
	    	if(ifexist)
	    	{
	    		return;
	    	}
	    	add_physical_page(phys_addr & 0xfffff000);
	    }
#endif
	    gettimeofday(&store_page_start, NULL);
	    //if(virt_addr > 0x80000000)
	    	//DECAF_printf("@@@@@@@@@@@@@@@@ fuzz_mem_write %x\n", virt_addr);
		store_page(virt_addr & 0xfffff000, page_host_addr, in_httpd); //in
		gettimeofday(&store_page_end, NULL);
    	full_store_page_time += (double)store_page_end.tv_sec - store_page_start.tv_sec + (store_page_end.tv_usec - store_page_start.tv_usec)/1000000.0;


	}

}
#endif


void do_callbacktests(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
  {
 
    strncpy(targetname[target_index], qdict_get_str(qdict, "procname"), 512);
    targetname[target_index][511] = '\0';
    target_index++;
  }
}


static void callbacktests_loadmainmodule_callback(VMI_Callback_Params* params)
{
	char procname[64];
	uint32_t pid;
	if (params == NULL)
	{
		return;
	}
	VMI_find_process_by_cr3_c(params->cp.cr3, procname, 64, &pid);

	if (pid == (uint32_t)(-1))
	{
		return;
	}
	//int index = target_exist(procname);
	//if (index != -1)
	if(strcmp(procname,program_analysis) == 0)
	{
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x start, time:%d,%d\n",procname, index, pid, params->cp.cr3, tv_api.tv_sec, tv_api.tv_usec);
		//targetpid[index] = pid;
		//targetcr3[index] = params->cp.cr3;

/*
		if(strcmp(procname,program_analysis) == 0 && first_pgd == 0)
		{  

			if(first_or_new_pgd == 0) 
				first_pgd = 1; 
#ifdef multiple_process
			else 
				first_or_new_pgd--;
#endif
			httpd_pgd = targetcr3[index]; 
		}
*/
		
		pgd_push(params->cp.cr3);
		httpd_pgd = get_current_pgd();
		DECAF_printf("cur pgd:%x\n", httpd_pgd);


	}
}

static void callbacktests_removeproc_callback(VMI_Callback_Params* params)
{

  	char procname[64];
	uint32_t pid;

	if (params == NULL)
	{
		return;
	}
	VMI_find_process_by_cr3_c(params->rp.cr3, procname, 64, &pid);
	
	if (pid == (uint32_t)(-1))
	{
		return;
	}
	//int index = target_exist(procname);
	//if (index != -1)
	if(strcmp(procname,program_analysis) == 0)
	{
		//stack_top[index] = 0; //??????????????????????????? http end
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x end, time:%d,%d\n",procname, index, pid, params->rp.cr3,  tv_api.tv_sec, tv_api.tv_usec);
		//targetpid[index] = 0;
		//targetcr3[index] = 0;

		target_ulong tmp_pgd = pgd_pop();
		assert(tmp_pgd==params->rp.cr3);
		httpd_pgd = get_current_pgd();
		DECAF_printf("cur pgd:%x\n", httpd_pgd);

	}

	

	//unregister the callback FIRST before getting the time of day - so
	// we don't get any unnecessary callbacks (although we shouldn't
	// since the guest should be paused.... right?)
/*
	DECAF_printf("unregister handle %x\n", callbacktests[index].handle);
	DECAF_unregister_callback(callbacktests[index].cbtype, callbacktests[index].handle);
	callbacktests[index].handle = DECAF_NULL_HANDLE;
	DECAF_printf("Callback Count = %u\n", callbacktests[index].count);

	gettimeofday(&callbacktests[index].tock, NULL);

	elapsedtime = (double)callbacktests[index].tock.tv_sec + ((double)callbacktests[index].tock.tv_usec / 1000000.0);
	elapsedtime -= ((double)callbacktests[index].tick.tv_sec + ((double)callbacktests[index].tick.tv_usec / 1000000.0));
	DECAF_printf("Process [%s] with pid [%d] ended at %u:%u\n", callbacktests[index].name, params->rp.pid, callbacktests[index].tock.tv_sec, callbacktests[index].tock.tv_usec);
	DECAF_printf("  Elapsed time = %0.6f seconds\n\n", elapsedtime);
*/
}

static int callbacktests_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");
	program_start = 1;

	target_main_address[0] = 0x40a218; //httpd
	target_main_address[1] = 0x4023e0; //hedwig.cgi
	stack_top[0] = 0;
	stack_top[1] = 0;

	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &callbacktests_loadmainmodule_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB, &callbacktests_removeproc_callback, NULL);
	block_begin_handle = DECAF_registerOptimizedBlockBeginCallback(&do_block_begin, NULL, INV_ADDR, OCB_ALL);
	block_end_handle = DECAF_registerOptimizedBlockEndCallback(&do_block_end, NULL, INV_ADDR, INV_ADDR);
#ifdef STORE_PAGE_FUNC
	mem_write_cb_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,fuzz_mem_write,NULL);
#endif					
	for(int i = 0; i < PRO_MAX_NUM; i++){	
		targetcr3[i] = 0;
		targetpid[i] = 0;
		targetname[i][0] = '\0';
	}
  	return (0);
}


static void callbacktests_cleanup(void)
{
  VMI_Callback_Params params;

  DECAF_printf("Bye world\n");

  if (processbegin_handle != DECAF_NULL_HANDLE)
  {
    VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
    processbegin_handle = DECAF_NULL_HANDLE;
  }

  if (removeproc_handle != DECAF_NULL_HANDLE)
  {
    VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
    removeproc_handle = DECAF_NULL_HANDLE;
  }

  //make one final call to removeproc to finish any currently running tests
  if (targetpid != (uint32_t)(-1))
  {
    params.rp.pid = targetpid;
    callbacktests_removeproc_callback(&params);
  }
}

#ifdef __cplusplus
extern "C"
{
#endif

static mon_cmd_t callbacktests_term_cmds[] = {
  #include "plugin_cmds.h"
  {NULL, NULL, },
};

#ifdef __cplusplus
}
#endif


plugin_interface_t* init_plugin(void)
{
  callbacktests_interface.mon_cmds = callbacktests_term_cmds;
  callbacktests_interface.plugin_cleanup = &callbacktests_cleanup;
  //initialize the plugin
  callbacktests_init();
  return (&callbacktests_interface);
}

