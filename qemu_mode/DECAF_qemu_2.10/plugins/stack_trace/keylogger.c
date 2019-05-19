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
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */

#include "qemu/osdep.h"
#include "cpu.h"

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "hookapi.h"
#include "DECAF_callback.h"

#include "utils/Output.h"
#include "function_map.h"
#include "vmi_callback.h"
#include "vmi_c_wrapper.h"
//basic stub for plugins
static plugin_interface_t keylogger_interface;
static int taint_key_enabled=0;

DECAF_Handle keystroke_cb_handle = DECAF_NULL_HANDLE;
DECAF_Handle handle_ins_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_read_taint_mem = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_begin_cb = DECAF_NULL_HANDLE;
FILE * keylogger_log=DECAF_NULL_HANDLE;

#define MAX_STACK_SIZE 5000
char modname_t[512];
char func_name_t[512];
uint32_t sys_call_ret_stack[MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[MAX_STACK_SIZE];
uint32_t cr3_stack[MAX_STACK_SIZE];
uint32_t stack_top = 0;
void check_call(DECAF_Callback_Params *param)
{
	CPUState *env=param->be.env;
	CPUArchState *mips_env = env->env_ptr;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;
	if(stack_top == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack,&sys_call_ret_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack,&sys_call_entry_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}

	//DECAF_read_mem(env,mips_env->active_tc.gpr[28],4,&sys_call_ret_stack[stack_top]);
	sys_call_entry_stack[stack_top] = pc;
	cr3_stack[stack_top] = cr3;
	stack_top++;




}
void check_ret(DECAF_Callback_Params *param)
{
	if(!stack_top)
		return;
	//if(param->be.next_pc == sys_call_ret_stack[stack_top-1])
	if(param->be.next_pc > 0x70000000 && param->be.next_pc < 0x90000000){
		//0x409ed4
		return;
	}
	if(param->be.next_pc == sys_call_entry_stack[stack_top-1])
	{
		//DECAF_printf("stack:%x\n", param->be.next_pc);
		stack_top--;
	}
	else{
		DECAF_printf("stack overflow:%x, %x, %d\n", param->be.next_pc, sys_call_entry_stack[stack_top-1], stack_top - 1);
		for(int i=0;i< stack_top;i++){
			DECAF_printf("%d:%x\n",i,sys_call_entry_stack[i]);
		}
		exit(32);
	}
}

static int main_start = 0;
void do_block_end_cb(DECAF_Callback_Params *param)
{

	unsigned char insn_buf[4];
	int is_call = 0, is_ret = 0;
	int b;
	target_ulong pgd = DECAF_getPGD(param->be.env);
	char cur_process[50];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 50, &pid);
	if(strcmp(cur_process, "httpd") == 0 && param->be.cur_pc < 0x70000000 && main_start == 1){
		//DECAF_printf("block end pc: %x\n", param->be.cur_pc);
		DECAF_read_mem(param->be.env,param->be.cur_pc - 4 ,sizeof(char)*4,insn_buf);
		if(insn_buf[0] == 9 && (insn_buf[1]&7) == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
			param->be.next_pc = param->be.cur_pc + 4;
			int jump_reg = (insn_buf[3] * 8) + (insn_buf[2]/32);
			int next_reg = insn_buf[1]/8;			
			
			int jump_value = ((CPUArchState *)param->be.env->env_ptr)->active_tc.gpr[25];
			if(next_reg == 31 && jump_value < 0x411910){
				// 0x42516c extern, 0x411910 mips.stub
				DECAF_printf("jalr ins:%x, next pc:%x, jalr reg:%d, jalr next reg:%d\n",param->be.cur_pc, param->be.next_pc, jump_reg, next_reg);
				is_call = 1;
			}
		}else if((insn_buf[3] & 252) == 12){
			param->be.next_pc = param->be.cur_pc + 4;
			DECAF_printf("jal ins:%x, next pc:%x\n",param->be.cur_pc, param->be.next_pc);
			is_call = 1;
		}else if((insn_buf[0] & 63) == 8 && insn_buf[1] == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
			int reg = (insn_buf[3] *8) + (insn_buf[2]/32);
			
			if(reg == 31){ 
				//jr $ra, not jr other(such as jr $t9, jump at the end of function)	
				DECAF_printf("jr ins:%x, next pc:%x, jr reg:%d\n",param->be.cur_pc, param->be.next_pc, reg);		
				is_ret = 1;
			}
			else if(reg == 25){
				//jr $ra happens in lib function
				stack_top --;
			}	
		}
		if (is_call)
		check_call(param);
		else if (is_ret)
		check_ret(param);
	}

}

void do_block_begin_cb(DECAF_Callback_Params *param)
{
	

	unsigned char insn_buf[2];
	int is_call = 0, is_ret = 0;
	int b;
	target_ulong cr3 = DECAF_getPGD(param->bb.env);
	char cur_process[50];
	int pid;
	VMI_find_process_by_cr3_c(cr3, cur_process, 50, &pid);
	//DECAF_printf("process pid:%d, name:%s\n",pid, cur_process);

	if(strcmp(cur_process, "httpd") == 0){
		target_ulong pc = param->bb.tb->pc;
		if(pc == 0x40a218){
			DECAF_printf("main start\n");
			main_start = 1;		
}

void tracing_insn_end(DECAF_Callback_Params *param)
{
/*
	unsigned char insn_buf[4];
	int is_call = 0, is_ret = 0;
	int b;
	target_ulong pgd = DECAF_getPGD(param->ie.env);
	char cur_process[50];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 50, &pid);
	//DECAF_printf("process pid:%d, name:%s\n",pid, cur_process);
	CPUState * cpu = param->ie.env;
	CPUArchState *cpu_env = cpu->env_ptr;
	if(strcmp(cur_process, "httpd") == 0 && cpu_env->current_tc < 0x70000000){
		DECAF_read_mem(param->ie.env,cpu_env->current_tc,sizeof(char)*4,insn_buf);
		//DECAF_printf("insn:%x\n",insn_buf[0] & 63);
		if(insn_buf[0] == 9 && (insn_buf[1]&7) == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
			DECAF_printf("jalr ins:%x\n",cpu_env->current_tc);
			is_call = 1;
		}else if((insn_buf[3] & 252) == 12){
			DECAF_printf("jal ins:%x\n",cpu_env->current_tc);
			is_call = 1;
		}else if((insn_buf[0] & 63) == 8 && insn_buf[1] == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
			DECAF_printf("jr ins:%x\n",cpu_env->current_tc);
			is_ret = 1;
		}
		if (is_call)
		check_call(param);
		else if (is_ret)
		check_ret(param);
	}
*/
}

void keylogger_cleanup()
{
/*
	  if(keylogger_log)
			fclose(keylogger_log);
		if(handle_read_taint_mem)
			DECAF_unregister_callback(DECAF_READ_TAINTMEM_CB,handle_read_taint_mem);
		if(handle_write_taint_mem)
			DECAF_unregister_callback(DECAF_WRITE_TAINTMEM_CB,handle_write_taint_mem);
		if(handle_block_end_cb)
			DECAF_unregisterOptimizedBlockEndCallback(handle_block_end_cb);
		handle_read_taint_mem = DECAF_NULL_HANDLE;
		handle_write_taint_mem = DECAF_NULL_HANDLE;
		keylogger_log = NULL;
		handle_block_end_cb = DECAF_NULL_HANDLE;
*/
}

void do_track_stack( Monitor *mon, const QDict *qdict)
{
	DECAF_printf("stack track start \n");
	if(!handle_block_end_cb)
		handle_block_end_cb =  DECAF_registerOptimizedBlockEndCallback(
				&do_block_end_cb, NULL, INV_ADDR, INV_ADDR);
	if(!handle_block_begin_cb)
		handle_block_begin_cb =  DECAF_registerOptimizedBlockBeginCallback(
				&do_block_begin_cb, NULL, INV_ADDR, INV_ADDR);
	if(!handle_ins_end_cb)
		handle_ins_end_cb = DECAF_register_callback(
				DECAF_INSN_END_CB, tracing_insn_end, NULL);

}

static int init(){

}
static mon_cmd_t keylogger_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	DECAF_output_init(NULL);
	DECAF_printf("start\n");
	keylogger_interface.mon_cmds = keylogger_term_cmds;
	keylogger_interface.plugin_cleanup = &keylogger_cleanup;

	//initialize the plugin
	return (&keylogger_interface);
}

