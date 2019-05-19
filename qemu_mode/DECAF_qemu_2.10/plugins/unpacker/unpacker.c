/*
 Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

 DECAF is based on QEMU, a whole-system emulator. You can redistribute
 and modify it under the terms of the GNU GPL, version 3 or later,
 but it is made available WITHOUT ANY WARRANTY. See the top-level
 README file for more details.

 For more information about DECAF and other softwares, see our
 web site at:
 http://sycurelab.ecs.syr.edu/

 If you have any questions about DECAF,please post it on
 http://code.google.com/p/decaf-platform/
 */

#include "qemu/osdep.h"
#include "cpu.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "config.h"

#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_target.h"
//change end
//#include "shared/read_linux.h"
//#include "shared/VMI.h"
#include "shared/vmi_callback.h"
#include "shared/hookapi.h"
#include "unpacker.h"
#include "mem_mark.h"

//zyw
#include <libxml/parser.h>
#include <netinet/in.h>

#define size_to_mask(size) ((1u << (size)) - 1u) //size<=4
static plugin_interface_t unpacker_interface;
//change begin
/* Callback handles */
DECAF_Handle block_begin_cb_handle = 0;
DECAF_Handle insn_end_cb_handle = 0;
DECAF_Handle mem_write_cb_handle=0;
DECAF_Handle proc_loadmodule_cb_handle=0;
DECAF_Handle proc_loadmainmodule_cb_handle=0;
DECAF_Handle proc_processend_cb_handle=0;

DECAF_Handle virus_block_begin_cb_handle = 0;
//change end
static FILE *unpacker_log = NULL;

char *syscall_name[1000];


static int max_rounds = 100;
static int cur_version = 1;
target_ulong unpack_cr3 = 0;
target_ulong virus_cr3 = 0;
char unpack_basename[256] = "";
char virus_basename[256] = "";
clock_t start;
uint32_t monitored_pid = 0;

//change to
static mon_cmd_t unpacker_term_cmds[] = {
		{
				.name="set_max_unpack_rounds",
				.args_type="rounds:i",
				.cmd=do_set_max_unpack_rounds,
				.params="rounds",
				.help="Set the maximum unpacking rounds (100 by default)",
		},
		{
				.name="trace_by_name",
				.args_type="filename:s",
				.cmd=do_trace_process,
				.params="filename",
				.help="specify the process name",

		},
		{
				.name="stop_unpack",
				.args_type="",
				.cmd=do_stop_unpack,
				.params="",
				.help="Stop the unpacking process",

		},
		{
				.name="linux_ps",
				.args_type="",
				.cmd=do_linux_ps,
				.params="",
				.help="List the processes on linux guest system",

		},
		{
				.name="guest_ps",
				.args_type="",
				.cmd=do_guest_procs,
				.params="",
				.help="List the processes on guest system",

		},
};
void do_set_max_unpack_rounds(Monitor *mon, const QDict *qdict)
{
	const int rounds=qdict_get_int(qdict,"rounds");
	  if (rounds <= 0) {
	    DECAF_printf("Unpack rounds has to be greater than 0!\n");
	    return;
	  }
	  max_rounds = rounds;
}
//static inline const char *get_basename(const char *path)
static inline const char *get_basename(const char *path)
{
  int i = strlen(path) - 1;
  for (; i >= 0; i--)
    if (path[i] == '/')
      return &path[i + 1];
  return path;
}
void do_trace_process(Monitor *mon, const QDict *qdict)
{
	const char *filename=qdict_get_str(qdict,"filename");
	const char *basename=get_basename(filename);
	if(!basename){
		DECAF_printf("cannot get basename\n");
		return;
	}
	strncpy(unpack_basename,filename,256);
	unpack_basename[255]='\0';
	DECAF_printf("Waiting for process %s(case sensitive to start)\n",unpack_basename);
	return;

}
void do_stop_unpack(Monitor *mon, const QDict *qdict)
{
	  unpack_cr3 = 0;
	  unpack_basename[0] = 0;
	  //For DECAF taint check need to be completed
	  //  mem_mark_cleanup();
	  cur_version = 1;
}
void do_linux_ps(Monitor *mon, const QDict *qdict)
{

}
void do_guest_procs(Monitor *mon, const QDict *qdict)
{

}

//end change




/*
	1. Search backward of virtual address from EIP for clean pages, and dump them
	2. Search forward of virtual address from EIP for clean pages, and dump them
	3. Search stops when we meet a clean page or all tainted bytes are already dumpped
	4. When dump a page, set "dumpped" flag to 1
*/
//will change it !!!!!!!!!!!!!!!!!!!!!!
static void dump_unpacked_code()
{
  uint32_t start_va, end_va, i, j, eip, cr3;
  uint8_t buf[TARGET_PAGE_SIZE];
  char filename[128];
  taint_record_t records[4];

  eip = DECAF_getPC(current_cpu);
  cr3 = DECAF_getPGD(current_cpu);

  //we just dump one page
  start_va = (eip & TARGET_PAGE_MASK);
  end_va = start_va + TARGET_PAGE_SIZE;
  sprintf(filename, "dump-%d-%08x-%08x-%08x.bin\n", cur_version, eip, start_va, end_va + TARGET_PAGE_SIZE - 1);
  FILE *fp = fopen(filename, "wb");
  assert(fp);

  for (i = 0; i < 4; i++) {
    records[i].version = cur_version;
  }

  for (i = start_va; i < end_va; i += TARGET_PAGE_SIZE) {
    bzero(buf, sizeof(buf));
    for (j = 0; j < TARGET_PAGE_SIZE; j+=4) {
    	set_mem_mark(i+j,4,0);
    	//taintcheck_taint_virtmem(i+j, 4, 0, records);//Need change for DECAF
    }
    if(DECAF_memory_rw(NULL,i,buf,TARGET_PAGE_SIZE,0)<0)
    	DECAF_printf("Cannot dump this page %08x!!! \n", i);
    else
    	fwrite(buf, TARGET_PAGE_SIZE, 1, fp);
  }
  fclose(fp);
  DECAF_printf("dump over\n");
  // printf("OK after taintcheck_taint_virtmem()\n");
}

int inContext = 0;
int memory_write = 0;
static void unpacker_insn_begin(DECAF_Callback_Params * dcp)
{

	CPUState *env = dcp->ie.env;
	uint32_t eip, cr3; 
	if(unpack_basename[0] == '\0' && virus_basename[0] == '\0')
		return ;

	cr3 = DECAF_getPGD(env);

	inContext = (unpack_cr3 == cr3 || virus_cr3 == cr3) && (!DECAF_is_in_kernel(env)); 
	//inContext = (virus_cr3 == cr3 ) && (!DECAF_is_in_kernel(env)); 
	if (!inContext)
		return ;
	eip = ((CPUArchState *)env->env_ptr)->current_tc;
	if(eip == 0x409070){
		//DECAF_printf("insn_begin:%x\n", eip);
	}
/*
	char tmpcurrent_proc[256];
	memset(tmpcurrent_proc, 0, 256 * sizeof(char));
	uint32_t tmppid;
	VMI_find_process_by_cr3_c(cr3, tmpcurrent_proc, sizeof(tmpcurrent_proc), &tmppid);
	DECAF_printf("insn_begin:%x,program:%s\n", eip, tmpcurrent_proc);
*/
	unsigned char insn_buf[4];
	DECAF_read_mem(env,eip ,sizeof(char)*4,insn_buf);
	if(eip == 0x40df20){
		DECAF_printf("insn_begin %x:%x,%x,%x,%x\n", eip, insn_buf[0], insn_buf[1], insn_buf[2], insn_buf[3]);
	}
	if(insn_buf[0]==0xc && insn_buf[1]==0 && insn_buf[2]==0 && insn_buf[3]==0){
		target_ulong v0 = ((CPUArchState *)env->env_ptr)->active_tc.gpr[2];
		if(v0<6999){
			char tmp_current_proc[256];
			memset(tmp_current_proc, 0, 256 * sizeof(char));
			uint32_t tmp_pid;
			VMI_find_process_by_cr3_c(cr3, tmp_current_proc, sizeof(tmp_current_proc), &tmp_pid);
			char * name = syscall_name[v0-4000];
			if(strcmp(name,"read")==0){
			
			}
			else if(strcmp(name,"connect") == 0 || strcmp(name,"bind") == 0){//(struct sockaddr*)&serv_addr
				target_ulong a1 = ((CPUArchState *)env->env_ptr)->active_tc.gpr[5];
				char *tmpBuf = malloc(50*sizeof(char));
				memset(tmpBuf, 0, 50);
				DECAF_read_mem(env, a1, 50, tmpBuf);
				struct sockaddr_in *so = (struct sockaddr_in *)tmpBuf;
				char * ip = inet_ntoa(so->sin_addr); //reverse of inet_addr
				int port = ntohs(so->sin_port); //reverse of htonl
				DECAF_printf("%s/%d insn_begin:%x, syscall:%s, ip:%s, port:%d\n",tmp_current_proc,tmp_pid, eip, name, ip, port);
				free(tmpBuf);
			}
			else if(strcmp(name,"open")==0){
				target_ulong a0 = ((CPUArchState *)env->env_ptr)->active_tc.gpr[4];
				char *tmpBuf = malloc(50*sizeof(char));
				memset(tmpBuf, 0, 50);
				DECAF_read_mem(env, a0, 50, tmpBuf);
				DECAF_printf("%s/%d insn_begin:%x, syscall:%s, file:%s\n",tmp_current_proc,tmp_pid, eip, name, tmpBuf);
				free(tmpBuf);
			}
			else if(strcmp(name,"sendto")==0 || strcmp(name,"send")==0 || strcmp(name,"sendmsg")==0){
				target_ulong a1 = ((CPUArchState *)env->env_ptr)->active_tc.gpr[5];
				target_ulong a2 = ((CPUArchState *)env->env_ptr)->active_tc.gpr[6];
				char *tmpBuf = malloc(a2*sizeof(char));
				memset(tmpBuf, 0, a2);
				DECAF_read_mem(env, a1, a2, tmpBuf);
				DECAF_printf("%s/%d insn_begin:%x, syscall:%s, buf:%s, len:%d\n",tmp_current_proc,tmp_pid, eip, name, tmpBuf,a2);
				free(tmpBuf);
			}
			else{
				DECAF_printf("%s/%d insn_begin:%x, syscall:%s\n",tmp_current_proc,tmp_pid, eip, name);
			}
					
		}
	}	

}

static void virus_block_begin(DECAF_Callback_Params*dcp)
{
	CPUState *env = dcp->bb.env;
	/*
	 * check current instruction:
	 * if it belongs to the examined process, and
	 * if it is clean, dump the region
	*/
	uint32_t eip, cr3; 
	if(virus_basename[0] == '\0'){
		return ;
	}

	cr3 = DECAF_getPGD(env);

	if(virus_cr3 == 0) {
		char current_proc[256];
		uint32_t pid;

		VMI_find_process_by_cr3_c(cr3, current_proc, sizeof(current_proc), &pid);
		if(strcasecmp(current_proc, virus_basename) != 0){
			return;
		}
		virus_cr3 = cr3;
	}
	inContext = (virus_cr3 == cr3) && (!DECAF_is_in_kernel(env)); 
	eip = DECAF_getPC(env);
	if (!inContext){
		return;
	}

	char tmp_current_proc[256];
	memset(tmp_current_proc, 0, 256 * sizeof(char));
	uint32_t tmp_pid;
	VMI_find_process_by_cr3_c(cr3, tmp_current_proc, sizeof(tmp_current_proc), &tmp_pid);
	//DECAF_printf("%s:%x\n", tmp_current_proc, eip);
/*
	char modname[512];
	char functionname[512];
	if (0 == funcmap_get_name_c(eip, cr3, &modname, &functionname)) {
		DECAF_printf("function:%s\n", functionname);
	}
*/
}

static void unpacker_block_begin(DECAF_Callback_Params*dcp)
{
	CPUState *env = dcp->bb.env;
	/*
	 * check current instruction:
	 * if it belongs to the examined process, and
	 * if it is clean, dump the region
	*/
	uint32_t eip, cr3; 
	if(unpack_basename[0] == '\0'){
		return ;
	}

	cr3 = DECAF_getPGD(env);

	if(unpack_cr3 == 0) {
		char current_proc[256];
		uint32_t pid;

		VMI_find_process_by_cr3_c(cr3, current_proc, sizeof(current_proc), &pid);
		if(strcasecmp(current_proc, unpack_basename) != 0){
			return;
		}
		unpack_cr3 = cr3;
	}
	inContext = (unpack_cr3 == cr3) && (!DECAF_is_in_kernel(env)); 
	eip = DECAF_getPC(env);
	if (!inContext){
		return;
	}

	char tmp_current_proc[256];
	memset(tmp_current_proc, 0, 256 * sizeof(char));
	uint32_t tmp_pid;
	VMI_find_process_by_cr3_c(cr3, tmp_current_proc, sizeof(tmp_current_proc), &tmp_pid);
	if(tmp_current_proc){				
		//DECAF_printf("%s block begin, pc:%x,cr3:%x\n", tmp_current_proc, eip, cr3);
	}	

    	uint64_t mybitmap=0;
    	mybitmap=check_mem_mark(eip,1);
    	if(mybitmap>0){
    		DECAF_printf("will dump this region: eip=%08x \n", eip);
    		DECAF_printf("Suspicious activity!\n");
    		fprintf(unpacker_log, "suspcious instruction: eip=%08x \n", eip);
    		fflush(unpacker_log);
    		dump_unpacked_code();
    		cur_version++;
    	}
    	return ;
}

//change add
static void unpacker_module_loaded(VMI_Callback_Params *pcp)
//change end
{

	//uint32_t pid=pcp->lm.pid;
	//char *name=pcp->lm.name;
	uint32_t base=pcp->lm.base;
	uint32_t size=pcp->lm.size;
    uint32_t virt_page, i;
    for (virt_page = base; virt_page < base + size;
    		virt_page += TARGET_PAGE_SIZE) {
      for (i = 0; i < TARGET_PAGE_SIZE; i+=4) {
    	  //taint check needed
    	  set_mem_mark(i+virt_page,4,0);
      }
   }
   fprintf(unpacker_log, "clean virt_page=%08x, size = %d \n", virt_page, size);

}


static void unpacker_mem_write(DECAF_Callback_Params*dcp)
{

	// DECAF change
	uint32_t virt_addr;//,phys_addr;
	int size;
	//phys_addr=dcp->mw.phy_addr;
	virt_addr=dcp->mw.vaddr;
	size=dcp->mw.dt;
	//end
	//DECAF_printf("write virtual addr:%x\n", virt_addr);

	if(inContext) {
		memory_write = 1;
		set_mem_mark(virt_addr,size,(1<<size)-1);
	} else {
	//clean memory 
		//taintcheck_clean_memory(phys_addr, size);  //Need change for DECAF
		set_mem_mark(virt_addr,size,0);
	}
/*	END	*/
}
void unregister_callbacks()
{
	DECAF_printf("Unregister_callbacks\n");
	if(block_begin_cb_handle){
		DECAF_printf("DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB,block_begin_cb_handle);\n");
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB,block_begin_cb_handle);
	}
	if(insn_end_cb_handle){
		//DECAF_unregister_callback(DECAF_INSN_END_CB,insn_end_cb_handle);
	}
	if(mem_write_cb_handle){
		DECAF_printf("DECAF_unregister_callback(DECAF_MEM_WRITE_CB,mem_write_cb_handle);\n");
		DECAF_unregister_callback(DECAF_MEM_WRITE_CB,mem_write_cb_handle);
	}
	if(proc_loadmodule_cb_handle){
		DECAF_printf("VMI_unregister_callback(VMI_LOADMODULE_CB)\n");
		VMI_unregister_callback(VMI_LOADMODULE_CB,proc_loadmodule_cb_handle);
	}
	if(proc_loadmainmodule_cb_handle){
		DECAF_printf("VMI_unregister_callback(VMI_CREATEPROC_CB)\n");
		VMI_unregister_callback(VMI_CREATEPROC_CB,proc_loadmainmodule_cb_handle);
	}
	if(proc_processend_cb_handle){
		DECAF_printf("VMI_unregister_callback(VMI_REMOVEPROC_CB)\n");
		VMI_unregister_callback(VMI_REMOVEPROC_CB,proc_processend_cb_handle);
	}
}
static void unpacker_cleanup()
{
	//DECAF change
	  //clean memory

	unregister_callbacks();
	//DECAF end
	if(unpacker_log) fclose(unpacker_log);
}

int count = 0;
static void unpacker_loadmainmodule_notify(VMI_Callback_Params *vcp)
{
		uint32_t pid=vcp->cp.pid;
		char *name=vcp->cp.name;
		int cr3 = VMI_find_cr3_by_pid_c(pid);

		if((strlen(name)==15 || strlen(name)==12) && strcmp(name, "UPDATELEASES.sh")!=0 && strcmp(name, "updateleases")!=0){
			count ++;
			DECAF_printf("new program:%s,cr3:%x\n",name,cr3);
			if(count == 2){ // decide different case when equals 2, crash.
				memset(virus_basename, 0, 256*sizeof(char));
				strcpy(virus_basename, name);
				virus_cr3 = cr3;
				if(!virus_block_begin_cb_handle){
					virus_block_begin_cb_handle=DECAF_register_callback(DECAF_BLOCK_BEGIN_CB,virus_block_begin,NULL);
					DECAF_printf("DECAF_register_callback(VIRUS_DECAF_BLOCK_BEGIN_CB)\n");
				}
			}
		}


		if(unpack_basename[0] != 0) {
			if(strcasecmp(name, unpack_basename)==0) {
				DECAF_printf("loadmainmodule_notify called, %s\n", name);

				monitored_pid = pid;
				unpack_cr3 = VMI_find_cr3_by_pid_c(pid);
				if(!block_begin_cb_handle){
					block_begin_cb_handle=DECAF_register_callback(DECAF_BLOCK_BEGIN_CB,unpacker_block_begin,NULL);
					DECAF_printf("DECAF_register_callback(DECAF_BLOCK_BEGIN_CB) pid=%d\n",pid);
				}

				if(!insn_end_cb_handle){
					insn_end_cb_handle=DECAF_register_callback(DECAF_INSN_BEGIN_CB, unpacker_insn_begin, NULL);
					DECAF_printf("DECAF_register_callback(DECAF_INSN_BEGIN_CB) pid=%d\n",pid);

				}

				if(!mem_write_cb_handle){
					mem_write_cb_handle=DECAF_register_callback(DECAF_MEM_WRITE_CB,unpacker_mem_write,NULL);
					DECAF_printf("DECAF_register_callback(DECAF_MEM_WRITE_CB) pid=%d\n",pid);
				}
				start = clock();
			}
		}
}

static void unpacker_removeproc_notify(VMI_Callback_Params *vcp)
{
	uint32_t pid=vcp->rp.pid;
  if(monitored_pid != 0 && monitored_pid == pid) {

	  DECAF_printf("unpacker_removeproc_notify pid=%d\n", pid);
	  //change begin
	  do_stop_unpack(NULL,NULL);
	  //change end
	  monitored_pid = 0;
	  printf("Unpacker: Time taken: %f\n", ((double)clock() - start)/CLOCKS_PER_SEC);
  }
}

plugin_interface_t * init_plugin()
{
	unpack_basename[0] = '\0';
	virus_basename[0] = '\0';
	if (!(unpacker_log = fopen("unpack.log", "w"))) {
	printf("Unable to open unpack.log for writing!\n");
	return NULL;
	}
	mem_mark_init();
	DECAF_output_init(NULL);
//syscall parser
	xmlDoc *document;
	xmlNode *root, *first_child, *node;
	char *filename = "syscall.xml";
	document = xmlReadFile(filename, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	for (node = first_child; node; node = node->next) {
		xmlAttr* attribute = node->properties;
		if(attribute && attribute->name && attribute->children){
			xmlChar *name = xmlNodeListGetString(node->doc, attribute->children,1);
			attribute = attribute->next;
			xmlChar *id = xmlNodeListGetString(node->doc, attribute->children,1);
			int index = atoi(id) - 4000;
			syscall_name[index] = malloc(sizeof(char) * 100);
			strcpy(syscall_name[index], name);
		}
	}

	//change to
	unpacker_interface.mon_cmds=unpacker_term_cmds;
	unpacker_interface.plugin_cleanup=unpacker_cleanup;
	proc_loadmodule_cb_handle=VMI_register_callback(VMI_LOADMODULE_CB,unpacker_module_loaded,&should_monitor);
	proc_loadmainmodule_cb_handle=VMI_register_callback(VMI_CREATEPROC_CB,unpacker_loadmainmodule_notify,&should_monitor);
	proc_processend_cb_handle=VMI_register_callback(VMI_REMOVEPROC_CB,unpacker_removeproc_notify,&should_monitor);
	//change end

	return &unpacker_interface;
}


