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
#include "qemu/osdep.h"
#include "cpu.h"


#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"
#include "afl-qemu-cpu-inl.h"


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


int socket_connect(char *host, in_port_t port){
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;     

	if((hp = gethostbyname(host)) == NULL){
		herror("gethostbyname");
		exit(1);
	}
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(sock == -1){
		perror("setsockopt");
		exit(1);
	}
	
	if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
		perror("connect");
		exit(1);

	}
	return sock;
}

#define BUFFER_SIZE 1024

int HTTP_Request(char * host, int port){
	int fd;
	char buffer[BUFFER_SIZE];

       
	fd = socket_connect(host, atoi(port)); 
	write(fd, "GET /\r\n", strlen("GET /\r\n")); // write(fd, char[]*, len);  
	bzero(buffer, BUFFER_SIZE);
	
	while(read(fd, buffer, BUFFER_SIZE - 1) != 0){
		fprintf(stderr, "%s", buffer);
		bzero(buffer, BUFFER_SIZE);
	}

	shutdown(fd, SHUT_RDWR); 
	close(fd); 

	return 0;
}



//http socket end



//basic stub for plugins

char * VMI_find_process_name_by_pgd(uint32_t pgd);

static plugin_interface_t callbacktests_interface;
static int bVerboseTest = 0;
static int enableTimer = 1;
static int afl_start = 0;
static int afl_fork = 0;
static char *current_data = NULL;
static int rest_len = 0;
static int network_read_block = 0;
static int open_block = 0;
static int recv_block = 0;
static int current_fd = 0;

typedef struct _callbacktest_t
{
  char name[64];
  DECAF_callback_type_t cbtype;
  OCB_t ocbtype;
  gva_t from;
  gva_t to;
  DECAF_Handle handle;
  struct timeval tick;
  struct timeval tock;
  int count;
  double elapsedtime;
}callbacktest_t;
#define CALLBACKTESTS_TEST_COUNT 8

static callbacktest_t callbacktests[CALLBACKTESTS_TEST_COUNT] = {
    {"Block Begin Single", DECAF_BLOCK_BEGIN_CB, OCB_CONST, 0x7C90d9b0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0}, //0x7C90d580 is NtOpenFile 0x7C90d9b0 is NtReadFile
    {"Block Begin Page", DECAF_BLOCK_BEGIN_CB, OCB_PAGE, 0x7C90d9b0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0}, //0x7C90d090 is NtCreateFile
    {"Block Begin All", DECAF_BLOCK_BEGIN_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Block End From Page", DECAF_BLOCK_END_CB, OCB_PAGE, 0x7C90d9b0, INV_ADDR, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Block End To Page", DECAF_BLOCK_END_CB, OCB_PAGE, INV_ADDR, 0x7C90d9b0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Block End All", DECAF_BLOCK_END_CB, OCB_PAGE, INV_ADDR, INV_ADDR, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Insn Begin", DECAF_INSN_BEGIN_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Insn End", DECAF_INSN_END_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
};

static int curTest = 0; //not to set this
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;

static char targetname[512];
static uint32_t targetpid;
static uint32_t targetcr3;

static void runTests(void);

static void callbacktests_printSummary(void);
static void callbacktests_resetTests(void);


static void callbacktests_printSummary(void)
{
  int i = 0;
  DECAF_printf("******* SUMMARY *******\n");
  DECAF_printf("%+30s\t%12s\t%10s\n", "Test", "Count", "Time");
  for (i = 0; i < CALLBACKTESTS_TEST_COUNT; i++)
  {
    DECAF_printf("%-30s\t%12u\t%.5f\n", callbacktests[i].name, callbacktests[i].count, callbacktests[i].elapsedtime);
  }
}

static void callbacktests_resetTests(void)
{
  int i = 0;
  for (i = 0; i < CALLBACKTESTS_TEST_COUNT; i++)
  {
    callbacktests[i].tick.tv_sec = 0;
    callbacktests[i].tick.tv_usec = 0;
    callbacktests[i].tock.tv_sec = 0;
    callbacktests[i].tock.tv_usec = 0;
    callbacktests[i].handle = 0;
    callbacktests[i].count = 0;
    callbacktests[i].elapsedtime = 0.0;
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

  //DECAF_printf("Process with pid = %d and cr3 = %u was just created\n", params->lmm.pid, params->lmm.cr3);

  VMI_find_process_by_cr3_c(params->cp.cr3, procname, 64, &pid);
  //DECAF_printf("process with pid=%d, name=%s\n",pid, procname);
  //in find_process pid is set to 1 if the process is not found
  // otherwise the number of elements in the module list is returned
  if (pid == (uint32_t)(-1))
  {
    return;
  }

  if (strcmp(targetname, procname) == 0)
  {
    DECAF_printf("Procname:%s,targetname:%s,targetpid:%d\n",targetname,procname,pid);
    targetpid = pid;
    targetcr3 = params->cp.cr3;
    runTests();
  }
}

static void callbacktests_removeproc_callback(VMI_Callback_Params* params)
{
  double elapsedtime;

  if (params == NULL)
  {
    return;
  }

  if (targetpid == params->rp.pid)
  {
    if (curTest >= CALLBACKTESTS_TEST_COUNT)
    {
      return;
    }

    if (callbacktests[curTest].handle == DECAF_NULL_HANDLE)
    {
      return;
    }

    //unregister the callback FIRST before getting the time of day - so
    // we don't get any unnecessary callbacks (although we shouldn't
    // since the guest should be paused.... right?)
    DECAF_unregister_callback(callbacktests[curTest].cbtype, callbacktests[curTest].handle);
    callbacktests[curTest].handle = DECAF_NULL_HANDLE;
    DECAF_printf("Callback Count = %u\n", callbacktests[curTest].count);

    gettimeofday(&callbacktests[curTest].tock, NULL);

    elapsedtime = (double)callbacktests[curTest].tock.tv_sec + ((double)callbacktests[curTest].tock.tv_usec / 1000000.0);
    elapsedtime -= ((double)callbacktests[curTest].tick.tv_sec + ((double)callbacktests[curTest].tick.tv_usec / 1000000.0));
    DECAF_printf("Process [%s] with pid [%d] ended at %u:%u\n", targetname, targetpid, callbacktests[curTest].tock.tv_sec, callbacktests[curTest].tock.tv_usec);
    DECAF_printf("  Elapsed time = %0.6f seconds\n", elapsedtime);

    callbacktests[curTest].elapsedtime = elapsedtime;

    //increment for the next test
//zyw
    //curTest++;
    if (curTest < CALLBACKTESTS_TEST_COUNT)
    {
      DECAF_printf("%d of %d tests completed\n", curTest, CALLBACKTESTS_TEST_COUNT);
      DECAF_printf("Please execute %s again to start next test\n", targetname);
    }
    else
    {
      DECAF_printf("All tests have completed\n");
      callbacktests_printSummary();
    }
    targetpid = (uint32_t)(-1);
    targetcr3 = 0;
  }
}



static void callbacktests_genericcallback(DECAF_Callback_Params* param)
{
  FILE * fp = fopen("api_callbacktest","a+");
  if (curTest >= CALLBACKTESTS_TEST_COUNT)
  {
    return;
  }
  
  //LOK: Setup to do a more comprehensive test that does something with the parameters
  if (1 || bVerboseTest)
  //if (0)
  {

    switch(callbacktests[curTest].cbtype)
    {
      case (DECAF_BLOCK_BEGIN_CB):
      {
// libuClibc-0.9.30.1.so is stripped, so no symbol was loaded
	if(param->bb.tb->pc < 0x80000000){
		char modname[512];
		char functionname[512];
		CPUArchState *cpu = param->bb.env->env_ptr;
	
		if (0 == funcmap_get_name_c(param->bb.tb->pc, targetcr3, &modname,
						&functionname)) {
/*		
			if(strcmp(functionname, "strcoll")!=0 && strcmp(functionname, "memcpy")!=0 && strcmp(functionname, "memset")!=0 && strcmp(functionname, "internal_dump")!=0){
				DECAF_printf("%s\n", functionname);	
			}
*/
			
			if(strcmp(functionname, "__libc_accept") == 0)
			{
				recv_block = 1;
				DECAF_printf("%s\n", functionname);
				//HTTP_Request("192.168.0.1",80);
			}
/*
			if(strcmp(functionname, "internal_dump") == 0)
			{
				DECAF_printf("%s,", functionname);
			}
*/
			if(strcmp(functionname, "poll") == 0)
			{
				DECAF_printf("%s\n", functionname);
			}
			else if(strcmp(functionname, "__libc_open") == 0)
			{
				target_ulong filename_ptr = cpu->active_tc.gpr[4];//fd
				char *tmpbuf = (char *)malloc(50);
				DECAF_read_mem(param->bb.env, filename_ptr, 50, tmpbuf);
				DECAF_printf("%s,%s", functionname, tmpbuf);
				free(tmpbuf);
			}
			else if(strcmp(functionname, "__libc_read")==0 || strcmp(functionname, "__libc_recv")==0 || strcmp(functionname, "__libc_recvfrom")==0 || strcmp(functionname, "__libc_recvmsg")==0) {
				target_ulong a0 = cpu->active_tc.gpr[4];//fd
				target_ulong a2 = cpu->active_tc.gpr[6];//nbytes	
				DECAF_printf("%s:%x, current_fd:%x, len:%d\n", functionname, a0, current_fd, a2);
				fprintf(fp, "%s:%x, current_fd:%x, len:%d\n", functionname, a0, current_fd, a2);
				if(a0 == current_fd){
					//network read				
					DECAF_printf("network read, %x\n", a0);
					network_read_block = 1;
				}
			}
			else{
				DECAF_printf("%s\n", functionname);	
			}
		}
		else if(param->bb.tb->pc < 0x500000){
			if(recv_block == 1){
				recv_block = 0;
				target_ulong v0 = cpu->active_tc.gpr[2];//return value (fd)
				if (v0!=0 && v0!=0xffffffff){
					if(afl_start == 0){	
						afl_start = 1;
						startForkserver(cpu, enableTimer);
						DECAF_printf("before fork pid:%d\n",getpid());	
					}
					current_fd = v0;
					fprintf(fp,"socket fd:%x\n", v0);
					DECAF_printf("socket fd:%x\n", v0);					
					//watcher();						
				}
			}

			else if(network_read_block == 1){
				network_read_block = 0;
//0x4072f8 after read
				CPUArchState *cpu = param->bb.env->env_ptr;
				target_ulong pc = cpu->active_tc.PC;
				target_ulong a0 = cpu->active_tc.gpr[4];//fd
				target_ulong a1 = cpu->active_tc.gpr[5];//buf
				target_ulong a2 = cpu->active_tc.gpr[6];//nbytes
				target_ulong v0 = cpu->active_tc.gpr[2];//return value (read)
//real network data
				char *buf1 = (char *)malloc(a2);
				DECAF_read_mem(param->bb.env, a1, a2, buf1);
				DECAF_printf("argument:%x,%x,%x,%d,%d\n data:%s\n",pc,a0,a1,a2,v0,buf1);
				free(buf1);
//read network data end 
//aflcall

				if(afl_start == 1 && afl_fork == 0){
					afl_fork = 1;	
					DECAF_printf("after fork pid:%d\n",getpid());					
					char * buf;
					//u_long bufsz = aflInit(buf);
					buf = (char *)malloc(4096);
					u_long bufsz = 4096;
					DECAF_printf("afl init:%x,%d\n",buf, bufsz);

					char filename[500];
					//ulong sz = getWork(cpu, (u_long)buf, bufsz, filename);
					//DECAF_printf("filename:%s\n",filename);
					//startWork(cpu, 0x81000000L, 0xffffffffL);
					ulong sz = getWork(cpu, buf, bufsz);
					startWork(cpu, 0x400000L, 0x500000L);
					current_data = buf;
					rest_len = sz; 
					DECAF_printf("data read:%x,%d\n",current_data, rest_len);		
				}

				DECAF_printf("compare:%d,%d\n",rest_len, a2);
				if(rest_len != 0){// rest_len is the length of virtual buffer
					if (rest_len + 1 >= a2){// a2 is the maximum recv length for once
						DECAF_printf("data wirte:%x,rest:%d,len:%d\n",current_data, rest_len,a2);
						fprintf(fp, "data wirte:%x,rest:%d,len:%d\n",current_data, rest_len,a2);
						//DECAF_write_mem(param->bb.env, a1, a2, current_data);
						current_data += a2;
						rest_len -= a2;
					}
					else{
						DECAF_printf("data wirte:%x,rest:%d,len:%d\n",current_data, rest_len,rest_len);
						fprintf(fp, "data wirte:%x,rest:%d,len:%d\n",current_data, rest_len,rest_len);
						//need memset all bits first
						//DECAF_write_mem(param->bb.env, a1, rest_len, current_data);
						current_data += rest_len;
						rest_len = 0;
					}	

				}
				else{// if input data's data is too little, it will end up with donework
					DECAF_printf("donework done:%d\n", getpid());
					free(buf); //current_data 
					doneWork(0);	
				}
			
			}
		}
		else if(param->bb.tb->pc < 0x70000000 && afl_fork == 1){
			//DECAF_printf("pc:%x\n", param->bb.tb->pc);
			/*
			if(param->bb.tb->pc == 0x407348)
			{
				DECAF_printf("donework done\n");
				doneWork(0);
			}
			*/
		}
	}	
//zyw
	//getPGD not work becuase of mips_get_cur_pgd cannot obtain mips_pgd_current for procinfo.ini	
	//uint32_t pgd = DECAF_getPGD(param->bb.env);
	//char * proc_name = VMI_find_process_name_by_pgd(pgd);
	//DECAF_printf("tc:%x\n", param->bb.env->current_tc);
	///uint32_t pid;
	////char current_name[50];
	//pid = mips_get_cur_pid(param->bb.env, current_name);
	//pgd = mips_get_cur_pgd(param->bb.env);
	//cr3 = mips_get_cur_cr3(param->bb.env);	
	/*
	if(strcmp(proc_name, "<kernel>")!=0){

		DECAF_printf("BB @ [%x], CS @ [%x], proc @ [%s]\n", param->bb.tb->pc, param->bb.tb->cs_base, proc_name);
	}*/
	/*
	if(strcmp(current_name,"httpd")==0){
	  if(param->bb.tb->pc>0x80000000){
	    //DECAF_printf("kernel address:%x\n",param->bb.tb->pc);
	  else if(param->bb.tb->pc>0x70000000){
	    DECAF_printf("BB @ [%x], CS @ [%x], proc @ [%s]\n", param->bb.tb->pc, param->bb.tb->cs_base, current_name);
	  }else{
	    //DECAF_printf("BB @ [%x], CS @ [%x], proc @ [%s]\n", param->bb.tb->pc, param->bb.tb->cs_base, current_name);
	  }
	}*/
        break;
      }
      case (DECAF_BLOCK_END_CB):
      {
	//fprintf(fp,"block end\n");
/*

	unsigned char insn_buf[2];
	DECAF_printf("pc:%x\n", param->be.cur_pc);
	int is_call = 0, is_ret = 0;
	DECAF_read_mem(param->be.env,param->be.cur_pc,sizeof(char)*2,insn_buf);
	DECAF_printf("pc:%x, block end:%x\n", param->be.cur_pc, insn_buf[1]);
	if(insn_buf[0] == 0x9a){
	  DECAF_printf("block end:%x\n", insn_buf[1]);
	}
        //DECAF_printf("BE @ [%x] [%x] -> [%x]\n", param->be.tb->pc, param->be.cur_pc, param->be.next_pc);
*/
        break;

      }
      case (DECAF_INSN_BEGIN_CB):
      {
        //do nothing yet?
	CPUState *env = param->ib.env;
	DECAF_printf("pc:%x\n", ((CPUArchState *)env->env_ptr)->active_tc.PC);
	break;
      }
      case (DECAF_INSN_END_CB):
      {
        //do nothing yet?
	CPUState *env = param->ie.env;
	target_ulong pc = 0;
	CPUArchState *env_ptr = (CPUArchState *)env->env_ptr;
	if(env_ptr)
	{
		TCState *tc = &(env_ptr->active_tc);
		if(tc)
		{
			pc = tc->PC;
			DECAF_printf("pc:%x\n", pc);
		}
	}
	break;

	//int is_call = 0, is_ret = 0;
	//DECAF_read_mem(env,pc,sizeof(char)*2,insn_buf);
	//DECAF_printf("pc:%x, block end:%x\n", pc, insn_buf[1]);
	//if(insn_buf[0] == 0x9a){
	  //DECAF_printf("block end:%x\n", insn_buf[1]);
	//}
	
      }
    }
  }

  //TODO: Add support for ONLY tracking target process and not ALL processes
  fclose(fp);
  callbacktests[curTest].count++;
}

static void runTests(void)
{
  if (curTest >= CALLBACKTESTS_TEST_COUNT)
  {
    DECAF_printf("All tests have completed\n");
    return;
  }

  if (callbacktests[curTest].handle != DECAF_NULL_HANDLE)
  {
    DECAF_printf("%s test is currently running\n", callbacktests[curTest].name);
    return;
  }

  DECAF_printf("\n");
  DECAF_printf("**********************************************\n");
  DECAF_printf("Running the %s test\n", callbacktests[curTest].name);
  DECAF_printf("\n");
  gettimeofday(&callbacktests[curTest].tick, NULL);
  DECAF_printf("Process [%s] with pid [%d] started at %u:%u\n", targetname, targetpid, callbacktests[curTest].tick.tv_sec, callbacktests[curTest].tick.tv_usec);
  DECAF_printf("Registering for callback\n");
  switch(callbacktests[curTest].cbtype)
  {
    case (DECAF_BLOCK_BEGIN_CB):
    {
      callbacktests[curTest].handle = DECAF_registerOptimizedBlockBeginCallback(&callbacktests_genericcallback, NULL, callbacktests[curTest].from, callbacktests[curTest].ocbtype);
      break;
    }
    case (DECAF_BLOCK_END_CB):
    {
      DECAF_printf("from and to: %d,%d\n",callbacktests[curTest].from, callbacktests[curTest].to);
      callbacktests[curTest].handle = DECAF_registerOptimizedBlockEndCallback(&callbacktests_genericcallback, NULL, callbacktests[curTest].from, callbacktests[curTest].to);
      break;
    }
    default:
    case (DECAF_INSN_BEGIN_CB):
    case (DECAF_INSN_END_CB):
    {
      callbacktests[curTest].handle = DECAF_register_callback(callbacktests[curTest].cbtype, &callbacktests_genericcallback, NULL);
    }
    
  }

  if (callbacktests[curTest].handle == DECAF_NULL_HANDLE)
  {
    DECAF_printf("Could not register the event\n");
    return;
  }

  callbacktests[curTest].count = 0;
  DECAF_printf("Callback Registered\n");
}

void do_callbacktests(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
  {
    strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
  }
  else
  {
    DECAF_printf("A program name was not specified, so we will use sort.exe\n");
    strncpy(targetname, "sort.exe", 512);
  }
  targetname[511] = '\0';
  curTest = 2;
  callbacktests_resetTests();
  DECAF_printf("Tests will be completed using: %s (case sensitive).\n", targetname);
  DECAF_printf("  Run the program to start the first test\n");
}

static int callbacktests_init(void)
{
  DECAF_output_init(NULL);
  DECAF_printf("Hello World\n");
  //register for process create and process remove events
  processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &callbacktests_loadmainmodule_callback, NULL);
  removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB, &callbacktests_removeproc_callback, NULL);
  if ((processbegin_handle == DECAF_NULL_HANDLE) || (removeproc_handle == DECAF_NULL_HANDLE))
  {
    DECAF_printf("Could not register for the create or remove proc events\n");
  }

  targetname[0] = '\0';
  targetcr3 = 0;
  targetpid = (uint32_t)(-1);

  do_callbacktests(NULL, NULL);
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

  curTest = 0;
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

