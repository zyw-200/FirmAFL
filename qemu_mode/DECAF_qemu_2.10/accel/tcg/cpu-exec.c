/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

int lmbench_count = 0;
int lat_select_init = 0;
extern int thread_pool;
extern int analysis_start;
extern int coroutine_start;
int stay_in_full = 0;

int start_fork_pc;
int libuclibc_addr = 0;
int not_exit = 0;
int tmp_not_exit = 0;
int last_pc = 0;
int last_program_pc = 0;
int end_pc = 0;
int program_id = 0;
int auto_find_fork_times = 0;
int poll_times = 0;
double full_store_page_time = 0.0;

int before_interrupt_stack = 0;
int before_syscall_stack = 0;
int before_switch_stack = 0;
int thread_context = 1;
int stack_mask = 0;
int ori_thread = 0;
int recv_times = 1;
int fork_accept_times = 1;
int accept_times = 0;
int accept_fd = 0;
int handle_recv = 0;
int count_142 = 0;
int count_3 = 0;
int sys_count = 0;

int CP0_UserLocal = 0;


#include "zyw_config1.h"
#include "zyw_config2.h"

#ifdef SNAPSHOT_SYNC
char *phys_addr_stored_bitmap; 

int add_physical_page(int phys_addr)
{
    int value = phys_addr >> 12;
    int index = value >> 3;
    int position = value & 0x07;

    phys_addr_stored_bitmap[index] |=  1 << position;
}

//if not exist,add it and return -1; if exist, return index;
int if_physical_exist(int phys_addr) //phys_addr <= 0x7ffff000
{   
    int value = phys_addr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    return (phys_addr_stored_bitmap[index] & (1 << position)) !=0; 

}
#endif 


#if defined(FUZZ) || defined(MEM_MAPPING)
#include "afl-qemu-cpu-inl.h" //AFL_QEMU_CPU_SNIPPET
extern int afl_wants_cpu_to_stop;
int exit_status = 0;
int full_store_count = 0;
//int tmp_print = 0;

void getconfig(char *keywords, char *res)
{
    FILE *fp = fopen("FirmAFL_config", "r");
    char StrLine[256];
    while (!feof(fp)) 
    { 
        fgets(StrLine,256,fp);
        char * key = strtok(StrLine, "=");
        char * value = strtok(NULL, "=");
        int val_len = strlen(value);
        if(value[val_len-1] == '\n')
        {
            value[val_len-1] = '\0';
        } 
        if(strcmp(keywords, key) == 0)
        {
            strcpy(res, value);
            break;
        }
    }
    fclose(fp); 
}


#endif

#ifdef MEM_MAPPING
int pipe_read_fd = -1;
int pipe_write_fd = -1; 
int read_type = -1;
int is_loop_over = 1;
int first_time = 0; //tlb store
int syscall_request = 0;


int write_addr(uintptr_t ori_addr, uintptr_t addr);
#endif

#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/cpus.h"
#include "sysemu/replay.h"

//zyw
#ifdef TARGET_ARM
typedef struct ARMMMUFaultInfo ARMMMUFaultInfo;
struct ARMMMUFaultInfo {
    target_ulong s2addr;
    bool stage2;
    bool s1ptw;
};
#endif

int total_count = 10000;
int count = 0;
int tmptmptmp = 0;
int brk_end = 0;
FILE * open_log_file = NULL;


int config_pc = 0;
char program_analysis[256];
char feed_type[256];
int environ_offset = 0;
char lib_name[256];
int program_type = 0;


int FirmAFL_config()
{
    memset(feed_type, 0, 256);
    getconfig("feed_type",feed_type);
    assert(strlen(feed_type)>0);

    char fork_pc_str[256];
    memset(fork_pc_str, 0, 256);
    getconfig("start_fork_pc", fork_pc_str);
    if(strlen(fork_pc_str) > 0)
    {   
        config_pc = strtol(fork_pc_str, NULL, 16);
        assert(config_pc!=0);
    }
#ifdef FUZZ  
    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
        getconfig("lib_name", lib_name);
        char offset_str[256];
        getconfig("environ_offset", offset_str);
        environ_offset = strtol(offset_str, NULL, 16);
        assert(strlen(lib_name) > 0);
        assert(environ_offset!=0);
    }
    char end_pc_str[256];
    memset(end_pc_str, 256, 0);
    getconfig("end_pc", end_pc_str);
    if(strlen(end_pc_str) > 0)
    {
        end_pc = strtol(end_pc_str, NULL, 16);
    }
#endif
    char id_str[256];
    memset(id_str, 256, 0);
    getconfig("id", id_str);
    if(strlen(id_str) > 0)
    {
        program_id = strtol(id_str, NULL, 10);
    }
    
    if(program_id == 105600)
    {
        fork_accept_times = 3;
    }
    if(program_id == 161161)
    {
        fork_accept_times = 1;
    }
    getconfig("program_analysis", program_analysis); 
    assert(strlen(program_analysis)>0);
    /*
    if(strcmp(program_analysis, "httpd") == 0 || strcmp(program_analysis, "miniupnpd") == 0)
    {
        program_type = 1;
    }
    */
    /*
    else if(strcmp(program_analysis, "network.cgi") == 0 || strcmp(program_analysis, "video.cgi") == 0)
    {
        program_type = 1;
    }
    */
}


#ifdef FUZZ

static void convert_endian_4b(uint32_t *data)
{
   *data = ((*data & 0xff000000) >> 24)
         | ((*data & 0x00ff0000) >>  8)
         | ((*data & 0x0000ff00) <<  8)
         | ((*data & 0x000000ff) << 24);
}

static void read_ptr(CPUState* cpu, int vaddr, uint32_t *pptr)
{
    cpu_memory_rw_debug(cpu, vaddr, pptr, 4, 0);
#ifdef TARGET_WORDS_BIGENDIAN
    convert_endian_4b(pptr);
#endif
}

static void write_ptr(CPUState* cpu, int vaddr, int pptr_addr)
{
#ifdef TARGET_WORDS_BIGENDIAN
    convert_endian_4b(&pptr_addr);
#endif
    cpu_memory_rw_debug(cpu, vaddr, &pptr_addr, 4, 1);

}
char * aflFile;

target_ulong getWork(char * ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;
    unsigned char ch;
    //printf("pid %d: getWork %lx %lx\n", getpid(), ptr, sz);fflush(stdout);
    //printf("filename:%s\n",aflFile);
    fp = fopen(aflFile, "rb");
    if(!fp) {
        perror(aflFile);
        printf("aflfile open failed\n");
        return errno;
    }
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;
        //cpu_stb_data(env, ptr, ch);
        *ptr = ch;
        retsz ++;
        ptr ++;
    }
    *ptr = '\0';
    fclose(fp);
    return retsz;
}


//FEED_ENV
int replace_addr = 0;
int global_addr = 0;
int environ_addr;
int content_addr;
int pre_feed_finish = 0;

//FEED_HTTP
char http_package[50][4096];
char tmp_http_package[50][4096];
char http_key[50][100];
char http_value[50][4096];
int package_index = 0;
int feed_addr = 0;

char recv_buf[4096];
int total_len = 0;
int buf_read_index = 0;


int write_package(CPUState *cpu, int vir_addr, char* cont, int len)
{
    //DECAF_printf("write_package:%x,%x\n", vir_addr, len);
    int ret = DECAF_write_mem(cpu, vir_addr, len, cont);
    if(ret ==-1)
    {
        DECAF_printf("write failed %x,%x\n", vir_addr, len);
        sleep(1000);
    }
    else
    {
        //DECAF_printf("write %x,%x\n", vir_addr, len);
    }
    return vir_addr + len;
}


void prepare_feed_input(CPUState * cpu)
{
    CPUArchState *env = cpu->env_ptr;
    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
        pre_feed_finish = 1;
        char modname[512];
        target_ulong base;
        target_ulong pgd = DECAF_getPGD(cpu);
        DECAF_printf("print_mapping for %x\n", pgd);
        FILE * fp2 = fopen("mapping", "w");
        print_mapping(modname, pgd, &base, fp2);// obtain mapping
        fclose(fp2);
        FILE * fp3 = fopen("mapping", "r");
        char strline[100];
        while(fgets(strline, 100, fp3)!=NULL)
        {
            char *p1 = strtok(strline, ":");
            char *p2 = strtok(NULL, ":");
            char *p3 = strtok(NULL, ":");
            char *p4 = strtok(NULL, ":");
            p4[strlen(p4)-1]='\0';
            if(strcmp(p4, lib_name) ==0)
            {
                int gva_start = strtol(p1,NULL, 16);
                libuclibc_addr = gva_start;
                DECAF_printf("libuclibc addr:%x\n", libuclibc_addr);
                break;
            }    
        }
        fclose(fp3);

        global_addr = libuclibc_addr + environ_offset; 


        read_ptr(cpu, global_addr, &environ_addr);
        read_ptr(cpu, environ_addr, &content_addr);
        DECAF_printf("global addr:%lx, %lx,%lx\n",global_addr, environ_addr, content_addr);
        get_page_addr_code(env, content_addr); //important
        //write_ptr(cpu, environ_addr + 4, 0);
    }
    else if(strcmp(feed_type, "FEED_HTTP") == 0)
    {
        /*
        pre_feed_finish = 1;
        CPUArchState *env= cpu->env_ptr;
#ifdef TARGET_MIPS
        feed_addr = env->active_tc.gpr[5];
#else defined(TARGET_ARM)
        feed_addr = env->regs[1];
#endif
        */
    }
    else if (strcmp(feed_type, "FEED_CMD") == 0)
    {
        CPUArchState *env = cpu->env_ptr;
        int argv = env->active_tc.gpr[5];
        int cmd_addr = 0;
        DECAF_read_ptr(cpu, argv + 4, &cmd_addr);
        DECAF_read_ptr(cpu, argv + 8, &feed_addr);
        char cmd_str[256];
        DECAF_read_mem(cpu, cmd_addr, 256, cmd_str);
        DECAF_printf("cmd is %s\n", cmd_str);
        char content[1024];
        DECAF_read_mem(cpu, feed_addr, 1024, content);
        DECAF_printf("content is %s\n", content);
        get_page_addr_code(env, feed_addr); //important
        get_page_addr_code(env, feed_addr+0x1000); //important
        DECAF_printf("pre get addr:%x,%x\n", feed_addr, feed_addr+0x1000);


    }
    else if(strcmp(feed_type, "NONE") == 0)
    {

    }
    else
    {
        DECAF_printf("feed type error\n");
        sleep(100);
    }
    
}

//a-z：97-122
//A-Z：65-90
//0-9：48-57
int check_input(char * input, int len) // if all are readable charater before =
{   
    int i = 0;
    while((input[i]>=97 && input[i]<=122) || (input[i]>=65 && input[i]<=90) || (input[i]>=48 && input[i]<=57))
    {
        i++;
        if(i == len)
        {
            return 1;
        }
        if(input[i] == '=')
        {
            return 1;
        }
    }
    return 0;
}

int check_http_header(char * input) // if all are readable charater before =
{   
    if(program_id == 9925)
    {
        if(strncmp(input, "GET /session_login.php HTTP/1.1", 31) == 0)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else if(program_id == 10853)
    {
        if(strncmp(input, "POST /HNAP1/ HTTP/1.1", 21) == 0)
        {
            return 1;
        }
        else
        {
            return 0;
        }

    }
    else if(program_id == 161161)
    {
        if(strncmp(input, "POST /apply.cgi HTTP/1.1\r\n", 26) == 0)
        {
            return 1;
        }
        else
        {
            return 0;
        }

    }

    return 1;
}

int feed_input(CPUState * cpu)
{
    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
        if(pre_feed_finish == 0)
            return 0;


        //char orig1_input_buf[MAX_LEN];
        //memset(orig_input_buf, 0, MAX_LEN);
        //DECAF_read_mem(cpu, content_addr, MAX_LEN, orig_input_buf);
        //DECAF_printf("orig_input:%s\n", orig_input_buf);
        


        char input_buf[MAX_LEN];
        int get_len = getWork(input_buf, MAX_LEN);
        if(check_input(input_buf, 1) == 0)
        {
            return 2;
        }
        //DECAF_printf("feed_input: %x, %s\n", content_addr, input_buf);
        int ret = DECAF_write_mem(cpu, content_addr, get_len, input_buf);
        DECAF_write_mem(cpu, content_addr + get_len, 1, "\0"); //important


        /*
        int tmp_content_addr = 0;
        int tmp_environ_addr = environ_addr;
        read_ptr(cpu, tmp_environ_addr, &tmp_content_addr);
        while(tmp_content_addr!=0)
        {
            char orig_input_buf[MAX_LEN];
            memset(orig_input_buf, 0, MAX_LEN);
            DECAF_read_mem(cpu, tmp_content_addr, MAX_LEN, orig_input_buf);
            DECAF_printf("tmp_content_addr:%x, orig_input:%s\n", tmp_content_addr, orig_input_buf);
            tmp_environ_addr+=4;
            read_ptr(cpu, tmp_environ_addr, &tmp_content_addr);
        } 
        */       

        return 1;
    }
    else if(strcmp(feed_type, "FEED_HTTP") == 0) 
    {
        //DECAF_printf("feed input -----------\n");
        /*
        if(pre_feed_finish == 0)
            return 0;
        CPUArchState *env = cpu->env_ptr;
        char input_buf[MAX_LEN-100];
        int get_len = getWork(input_buf, MAX_LEN-100);
        if(get_len > 2800)
        {
            get_len = 2700;
        }

        int tmp_addr = write_package(cpu, feed_addr, input_buf, get_len);
        DECAF_write_mem(cpu, tmp_addr, 1, "\0"); //important

#ifdef TARGET_MIPS
        env->active_tc.gpr[2] = tmp_addr - feed_addr;
        //DECAF_printf("modified length:%d\n", env->active_tc.gpr[2]);
        char tt[4096];
        DECAF_read_mem(cpu, feed_addr, 4096, tt);
        DECAF_printf("modified content:########%s\n", tt);
#else defined(TARGET_ARM)
        env->regs[0] = tmp_addr - feed_addr;
#endif
        return 1;
        */
        total_len = getWork(recv_buf, 4096);
        
        
        if(check_http_header(recv_buf) == 0)
        {
            //printf("recv_buf:%s\n", recv_buf);
            return 2;
        }
        
        //DECAF_printf("recv_buf:%s\n", recv_buf);
    }
    else if(strcmp(feed_type, "FEED_CMD") == 0)
    {
        /*
        CPUArchState *env = cpu->env_ptr;
        int argv = env->active_tc.gpr[5];
        int cmd_addr = 0;
        DECAF_read_ptr(cpu, argv + 4, &cmd_addr);
        DECAF_printf("cmd addr:%x\n", cmd_addr);
        char cmd_str[256];
        DECAF_read_mem(cpu, cmd_addr, 256, cmd_str);
        printf("cmd is %s\n", cmd_str);
        */
        char input_buf[MAX_LEN];
        int get_len = getWork(input_buf, MAX_LEN);
        //DECAF_printf("new inputs:%s, len:%d\n", input_buf, get_len);
        target_ulong tmp_addr = feed_addr;
        tmp_addr = write_package(cpu, feed_addr, input_buf, get_len);
        write_package(cpu, tmp_addr, "\0", 1); //important

    }
    else if(strcmp(feed_type, "NONE") == 0)
    {

    }
    else
    {
        DECAF_printf("feed type error\n");
        sleep(100);
    }
}
#endif

#ifdef AUTO_FIND_FORK_PC
int into_recv_syscall = 0;

/*
int check_arg(CPUState *cpu , char * arg_name)
{
    CPUArchState *env = cpu->env_ptr;
#ifdef TARGET_MIPS
    int argv = env->active_tc.gpr[5];
#elif defined(TARGET_ARM)
    int argv = env->regs[1];
#endif
    int sec_arg_addr;
    read_ptr(cpu, argv+4, &sec_arg_addr);
    char actual_name[100];
    DECAF_read_mem(cpu, sec_arg_addr, 100, actual_name);
    DECAF_printf("check:%x,%x,%s\n", argv, sec_arg_addr, actual_name);
    if(strcmp(arg_name, actual_name) == 0)
    {
        return 1;
    }
    return 0;
}
*/
#endif


#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"
int in_httpd = 0;
struct timeval store_page_start;
struct timeval store_page_end;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_end_handle = DECAF_NULL_HANDLE;
static DECAF_Handle mem_write_cb_handle = DECAF_NULL_HANDLE;

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

//extern FILE *file_log;
int mem_mapping_exit = 0;

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
    if(afl_user_fork && (pc == 0x80133a84 || pc == 0x80133ac4))
    {
        DECAF_printf("print_fatal_signal:%x\n",pc);
#ifdef FORK_OR_NOT
        int ret_value = 32;
        doneWork(ret_value);
        //goto end;
#endif
#ifdef MEM_MAPPING
        target_ulong pgd = DECAF_getPGD(cpu);
        if(pgd == httpd_pgd)
        {
            mem_mapping_exit = 1;
        }
#endif
    }
#ifdef STORE_PAGE_FUNC
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
#endif
    /*
    if(afl_user_fork && into_syscall == 4005 && tmptmptmp == 1)
    {
        if(pc == 0x80101cc0)
        {
            DECAF_printf("handle int pc:%x, cpu0:%x,%x,%x\n",pc, env->CP0_Status, env->CP0_Cause, env->CP0_EPC);
        }
        if(pc == 0x80100ea0)
        {
            DECAF_printf("pc:%x, cpu0:%x,%x,%x\n",pc, env->CP0_Status, env->CP0_Cause, env->CP0_EPC);
        }
        if(pc == 0x80100ed4)
        {
            DECAF_printf("pc:%x, cpu0:%x,%x,%x\n",pc ,env->CP0_Status, env->CP0_Cause, env->CP0_EPC);
        }
        count++;
        fprintf(open_log_file, "open pc:%x, %x\n", pc, ra);
        //if(count == total_count)
        //{
        //    fclose(open_log_file);
        //    sleep(100);
        //}

    
    }
    */
    return;
}

/*
static void do_block_end(DECAF_Callback_Params* param){ 
    return;

}
*/
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
            sleep(100);
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

#ifdef CAL_TIME_ext
        gettimeofday(&store_page_start, NULL);
#endif
        store_page(virt_addr & 0xfffff000, page_host_addr, in_httpd);
#ifdef CAL_TIME_ext
        gettimeofday(&store_page_end, NULL);
        double store_once_time = (double)store_page_end.tv_sec - store_page_start.tv_sec + (store_page_end.tv_usec - store_page_start.tv_usec)/1000000.0;
        full_store_page_time += store_once_time;
#endif

    }

}
#endif

static void callbacktests_loadmainmodule_callback(VMI_Callback_Params* params)
{
    char procname[64];
    uint32_t pid;
    uint32_t par_pid;
    if (params == NULL)
    {
        return;
    }
    //VMI_find_process_by_cr3_c(params->cp.cr3, procname, 64, &pid);
    VMI_find_process_by_cr3_all(params->cp.cr3, procname, 64, &pid, &par_pid);
    if (pid == (uint32_t)(-1))
    {
        return;
    }
    if(strcmp(procname,program_analysis) == 0)
    {
        DECAF_printf("\nProcname:%s/%d,pid:%d:%d, cr3:%x\n",procname, index, pid, par_pid, params->cp.cr3);
        
        char par_proc_name[100];
        int par_cr3;
        VMI_find_process_by_pid_c(par_pid, par_proc_name, 100, &par_cr3);
        DECAF_printf("parent proc:%s\n", par_proc_name);

        pgd_push(params->cp.cr3);
        httpd_pgd = get_current_pgd();
        DECAF_printf("cur pgd:%x\n", httpd_pgd);
        //pro_start = 1;
        //flush_not_regen_pc();
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
    if(strcmp(procname,program_analysis) == 0)
    {
        DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x\n",procname, index, pid, params->rp.cr3);

        target_ulong tmp_pgd = pgd_pop();
        assert(tmp_pgd==params->rp.cr3);
        httpd_pgd = get_current_pgd();
        DECAF_printf("cur pgd:%x\n", httpd_pgd);

    }
}

int callbacktests_init(void)
{
    DECAF_output_init(NULL);
    DECAF_printf("Hello World\n");
    processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &callbacktests_loadmainmodule_callback, NULL);
    removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB, &callbacktests_removeproc_callback, NULL);

    block_begin_handle = DECAF_registerOptimizedBlockBeginCallback(&do_block_begin, NULL, INV_ADDR, OCB_ALL);
#ifdef STORE_PAGE_FUNC
    //block_end_handle = DECAF_registerOptimizedBlockEndCallback(&do_block_end, NULL, INV_ADDR, INV_ADDR);
    mem_write_cb_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,fuzz_mem_write,NULL);
#endif                  
    return (0);
}


/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

int last_log_pc = 0;
/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %p [%d: " TARGET_FMT_lx "] %s\n",
                           itb->tc_ptr, cpu->cpu_index, itb->pc,
                           lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)
        && qemu_log_in_addr_range(itb->pc)) {
        qemu_log_lock();
#if defined(TARGET_I386)
        log_cpu_state(cpu, CPU_DUMP_CCOP);
#else
        log_cpu_state(cpu, 0);
#endif
        qemu_log_unlock();
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;

    ret = tcg_qemu_tb_exec(env, tb_ptr);
    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc_ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        } else {
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
    }
    else
    {

#ifdef FUZZ
        if(afl_user_fork && !into_syscall && itb->pc < 0x80000000) //important
        //if(afl_user_fork && into_syscall == 0 && itb->pc!=last_log_pc) //important
        {
            target_ulong pgd = DECAF_getPGD(cpu);
            if(pgd == httpd_pgd)
            {
                //last_log_pc = itb->pc;
                CPUArchState *env = cpu->env_ptr;
                AFL_QEMU_CPU_SNIPPET2;
            }   
        }
#endif
    }
    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    tb_lock();
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles | CF_NOCACHE
                         | (ignore_icount ? CF_IGNORE_ICOUNT : 0));
    tb->orig_tb = orig_tb;
    tb_unlock();

    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);

    tb_lock();
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
    tb_unlock();
}
#endif

static void cpu_exec_step(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        mmap_lock();
        tb_lock();
        tb = tb_gen_code(cpu, pc, cs_base, flags,
                         1 | CF_NOCACHE | CF_IGNORE_ICOUNT);
        tb->orig_tb = NULL;
        tb_unlock();
        mmap_unlock();

        cc->cpu_exec_enter(cpu);
        /* execute the generated code */
        trace_exec_tb_nocache(tb, pc);
        cpu_tb_exec(cpu, tb);
        cc->cpu_exec_exit(cpu);

        tb_lock();
        tb_phys_invalidate(tb, -1);
        tb_free(tb);
        tb_unlock();
    } else {
        /* We may have exited due to another problem here, so we need
         * to reset any tb_locks we may have taken but didn't release.
         * The mmap_lock is dropped by tb_gen_code if it runs out of
         * memory.
         */
#ifndef CONFIG_SOFTMMU
        tcg_debug_assert(!have_mmap_lock());
#endif
        tb_lock_reset();
    }
}

void cpu_exec_step_atomic(CPUState *cpu)
{
    start_exclusive();

    /* Since we got here, we know that parallel_cpus must be true.  */
    parallel_cpus = false;
    cpu_exec_step(cpu);
    parallel_cpus = true;

    end_exclusive();
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
    uint32_t trace_vcpu_dstate;
};

static bool tb_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb->trace_vcpu_dstate == desc->trace_vcpu_dstate &&
        !atomic_read(&tb->invalid)) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.trace_vcpu_dstate = *cpu->trace_dstate;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags, *cpu->trace_dstate);
    return qht_lookup(&tcg_ctx.tb_ctx.htable, tb_cmp, &desc, h);
}

static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    bool have_tb_lock = false;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = atomic_rcu_read(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)]);
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags ||
                 tb->trace_vcpu_dstate != *cpu->trace_dstate)) {
        tb = tb_htable_lookup(cpu, pc, cs_base, flags);
        if (!tb) {

            /* mmap_lock is needed by tb_gen_code, and mmap_lock must be
             * taken outside tb_lock. As system emulation is currently
             * single threaded the locks are NOPs.
             */
            mmap_lock();
            tb_lock();
            have_tb_lock = true;

            /* There's a chance that our desired tb has been translated while
             * taking the locks so we check again inside the lock.
             */
            tb = tb_htable_lookup(cpu, pc, cs_base, flags);
            if (!tb ) {
#ifdef CAL_TIME_ext
                if(afl_user_fork && into_syscall)
                {
                    gettimeofday(&syscall_codegen_begin, NULL);
                }
                else if(afl_user_fork)
                {
                    gettimeofday(&user_codegen_begin, NULL);
                }
#endif

                /* if no translated code available, then translate it now */
                tb = tb_gen_code(cpu, pc, cs_base, flags, 0);

#ifdef CAL_TIME_ext
                if(afl_user_fork && into_syscall) 
                {
                    gettimeofday(&syscall_codegen_end, NULL);
                    double block_codegen_time = (double)syscall_codegen_end.tv_sec - syscall_codegen_begin.tv_sec + (syscall_codegen_end.tv_usec - syscall_codegen_begin.tv_usec)/1000000.0;
                    syscall_codegen_time += block_codegen_time;
                }
                else if(afl_user_fork)
                {
                    gettimeofday(&user_codegen_end, NULL);
                    double block_codegen_time = (double)user_codegen_end.tv_sec - user_codegen_begin.tv_sec + (user_codegen_end.tv_usec - user_codegen_begin.tv_usec)/1000000.0;
                    user_codegen_time += block_codegen_time;
                }
#endif

            }

            mmap_unlock();
        }

        /* We add the TB in the virtual pc hash table for the fast lookup */
        atomic_set(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)], tb);
    }


#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
    if (last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
#ifndef FUZZ
        if (!have_tb_lock) {
            tb_lock();
            have_tb_lock = true;
        }


        if (!tb->invalid) {
            tb_add_jump(last_tb, tb_exit, tb);
        }
#endif
    }


    if (have_tb_lock) {
        tb_unlock();
    }
    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            qemu_mutex_lock_iothread();
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
            qemu_mutex_unlock_iothread();
        }
#endif
        if (!cpu_has_work(cpu)) {
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index >= 0) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        } else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            if (replay_exception()) {
                CPUClass *cc = CPU_GET_CLASS(cpu);
                qemu_mutex_lock_iothread();
                cc->do_interrupt(cpu);
                qemu_mutex_unlock_iothread();
                cpu->exception_index = -1;
            } else if (!replay_has_interrupt()) {
                /* give a chance to iothread in replay mode */
                *ret = EXCP_INTERRUPT;
                return true;
            }
#endif
        }
#ifndef CONFIG_USER_ONLY
    } else if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0) {
        /* try to cause an exception pending in the log */
        cpu_exec_nocache(cpu, 1, tb_find(cpu, NULL, 0), true);
        *ret = -1;
        return true;
#endif
    }

    return false;
}

static inline bool cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (unlikely(atomic_read(&cpu->interrupt_request))) {
        int interrupt_request;
        qemu_mutex_lock_iothread();
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            qemu_mutex_unlock_iothread();
            return true;
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            qemu_mutex_unlock_iothread();
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            qemu_mutex_unlock_iothread();
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            qemu_mutex_unlock_iothread();
            return true;
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                replay_interrupt();
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }

        /* If we exit via cpu_loop_exit/longjmp it is reset in cpu_exec */
        qemu_mutex_unlock_iothread();
    }

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(atomic_read(&cpu->exit_request)
        || (use_icount && cpu->icount_decr.u16.low + cpu->icount_extra == 0))) {
        atomic_set(&cpu->exit_request, 0);
        cpu->exception_index = EXCP_INTERRUPT;
        return true;
    }

    return false;
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit)
{
    uintptr_t ret;
    int32_t insns_left;

    trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);
    tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    if (*tb_exit != TB_EXIT_REQUESTED) {
        *last_tb = tb;
        return;
    }

    *last_tb = NULL;
    insns_left = atomic_read(&cpu->icount_decr.u32);
    atomic_set(&cpu->icount_decr.u16.high, 0);
    if (insns_left < 0) {
        /* Something asked us to stop executing chained TBs; just
         * continue round the main loop. Whatever requested the exit
         * will also have set something else (eg exit_request or
         * interrupt_request) which we will handle next time around
         * the loop.  But we need to ensure the zeroing of icount_decr
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_mb();
        return;
    }

    /* Instruction counter expired.  */
    assert(use_icount);
#ifndef CONFIG_USER_ONLY
    /* Ensure global icount has gone forward */
    cpu_update_icount(cpu);
    /* Refill decrementer and continue execution.  */
    insns_left = MIN(0xffff, cpu->icount_budget);
    cpu->icount_decr.u16.low = insns_left;
    cpu->icount_extra = cpu->icount_budget - insns_left;
    if (!cpu->icount_extra) {
        /* Execute any remaining instructions, then let the main loop
         * handle the next event.
         */
        if (insns_left > 0) {
            cpu_exec_nocache(cpu, insns_left, tb, false);
        }
    }
#endif
}

//zyw
void copy_tlb_helper(CPUTLBEntry *d, CPUTLBEntry *s,
                                   bool atomic_set)
{
#if TCG_OVERSIZED_GUEST
    *d = *s;
#else
    if (atomic_set) {
        d->addr_read = s->addr_read;
        d->addr_code = s->addr_code;
        atomic_set(&d->addend, atomic_read(&s->addend));
        /* Pairs with flag setting in tlb_reset_dirty_range */
        atomic_mb_set(&d->addr_write, atomic_read(&s->addr_write));
    } else {
        d->addr_read = s->addr_read;
        d->addr_write = atomic_read(&s->addr_write);
        d->addr_code = s->addr_code;
        d->addend = atomic_read(&s->addend);
    }
#endif
}


void print_tlb(CPUArchState *env, FILE * fp)
{

    DECAF_printf("print tlb\n");
    for(int index=0; index < 256; index++)
    {
        int prot = -1;
        target_ulong addr = 0;
        target_ulong addr_code = env->tlb_table[2][index].addr_code;
        target_ulong addr_read = env->tlb_table[2][index].addr_read;
        target_ulong addr_write = env->tlb_table[2][index].addr_write;
        uintptr_t addend = env->tlb_table[2][index].addend;
        if(addr_write!= -1)
        {
            addr = addr_write;
            prot = 1;
        }
        else if(addr_read != -1)
        {
            addr = addr_read;
            prot = 0;
        }
        else if(addr_code != -1)
        {
            addr = addr_code;
            prot = 0;
        }
        if(prot!=-1)
        {   
            target_ulong phys_addr = qemu_ram_addr_from_host(addr + addend);
            DECAF_printf("%x,%x,%x, addend:%lx, phys_addr:%x, prot:%d\n", addr_code, addr_read, addr_write, addend, phys_addr, prot);
            fprintf(fp, "%x:%x:%d\n", addr, phys_addr, prot);
        } 
    }
    for(int ind=0; ind < 64; ind++)
    {
        int v_prot = -1;
        target_ulong v_addr = 0;
        CPUTLBEntry tmptlb;
        copy_tlb_helper(&tmptlb, &env->tlb_v_table[2][ind], true);
        target_ulong v_addr_code = tmptlb.addr_code;
        target_ulong v_addr_read = tmptlb.addr_read;
        target_ulong v_addr_write = tmptlb.addr_write;
        uintptr_t v_addend = tmptlb.addend;
        if(v_addr_write!= -1)
        {
            v_addr = v_addr_write;
            v_prot = 1;
        }
        else if(v_addr_read != -1)
        {
            v_addr = v_addr_read;
            v_prot = 0;
        }
        else if(v_addr_code != -1)
        {
            v_addr = v_addr_code;
            v_prot = 0;
        }

        if(v_addend!=0)
        {   
            target_ulong v_phys_addr = qemu_ram_addr_from_host(v_addr + v_addend);
            if(v_phys_addr!=-1)
            {
                DECAF_printf("v_tlb:%x,%x,%x, addend:%lx, phys_addr:%x, prot:%d\n", v_addr_code, v_addr_read, v_addr_write, v_addend, v_phys_addr, v_prot);
                fprintf(fp, "%x:%x:%d\n", v_addr, v_phys_addr, v_prot);
            }   
        }
    }
}

void skip_syscall(CPUState *cpu, int ret_value, int error_value)
{
    CPUArchState *env = cpu->env_ptr;
    cpu->exception_index = -1;
#ifdef TARGET_MIPS
    target_ulong pc = env->active_tc.PC;
    env->active_tc.PC = pc + 4;
    env->active_tc.gpr[2] = ret_value;
    env->active_tc.gpr[7] = error_value;//a3
#elif defined TARGET_ARM 
    target_ulong pc = env->regs[15];
    env->regs[15] = pc + 4;
    //??????????
#endif

}

void prepare_exit()
{
#ifndef FUZZ
#ifdef CAL_TIME 
                gettimeofday(&loop_end, NULL);
                double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;
                double syscall_execution = time_interval_total - total_syscall_codegen_time;
                double user_execution = total_loop_time - time_interval_total - user_codegen_time;
                if(print_debug)
                    DECAF_printf("full: %f:%f:%f:%f:%f:%d\n", total_loop_time, syscall_execution, total_syscall_codegen_time, user_execution, user_codegen_time, syscall_count);
#endif //CAL_TIME
#else

#ifndef QEMU_SNAPSHOT
#ifdef CAL_TIME 
                gettimeofday(&restore_begin, NULL);
#endif //CAL_TIME
#ifdef STORE_PAGE_FUNC
#ifdef CAL_TIME 
                restore_page(0);
#endif //CAL_TIME
#endif //STORE_PAGE_FUNC
#ifdef CAL_TIME               
                gettimeofday(&restore_end, NULL);      
                double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;
#endif //CAL_TIME
#else //QEMU_SNAPSHOT
#ifdef CAL_TIME  
                double restore_time = (double)load_snapshot_end.tv_sec - load_snapshot_start.tv_sec + (load_snapshot_end.tv_usec - load_snapshot_start.tv_usec)/1000000.0;
#endif //CAL_TIME
#endif // QEMU_SNAPSHOT

                //truncate_sysinfo();
#ifdef CAL_TIME
                gettimeofday(&loop_end, NULL);
                double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;

                if(print_loop_count == print_loop_times)
                {
                    print_loop_count = 0;
                    double syscall_execution = time_interval_total - total_syscall_codegen_time;
                    double user_execution = total_loop_time - time_interval_total - user_codegen_time - store_time - restore_time;
                    if(print_debug)
                        DECAF_printf("full: %f:%f:%f:%f:%f:%f:%f:%f:%d\n", total_loop_time, syscall_execution, total_syscall_codegen_time, user_execution, user_codegen_time, tlb_time_interval_total, full_store_page_time, restore_time,  syscall_count);
                }
                tlb_time_interval_total = 0.0;
                time_interval_total = 0.0;
                syscall_count = 0;
                total_syscall_codegen_time = 0.0;
                user_codegen_time = 0.0;
                store_time = 0.0;
#endif //CAL_TIME

#endif //FUZZ
}

int cpu_exec_head(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    //rcu_read_lock();

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);
}

int cpu_exec_tail(CPUState * cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    cc->cpu_exec_exit(cpu);
    //rcu_read_unlock();
}


/* main execution loop */
int feed_input_times = 0;

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    rcu_read_lock();

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    /* prepare setjmp context for exception handling */
    if (sigsetjmp(cpu->jmp_env, 0) != 0) {
        if(afl_user_fork)
        {
            //if(cpu->exception_index == 65537)
            //{


               // printf("trigger exception:%d,%d\n", cpu->exception_index, cpu->halted);
            //}
        }
#ifdef NEW_MAPPING
        if(tlb_match)
        {
            tlb_match = 0;
            DECAF_printf("jump back\n");
            into_normal_execution = 0;
            afl_wants_cpu_to_stop = 1;
            exit_status = 0;
            uintptr_t tmp_vaddr = write_vaddr;
            uintptr_t tmp_paddr = write_paddr;
            write_addr(tmp_vaddr, tmp_paddr);
            goto end;
        }
#endif
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
        /* Some compilers wrongly smash all local variables after
         * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
         * Reload essential local variables here for those compilers.
         * Newer versions of gcc would complain about this code (-Wclobbered). */
        cpu = current_cpu;
        cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
        /* Assert that the compiler does not smash local variables. */
        g_assert(cpu == current_cpu);
        g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
        cpu->can_do_io = 1;
        tb_lock_reset();
        if (qemu_mutex_iothread_locked()) {
            qemu_mutex_unlock_iothread();
        }
    }

    CPUArchState * env = cpu->env_ptr;
#ifdef AUTO_FIND_FORK_PC
    if(start_fork_pc == 0 && cpu->exception_index == 17)
    {
        target_ulong pgd = DECAF_getPGD(cpu);
        if(pgd == httpd_pgd) {
#ifdef TARGET_MIPS
            target_ulong sys_call_num = env->active_tc.gpr[2];
            if (sys_call_num == 4003 || sys_call_num == 4175 || sys_call_num == 4176 || sys_call_num == 4168)
            {
                into_recv_syscall = sys_call_num;
                if(into_recv_syscall != 4168)
                {

                    int tmp_fd = env->active_tc.gpr[4];
                    if(accept_fd == tmp_fd && accept_fd!=0) 
                    {
                        DECAF_printf("recv after:%d,%d\n",tmp_fd, accept_fd);
                        handle_recv = 1;
                        goto skip_to_pos;

                    }
                    
                }
            }
            else
            {
                into_recv_syscall = 0;
            }

#elif defined TARGET_ARM
            target_ulong sys_call_num = env->regs[0];
            if (sys_call_num == 63 || sys_call_num == 1073 || sys_call_num == 207)
            {
                into_recv_syscall = sys_call_num;
                //DECAF_printf("into recv syscall:%d\n", into_recv_syscall);
            }
            else
            {   
                into_recv_syscall = 0;
            }
#endif
        }
    }
#endif
    /*
    if(httpd_pgd!=0 && cpu->exception_index == 17 && env->active_tc.gpr[2] == 4283)
    {
        printf("(((( set thread area:%x,%x,%x\n", env->active_tc.gpr[4], env->active_tc.gpr[5],env->active_tc.gpr[6]);
    }
    */
#ifdef LMBENCH
    if(cpu->exception_index == 17 && httpd_pgd!= 0)
    {
        target_ulong pgd = DECAF_getPGD(cpu);
        if(pgd != 0)
        {
            if(env->active_tc.gpr[2] == 4283)
            {
                CP0_UserLocal = env->active_tc.gpr[4];
                printf("set thread are:%x\n", CP0_UserLocal);
            }
        }
    }
#endif
    if(afl_user_fork && cpu->exception_index == 17 && into_syscall == 0)
    {

#ifdef DECAF
        target_ulong pgd = DECAF_getPGD(cpu);
        int tmp_pc;
#ifdef TARGET_MIPS
        tmp_pc = env->active_tc.PC;

#endif 
        int cond = 0;
#ifdef TARGET_MIPS
        if(program_id == 105600)
        {
            cond = ((pgd == httpd_pgd) && ((env->active_tc.gpr[29] & 0xfff00000)==stack_mask));
        }
        else
        {
            cond = (pgd == httpd_pgd);
        }
#elif defined(TARGET_ARM)
        cond = (pgd == httpd_pgd);
#endif
        if(cond){
#endif
#ifdef CAL_TIME
            gettimeofday(&syscall_begin, NULL);
#endif
            int if_exit = 0;
            //global_into_syscall = 1;
#ifdef TARGET_MIPS
            int a0 = env->active_tc.gpr[4];
            int a1 = env->active_tc.gpr[5]; 
            int a2 = env->active_tc.gpr[6];
            int a3 = env->active_tc.gpr[7];
            into_syscall = env->active_tc.gpr[2];
            before_syscall_stack = env->active_tc.gpr[29];
            curr_state_pc = env->active_tc.PC;

            if(print_debug)
            {   
                sys_count++;
                DECAF_printf("----------------------------------------------------------%d\n", sys_count);
                DECAF_printf("sys num:%d, pc: %x, stack:%x, %x, %x, %x ,interrupt:%d\n", into_syscall, curr_state_pc, before_syscall_stack, a0, a1, a2, cpu->interrupt_request);
                if(into_syscall == 4005 || into_syscall == 4040 || into_syscall == 4010 )
                {
                    char prog_name[100];
                    DECAF_read_mem(cpu, a0, 100, prog_name);
                    DECAF_printf("open:%s, %x\n", prog_name, a0);
                }
                if(into_syscall == 4175)
                {
                    DECAF_printf("last pc:%x\n", last_program_pc);
                }
                if(into_syscall == 4142)
                {
                    DECAF_printf("last pc:%x\n", last_program_pc);
                }
                if(into_syscall == 4011)
                {
                    DECAF_printf("last pc:%x\n", last_program_pc);
                }
            }
            if(into_syscall == 4001 || into_syscall == 4246){  
                if_exit = 1;
            }
            else if(into_syscall == 4142)
            {
                if(program_id == 9925 || program_id == 10853 || program_id == 105600 || program_id == 161160)
                {
                    if_exit = 1;
                }
                else if(program_id == 161161)
                {
                    if(last_syscall == 4142)
                    {
                        if_exit = 1;
                        last_syscall = 0;
                    }
                }
                
            }

            else if(into_syscall == 4003)
            {
                if(program_id == 161161)
                {
                    //DECAF_printf("count3:%x\n", count_3);
                    count_3++;
                    if(count_3 == 3)
                    {
                        if_exit = 1;
                        count_3 = 0;
                        last_syscall = 0;
                        goto exit;
                    }
                }
            }

            else if(into_syscall == 4045)
            {
                if(program_id == 10853)
                {
                    if_exit = 1;
                }
                
                if(program_id == 161161)
                {
                    if_exit = 1;
                }
            }
            /*
            else if(into_syscall == 4140)
            {
                if(program_id == 161161)
                {
                    if_exit = 1;
                }
            }
            */
            //161161
            if(into_syscall != 4003)
            {
                count_3 = 0;
            }
            last_syscall = into_syscall;

#ifdef FUZZ
            if(a0 == accept_fd && (into_syscall == 4175 || into_syscall == 4003 || into_syscall == 4176)
             && strcmp(feed_type,"FEED_HTTP") == 0 && feed_input_times == 0) //161161
            {
                get_page_addr_code(env, a1); //important
                int final_recv_len = 0;
                //161161
                if(program_id == 161161)
                {
                    feed_input_times++;
                }
    
                int flag = a3;
                int len = a2;
                int rest_len = total_len - buf_read_index;
                //printf("hook flag:%x, %x\n", MSG_PEEK, flag);
                //printf("rest len:%d\n", rest_len);
                if(rest_len > len)
                {
                    final_recv_len = len;
                }
                else
                {
                    final_recv_len  = rest_len;
                }
                int tmp_addr = write_package(cpu, a1, recv_buf + buf_read_index, final_recv_len);
                DECAF_write_mem(cpu, tmp_addr, 1, "\0"); //important
                //DECAF_printf("recv :%d,%d,%x, %s\n", accept_fd, len, env->active_tc.gpr[5], recv_buf);
                if(MSG_PEEK == flag && (into_syscall == 4175 || into_syscall == 4176))
                {
                    //printf("recv msg_peek\n");
                }
                else
                {
                    //printf("feed input:%s\n", recv_buf + buf_read_index);
                    buf_read_index+=final_recv_len;   
                }

                skip_syscall(cpu, final_recv_len, 0);
                goto skip_to_pos;
            }
            /*
            if(a0 == accept_fd && into_syscall == 4004 && strcmp(feed_type,"FEED_HTTP") == 0)
            {
                skip_syscall(cpu, a2, 0);
                goto skip_to_pos;
            }
            */
            else if(a0 == accept_fd && into_syscall == 4178 && strcmp(feed_type,"FEED_HTTP") == 0)
            {
                skip_syscall(cpu, a2, 0);
                goto skip_to_pos;
            }
            else if(a0 == accept_fd && into_syscall == 4004 && strcmp(feed_type,"FEED_HTTP") == 0)
            {
                if(program_id == 161161)
                {
                   if_exit = 1;
                   goto exit;
                }
                else
                {
                    skip_syscall(cpu, a2, 0);
                    goto skip_to_pos;
                }
            }
            else if(a0 == accept_fd && into_syscall == 4140)
            {
                skip_syscall(cpu,0, 0);
                goto skip_to_pos;
            }
#endif
            tmp_not_exit = 0;
            if(into_syscall == 4002) //fork
            {
                not_exit = 1;
                skip_syscall(cpu, 100, 0);
                goto skip_to_pos;
            }
            else if(into_syscall == 4114) //wait
            {
                not_exit = 0;
                skip_syscall(cpu, 100, 0);
                goto skip_to_pos;
            }
            
            else if(into_syscall == 4166) //nanosleep
            {
                skip_syscall(cpu, 0, 0);
                goto skip_to_pos;
            }
            /*
            else if(into_syscall == 4178) //send
            {
                if(program_id == 10853)
                {
                    skip_syscall(cpu, a2, 0);
                    goto skip_to_pos;
                }             
            }
            */
            else if(into_syscall == 4194 || into_syscall == 4119 || into_syscall == 4193) //sig
            {
                if(program_id == 10853 || program_id == 9925 || program_id == 129781 || program_id == 161161)
                {
                    //printf("tmp_not_exit 1\n");
                    tmp_not_exit = 1;
                    skip_syscall(cpu, 0, 0);
                    goto skip_to_pos;
                }             
            }
            
            else if(into_syscall == 4170) //connect
            {
                if(program_id == 10566 || program_id == 9054) 
                {
                    skip_syscall(cpu, 0, 0);
                    goto skip_to_pos;
                }             
            }
            else if(into_syscall == 4117) 
            {
                skip_syscall(cpu, 0, 0);
                goto skip_to_pos;
            
            }

#elif defined(TARGET_ARM)
            int a0 = env->regs[0];
            int a1 = env->regs[1];
            int a2 = env->regs[2];
            into_syscall = env->regs[0];
            curr_state_pc = env->regs[15];
            before_syscall_stack = env->regs[13];
            if(into_syscall == 93 || into_syscall == 1079 || into_syscall == 94){
                if_exit = 1;
            }
#endif

exit:
            if(if_exit){ 
#ifdef FUZZ
                total_len = 0;
                buf_read_index = 0;
#endif
                sys_count = 0;
                prepare_exit();
                exit_status = 0;
#ifdef FORK_OR_NOT
                int ret_value = 0;
                doneWork(ret_value);
#else
                //fork_tb_flush();
                into_syscall = 0;
                afl_wants_cpu_to_stop = 1;
                goto end;
#endif               
            }

#ifdef DECAF
        }
#endif

    } 


    /* if an exception is pending, we execute it here */
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
skip_to_pos:
            assert(1==1);
#ifdef TARGET_MIPS
            target_ulong pc = env->active_tc.PC;
            target_ulong a0 = env->active_tc.gpr[4];
            target_ulong a1 =env->active_tc.gpr[5];
            target_ulong a2 = env->active_tc.gpr[6];
            target_ulong ra = env->active_tc.gpr[31];
            target_ulong ret = env->active_tc.gpr[2];
            target_ulong err = env->active_tc.gpr[7];
            target_ulong stack = env->active_tc.gpr[29];
#elif defined(TARGET_ARM)
            target_ulong pc = env->regs[15];
            target_ulong a0 = env->regs[0];
            target_ulong a1 =env->regs[1];
            target_ulong a2 = env->regs[2];
            target_ulong ra = env->regs[14];
            target_ulong ret = env->regs[0];
            target_ulong err = 0; //???
            target_ulong stack = env->regs[13]; //???????

#endif

#ifdef NEW_MAPPING
            if(afl_user_fork && handle_addr !=0) //normal execution
            {
                if(into_normal_execution == 0 && pc < 0x80000000)
                {
                    into_normal_execution = 1;
                    int ind =  (handle_addr >> 12) & 255;
                    target_ulong addr_code = env->tlb_table[2][ind].addr_code;
                    target_ulong addr_read = env->tlb_table[2][ind].addr_read;
                    target_ulong addr_write = env->tlb_table[2][ind].addr_write;
                    uintptr_t addend = env->tlb_table[2][ind].addend;
                    DECAF_printf("into normal execution:%x, %x,%x,%x, %lx\n",handle_addr, addr_code, addr_read, addr_write,addend);        
                    normal_execution_tb = pc;

                    if((handle_addr & 0xfffff000) == addr_write)
                    {
                        into_normal_execution = 0;
                        target_ulong final_phys_addr = qemu_ram_addr_from_host(addr_write + addend);
                        write_addr(handle_addr, final_phys_addr + (handle_addr & 0xfff));
                        exit_status = 0;
                        afl_wants_cpu_to_stop = 1;
                        goto end;   
                    }
                } 
            }          
#endif


#ifdef AUTO_FIND_FORK_PC
            if(config_pc==0)
            {
                if(start_fork_pc == 0 && handle_recv == 1)
                {
                    into_syscall = 0;
                    cpu->exception_index = -1;
                    stack_mask = stack & 0xfff00000;
                    start_fork_pc = pc;
                    DECAF_printf("start fork pc:%x\n", pc);
                }

                else if(start_fork_pc == 0 && pc < 0x80000000 && into_recv_syscall)
                {
                    target_ulong pgd = DECAF_getPGD(cpu);
                    if(pgd == httpd_pgd) {
                        char *buf = malloc(a2);
                        printf("pc:%x,  syscall:%d, fd:%d, a1:%x, len:%d, ret:%d, ra:%x\n", pc, into_recv_syscall, a0, a1, a2, ret, ra);
                        DECAF_read_mem(cpu, a1, a2, buf);

                        if(into_recv_syscall == 4168)
                        {
                            accept_times++;
                            printf("_______{fd:%d\n", ret);
                            if(accept_times == fork_accept_times)
                            {
                                accept_fd = ret;
                                printf("_________accept fd:%d\n", accept_fd);
                            }
                            
                        }
                        free(buf);
                    }
                    into_recv_syscall = 0;
                }

            }
            else
            {

                if(start_fork_pc == 0 && pc == config_pc)
                {
                    target_ulong pgd = DECAF_getPGD(cpu);
#ifdef LMBENCH

                    //if(pgd != 0 && httpd_pgd !=0) {
                    if(pgd == httpd_pgd) {
#else
                    if(pgd == httpd_pgd) {
#endif
                        stack_mask = stack & 0xfff00000;
                        ori_thread = cpu->thread_id;
                        DECAF_printf("start fork stack:%x\n", stack);
                        start_fork_pc = pc;

                    }
                } 
            }
                   
#endif //AUTO_FIND_FORK_PC


#if defined(FUZZ) || defined(MEM_MAPPING)
#ifdef LMBENCH
           //if(pc == 0x400b64 && fork_times == 0) //fstat
            //if(pc == (0x4009e4) && fork_times == 0) //select 0x400710 ||
            //if(pc == (0x4009d0) && fork_times == 0) //select_debug //server
            //if(pc == (0x4008c0) && fork_times == 0) //select_debug2 //server
            //if(pc == (0x40088c) && fork_times == 0) //select_debug3 //server 0x4008e4
            //if((pc == 0x401f90 ||  pc == 0x401f94 || pc == 0x400fdc) && fork_times == 0) //test
            if(pc == 0x402950 && fork_times == 0) //test
            //if(pc == 0x400850 && fork_times == 0) //pipe initialization
            //if(pc == 0x400a30 && fork_times == 0) //read initialization
             //if(pc == 0x40099c && fork_times == 0) //write initialization
            //if(pc == start_fork_pc && fork_times == 0) //null openclose stat
#else
            if(pc == start_fork_pc && fork_times == 0) //?////?????????
#endif
            {

                target_ulong pgd = DECAF_getPGD(cpu);       
#ifdef DECAF
#ifdef LMBENCH
                if(pgd == httpd_pgd)
                //if(pgd != 0 && httpd_pgd !=0 )
                {
#else
                if(pgd == httpd_pgd)
                {
#endif //lmbench
#endif //DECAF
                    
                    CPUArchState * env = cpu->env_ptr;
                    char modname[512];
                    target_ulong base;
#if defined(FUZZ)
                    prepare_feed_input(cpu);
                    FILE * fp2 = fopen("mapping", "w");
                    print_mapping(modname, pgd, &base, fp2);// obtain mapping
                    fclose(fp2);
                    FILE * fp3 = fopen("mapping", "r");
                    char strline[100];
                    while(fgets(strline, 100, fp3)!=NULL)
                    {
                        char *p1 = strtok(strline, ":");
                        char *p2 = strtok(NULL, ":");
                        char *p3 = strtok(NULL, ":");
                        char *p4 = strtok(NULL, ":");
                        p4[strlen(p4)-1]='\0';
                        if(strcmp(p4, "libuClibc-0.9.30.so") ==0)
                        {
                            int gva_start = strtol(p1,NULL, 16);
                            libuclibc_addr = gva_start;
                            DECAF_printf("libuclibc addr:%x\n", libuclibc_addr);
                            break;
                        }    
                    }
                    fclose(fp3);

#endif
                    fork_times = 1;


#ifdef MEM_MAPPING
                    char mapping_filename[256];
                    getconfig("mapping_filename", mapping_filename);
                    assert(strlen(mapping_filename)>0);
                    FILE * fp = fopen(mapping_filename, "a+");
                    printf("map file:%s\n", mapping_filename);
                    fprintf(fp,"%x\n", start_fork_pc);
#ifdef TARGET_MIPS
                    for(int i=0;i<32;i++) {
                        fprintf(fp, "%x\n", env->active_tc.gpr[i]);
                    }
                    fprintf(fp, "%x\n", env->active_tc.PC);
                    fprintf(fp ,"%x\n", env->CP0_Status);
                    fprintf(fp ,"%x\n", env->CP0_Cause);
                    fprintf(fp ,"%x\n", env->CP0_EPC);
                    printf("user pc:%x, stack:%x,  qemu pid:%x\n", env->active_tc.PC, stack, getpid());
#elif defined(TARGET_ARM)
                    for(int i=0;i<16;i++) {
                        fprintf(fp, "%x\n", env->regs[i]);
                    }
                    
#endif
                    DECAF_printf("print_mapping for %x\n", pgd);

                    print_mapping(modname, pgd, &base, fp);// obtain mapping
                    //memory for snapshot consistency
                    fprintf(fp, "###########\n");
                    print_tlb(env, fp);
                    fprintf(fp, "###########\n");


#ifdef SNAPSHOT_SYNC
                    int shmem_id = shmget(0, 8192, IPC_CREAT|IPC_EXCL); //0xfffffff(7 bit)  orig:131072
                    fprintf(fp, "%d\n", shmem_id);
                    void * shmem_start = shmat(shmem_id, NULL,  1); 
                    memset(shmem_start, 0, 8192);
                    phys_addr_stored_bitmap = (char *)shmem_start;
                    printf("share mem id:%d, shmem_start: %x\n", shmem_id, shmem_start);
#endif
                    printf("accept fd:%d\n", accept_fd);
                    fprintf(fp, "%d\n", accept_fd);
                    fprintf(fp, "%x\n", CP0_UserLocal);
                    fclose(fp);
#endif  //MEM_MAPPING

#if defined(FUZZ) && !defined(MEM_MAPPING)
                    startTrace(cpu, 0, 0x7fffffff);
                    //startTrace(cpu, 0, 0x70000000);
#endif
                    ///*
                    //exit_status = 0;
                    afl_wants_cpu_to_stop = 1;
                    //afl_user_fork = 1;
                    goto end;   
                    //*/
#ifdef DECAF           
                }           
#endif

            }
#endif

#ifdef FUZZ
            if(start_fork_pc != 0 && pc == start_fork_pc && feed_times == 0)
            {

                target_ulong pgd = DECAF_getPGD(cpu);
                if(pgd == httpd_pgd) {
                    int res = feed_input(cpu);
                    feed_times = 1;
                    if(res == 2){ 
#ifdef FUZZ
                        total_len = 0;
                        buf_read_index = 0;
#endif
                        sys_count = 0;
                        prepare_exit();
                        exit_status = 0;
#ifdef FORK_OR_NOT
                        int ret_value = 0;
                        doneWork(ret_value);
#else
                        //fork_tb_flush();
                        into_syscall = 0;
                        afl_wants_cpu_to_stop = 1;
                        goto end;
#endif               
                    }

             
                }

            }
#endif
            if(afl_user_fork && pc ==  curr_state_pc + 4 && into_syscall && before_syscall_stack == stack)
            {

#ifdef DECAF 
                target_ulong new_pgd = DECAF_getPGD(cpu);
                if(new_pgd == httpd_pgd){ //user_stack_count // || get_current_pc()  == 0xb960 + tmp_libuclibc_addr
#endif
                    /*
                    if(afl_user_fork && a0 == accept_fd&& 
                            (into_syscall != 4175 && into_syscall != 4003 && into_syscall != 4176 && into_syscall != 4178 && into_syscall != 4004))
                    {
                        printf("network syscall end:%d,%d,%d, accept_fd:%d\n", into_syscall, ret,err, accept_fd);
                        sleep(10);
                    }
                    
                    if(afl_user_fork && a0 == accept_fd && 
                            (into_syscall == 4175 || into_syscall == 4003 || into_syscall == 4176))
                    {
                        char buff[4096];
                        memset(buff, 0, 4096);
                        DECAF_read_mem(cpu, a1, ret, buff);
                        DECAF_printf("recv %s, len:%d\n", buff, ret);

                    }
                    */
                    
                    if(print_debug){
                        DECAF_printf("end syscall:%d, pc:%x,stack:%x, ra:%x, ret:%x, err:%x, interrupt:%d\n", into_syscall, pc, stack, ra, ret, err, cpu->interrupt_request); 
                    }
                    before_syscall_stack = 0;
#ifdef CAL_TIME                  
                    //if(env->active_tc.gpr[7]!=0)  env->active_tc.gpr[2]=0xffffffff;  //NEED MODIFY for http accept, zywzyw
                    gettimeofday(&syscall_end, NULL);
                    time_interval = (double)syscall_end.tv_sec - syscall_begin.tv_sec + (syscall_end.tv_usec - syscall_begin.tv_usec)/1000000.0;
                    time_interval_total += time_interval;
                    //DECAF_printf("syscall execute:%f, pid:%x\n",time_interval, getpid());
                    total_syscall_codegen_time += syscall_codegen_time;
                    if(print_debug)
                    {
                        DECAF_printf("syscall execute:%f, syscall without code gen:%f, pid:%x\n",time_interval, time_interval - syscall_codegen_time, getpid());
                        //DECAF_printf("syscall codegen time:%fs,%fs\n", syscall_codegen_time, total_syscall_codegen_time);            
                    }
                    syscall_count++;
                    syscall_codegen_time = 0.0;
#endif
                    into_syscall = 0;
                    //global_into_syscall = 0;
                    //sysinfo_pop();
                   
#ifdef MEM_MAPPING
#ifdef LMBENCH
#else
                    
                    //if(!not_exit && !stay_in_full)
                    //if(!not_exit && !tmp_not_exit) //4194 4114
                    if(!not_exit) //4194 4114
                    {
                        afl_wants_cpu_to_stop = 1; // BEFORE WRITE STATE
                        goto end;
                    }
#endif //LMBENCH                                
#endif //MEM_MAPPING

#ifdef DECAF 
                }
#endif
            }

#ifdef LMBENCH
            //lat_select_debug3
            if(pc == 0x40067c && lat_select_init == 0) //init
            {
                lat_select_init = 1;
                printf("*****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
            }
            if(pc == 0x400814) //user_fork
            {
                printf("user_fork *****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
            }
            /*
            //lat_select_debug2
            if(pc == 0x4006d0 && lat_select_init == 0) //init
            {
                lat_select_init = 1;
                printf("*****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
            }
            //lat_select_debug
            if(pc == 0x4007a4 && lat_select_init == 0) //init
            {
                lat_select_init = 1;
                printf("*****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
            }
            */
            /*
            //lat_select
            if(pc == 0x400710 && lat_select_init == 0)
            {
                lat_select_init = 1;
                printf("*****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
            }
            */
            if(pc == start_fork_pc)
            {
                lmbench_count++;
                printf("*****************:%d\n",lmbench_count);
                afl_wants_cpu_to_stop = 1;
                goto end;   
                //write_state(env);
            }
            
#endif

            if(afl_user_fork) last_pc = pc;
            if(pc < 0x70000000) last_program_pc = pc;


            if(afl_user_fork && pc == 0x80133a84)
            {
                DECAF_printf("print_fatal_signal:%x\n",pc);
#ifdef FORK_OR_NOT
                int ret_value = 32;
                doneWork(ret_value);
                //goto end;
#endif
            }
            TranslationBlock *tb = tb_find(cpu, last_tb, tb_exit);
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
            /* Try to align the host and virtual clocks
               if the guest is in advance */
        }
    }
end:
    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();

    return ret;
}



#ifdef STORE_PAGE_FUNC
extern ram_addr_t qemu_ram_addr_from_host(void *ptr);

typedef struct STORE_PAGE{
    uintptr_t prev_addr;
    uintptr_t curr_addr;
    struct STORE_PAGE * page;
} STORE_PAGE;


STORE_PAGE *pt[0x1000];



void store_page(uint32_t virt_addr, uintptr_t addr, int in_httpd)
{ 
    full_store_count += 1; 
    int page_exist = 0;
    int index = (addr >> 12) & 0xfff;
    STORE_PAGE * tmp_p = pt[index];
    STORE_PAGE * last_p;
    if(tmp_p == NULL)
    {   
        STORE_PAGE * page = malloc(sizeof(STORE_PAGE));
        void * dst = malloc(0x1000);
        memset(dst, 0, 0x1000);
        void * src = addr;
        memcpy(dst, src, 0x1000);
        //full_store_count += 1; 
        uint32_t phys_addr = qemu_ram_addr_from_host(addr);
        //show_store_phys();
        //printf("index1:%x, copy finished from %lx(%lx) to %lx, int_httpd:%x\n",  virt_addr, src, phys_addr, dst, in_httpd);
        page->prev_addr = src;
        page->curr_addr = dst;
        page->page = NULL;  
        pt[index] = page;
        return;
    }
    while(tmp_p!= NULL)
    {
        last_p = tmp_p;
        //printf("store page:%lx,%lx\n", addr, tmp_p->prev_addr);
        if(addr == tmp_p->prev_addr){
            page_exist = 1;         
            return;
        }
        //printf("into list\n");
        tmp_p = tmp_p->page;
    }
    if(page_exist == 0){
        STORE_PAGE * page = malloc(sizeof(STORE_PAGE));
        void * dst = malloc(0x1000);
        memset(dst, 0, 0x1000);
        void * src = addr;
        memcpy(dst, src, 0x1000);
        //full_store_count += 1; 
        uint32_t phys_addr = qemu_ram_addr_from_host(addr);
        //printf("index2:%x, copy finished from %lx(%lx) to %lx, in_httpd:%x\n", virt_addr , src, phys_addr, dst, in_httpd);
        page->prev_addr = src;
        page->curr_addr = dst;
        page->page = NULL;  
        last_p->page = page;
    }

}

void restore_page()
{
    for(int i=0; i<0x1000; i++)
    {
        STORE_PAGE * tmp_p = pt[i]; 
        STORE_PAGE * last = NULL;
        while(tmp_p){
            last = tmp_p;
            uintptr_t dst = tmp_p-> prev_addr;
            uintptr_t src = tmp_p-> curr_addr;
            if(dst && src)
            {
                char tmp[0x1000];
                memcpy(tmp, src, 0x1000);
                memcpy(dst, tmp, 0x1000);
                //memcpy(dst, src, 0x1000);
                //printf("restore from %lx to %lx\n", src, dst);
                free(src);
                tmp_p = tmp_p->page;
                free(last);
            }
            else
            {
                printf("restore page error:%lx,%lx\n", pt[i], tmp_p);
                sleep(100);
                exit(32);
            }
            
        }
        pt[i] = NULL;
    }
}

#endif //STORE_PAGE_FUNC


#ifdef MEM_MAPPING

typedef struct MISSING_PAGE{
    target_ulong addr;
    int prot; 
    int mmu_idx;
} MISSING_PAGE;

typedef struct 
{
  double handle_state_time;
  double handle_addr_time;
  double handle_syscall_time;
  double store_page_time;
  double restore_page_time;
  int user_syscall_count;
  int user_store_count;
} USER_MODE_TIME;


#ifdef TARGET_MIPS

typedef struct CPUSHSTATE{
    target_ulong regs[32];
    target_ulong PC;
    target_ulong CP0_Status;
    target_ulong CP0_EPC;
    target_ulong CP0_Cause;
} CPUSHSTATE;

void loadCPUShState(CPUSHSTATE *state, CPUArchState *env, target_ulong *addr)
{
    for(int i=0; i<32; i++)
    {
        env->active_tc.gpr[i] = state->regs[i];
    }
    env->active_tc.PC = state->PC;
    /*
    if(*addr == 0)
    {
        env->CP0_Status = state->CP0_Status;
        env->CP0_Cause = state->CP0_Cause;
        env->CP0_EPC = state->CP0_EPC;  
    } 
    */  
}

void storeCPUShState(CPUSHSTATE *state, CPUArchState *env)
{
    for(int i=0; i<32; i++)
    {
        state->regs[i] = env->active_tc.gpr[i];
    }
    state->PC = env->active_tc.PC;
    /*
    state->CP0_Status = env->CP0_Status; 
    state->CP0_Cause = env->CP0_Cause; 
    state->CP0_EPC = env->CP0_EPC; 
    */
}



#elif defined(TARGET_ARM)

typedef struct CPUSHSTATE{
    target_ulong regs[16];
} CPUSHSTATE;

void loadCPUShState(CPUSHSTATE *state, CPUArchState *env, target_ulong *addr)
{
    for(int i=0; i<16; i++)
    {
        env->regs[i] = state->regs[i];
    }
}

void storeCPUShState(CPUSHSTATE *state, CPUArchState *env)
{
    for(int i=0; i<16; i++)
    {
        state->regs[i] = env->regs[i];
    }
}


#endif


int open_read_pipe()
{
    const char fifo_name_user[256];
    getconfig("init_read_pipename" ,fifo_name_user);
    assert(strlen(fifo_name_user)>0);
    const int open_mode_user = O_RDONLY | O_NONBLOCK; 
    int res = 0;  
    if(access(fifo_name_user, F_OK) == -1)  
    {  
        res = mkfifo(fifo_name_user, 0777);  
        if(res != 0)  
        {  
            fprintf(stderr, "Could not create fifo %s\n", fifo_name_user);  
            exit(EXIT_FAILURE);  
        }  
    } 
    pipe_read_fd = open(fifo_name_user, open_mode_user);
    if(pipe_read_fd != -1)  
    {
        return pipe_read_fd;
    }
    return -1;
}  

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

int read_state(CPUArchState * env, MISSING_PAGE *page, target_ulong *addr)  
{   
     int type;
     char buf[1024]; 
     memset(buf, 0, 1024);
     int res = 0;   
     if(pipe_read_fd != -1)
     {
        if(read_type == -1)
        {
            
            res = read_content(pipe_read_fd, &type, sizeof(int));
            if(res == -1)  
            {
                printf("after fix the pipe usage error, will not step into here");  
                return -1;
            
            }
            else if(res == 0)
            {
                printf("after fix the pipe usage error, will not step into here");  
                return -1;
            }
            else{
                //printf("res is %x, type is %x\n", res, type);
                read_type = type;
                return -1;
            }

        }
        switch (read_type){
            case 0:
            {
                res = read_content(pipe_read_fd, page, sizeof(MISSING_PAGE));
                int data = 0;
                //printf("read addr:%x\n", page->addr);
                read_type = -1;
                return 0;
            }
            case 1:
            {   
                CPUSHSTATE cpustate;
                res = read_content(pipe_read_fd, &cpustate, sizeof(CPUSHSTATE));
                loadCPUShState(&cpustate, env, addr);
                res = read_content(pipe_read_fd, addr, sizeof(target_ulong));
                //printf("read state ok:%x\n", env->active_tc.PC);
                read_type = -1; 
                return 1;
            }
            case 2:
            {
                target_ulong cmd;
                USER_MODE_TIME user_mode_time;
                res = read_content(pipe_read_fd, &cmd, sizeof(target_ulong));
                res = read_content(pipe_read_fd, &user_mode_time, sizeof(USER_MODE_TIME));
                write_cmd_resp(is_loop_over);
                if(cmd == 0x10 && is_loop_over) {
                    afl_user_fork = 1;
#ifdef CAL_TIME
                    gettimeofday(&loop_begin, NULL);
#endif
                    if(print_debug)
                    {
                       DECAF_printf("cmd is %x #######################################\n", cmd);
                    }
                    print_loop_count++;
                    //sleep(5);

                    if(first_time == 0)
                    {
                        first_time = 1;
#ifdef TARGET_MIPS
                        store_tlb(env);
#endif
                    }
                    else
                    {
#ifdef TARGET_MIPS
                       reload_tlb(env);
#endif
                    }
                    is_loop_over = 0;
                }
                else if(cmd == 0x20  && !is_loop_over) 
                {   
#ifdef CAL_TIME
                    double handle_state_time = user_mode_time.handle_state_time;
                    double handle_addr_time = user_mode_time.handle_addr_time;
                    double handle_syscall_time = user_mode_time.handle_syscall_time;
                    double user_store_page_time = user_mode_time.store_page_time;
                    double user_restore_page_time = user_mode_time.restore_page_time;
                    int user_syscall_count = user_mode_time.user_syscall_count;
                    int user_store_count = user_mode_time.user_store_count;

                    gettimeofday(&loop_end, NULL);
                    double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;
                    gettimeofday(&restore_begin, NULL);
#endif

#ifdef STORE_PAGE_FUNC
                    restore_page(); //restore_addr();
#endif

#ifdef CAL_TIME
                    gettimeofday(&restore_end, NULL);
                    double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;
                    DECAF_printf("cmd is %x #######################################\n", cmd);
                
                    if(print_debug)
                    {
                        DECAF_printf("----------------------------------------------------------\n");
                    }
                    if(print_loop_count == print_loop_times)
                    {
                        print_loop_count = 0;
                        //if(print_debug)
                        //{
                        //printf("total loop time:%fs,syacall execute:%fs, restore page time:%fs\n", total_loop_time, time_interval_total, restore_time);
                            double rest_time = total_loop_time  - full_store_page_time - restore_time - handle_state_time - handle_addr_time - user_restore_page_time- user_store_page_time;
                            DECAF_printf("FirmAFL: %f:%f:%f:%f:%f:%f:%f:%f:%f:%f:%d:%d:%d:%d\n", total_loop_time, time_interval_total,  handle_syscall_time, 
                                full_store_page_time, restore_time, user_store_page_time, user_restore_page_time, 
                                handle_state_time - time_interval_total, handle_addr_time, rest_time, 
                                syscall_count, user_syscall_count, full_store_count, user_store_count);
                        //}

                    }
                    time_interval_total = 0.0;
                    full_store_page_time = 0.0;
                    full_store_count = 0;
                    syscall_count = 0;
#endif
                    /*
                    close(pipe_write_fd);
                    pipe_write_fd = -1;
                    */     
                    is_loop_over = 1;

                    //truncate_sysinfo();

                }
                else
                {
                    printf("one loop not over, cmd:%x, is_loop_over:%d\n", cmd, is_loop_over);
                    //exit(32);
                }
                read_type = -1;
                return 2;
            }
            default:
            {
                printf("############error############ cmd is:%x\n", read_type);
                read_type = -1;
                exit(32);
            }
        }
    }  
    else{
        printf("pipe fd not right\n");    
        exit(EXIT_FAILURE);
    }  
}

int write_cmd_resp(int loop_is_over)
{
    int res = 0; 
    if(pipe_write_fd == -1){
        const char *fifo_name_full[256];
        getconfig("write_pipename", fifo_name_full);  ;
        assert(strlen(fifo_name_full)>0);
        const int open_mode_full = O_WRONLY; 
        if(access(fifo_name_full, F_OK) == -1)  
        {  
            printf("write addr mkfifo\n");
            res = mkfifo(fifo_name_full, 0777);  
            if(res != 0)  
            {  
                printf("Could not create fifo %s\n", fifo_name_full);  
                exit(EXIT_FAILURE);  
            }  
        } 
        pipe_write_fd = open(fifo_name_full, open_mode_full);  
    }
    if(pipe_write_fd != -1)  
    {  
        int bytes_read = 0;  
        res = write(pipe_write_fd, &loop_is_over, sizeof(int));  
        if(res == -1)  
        {  
            printf("Write addr error on pipe\n");  
            sleep(1000);
            exit(EXIT_FAILURE);  
        }  
    }  
    else{
        printf("write addr failure\n");
        sleep(1000);  
        exit(EXIT_FAILURE);  
    }
    return 1;
}


int write_addr(uintptr_t ori_addr, uintptr_t addr)  
{  
    int res = 0;  
    if(pipe_write_fd == -1){
        const char *fifo_name_full[256];
        getconfig("write_pipename", fifo_name_full);  ;
        assert(strlen(fifo_name_full)>0);
        const int open_mode_full = O_WRONLY; 
        if(access(fifo_name_full, F_OK) == -1)  
        {  
            printf("write addr mkfifo\n");
            res = mkfifo(fifo_name_full, 0777);  
            if(res != 0)  
            {  
                printf("Could not create fifo %s\n", fifo_name_full);  
                exit(EXIT_FAILURE);  
            }  
        } 
        pipe_write_fd = open(fifo_name_full, open_mode_full);  
    }
    if(pipe_write_fd != -1)  
    {  
        int bytes_read = 0;  
        res = write(pipe_write_fd, &addr, sizeof(uintptr_t));  
        if(res == -1)  
        {  
            printf("Write addr error on pipe\n");  
            exit(EXIT_FAILURE);  
        }  
        //printf("write addr ok:%lx, %lx\n",ori_addr, addr);
    }  
    else{
        printf("write addr failure\n");  
        exit(EXIT_FAILURE);  
    }
    return 1;
}  


int write_state(CPUArchState * env)  
{  
    int res = 0;  
    CPUSHSTATE cpustate;
    storeCPUShState(&cpustate, env);
    if(pipe_write_fd == -1)
    {
        const char *fifo_name_full[256];
        getconfig("write_pipename", fifo_name_full);
        assert(strlen(fifo_name_full)>0);
        const int open_mode_full = O_WRONLY;
        if(access(fifo_name_full, F_OK) == -1)  
        {  
            res = mkfifo(fifo_name_full, 0777);  
            if(res != 0)  
            {  
                fprintf(stderr, "Could not create fifo %s\n", fifo_name_full);  
                exit(EXIT_FAILURE);  
            }  
        } 
        pipe_write_fd = open(fifo_name_full, open_mode_full);
    }
    if(pipe_write_fd != -1)  
    {  
        int bytes_read = 0;  
        res = write(pipe_write_fd, &cpustate, sizeof(cpustate));  
        if(res == -1)  
        {  
            fprintf(stderr, "Write error on pipe\n");  
            exit(EXIT_FAILURE);  
        }  
        //printf("write state ok\n");
    }  
    else{
        printf("write state failure:%d\n", pipe_write_fd);  
        exit(EXIT_FAILURE);  
    }
    return 1;
} 


#ifdef TARGET_MIPS

MISSING_PAGE handle_page;
int ask_addr = 0;
uintptr_t res_addr;
int tcg_handle_addr = 0;
void *qemu_handle_addr_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    CPUArchState * env = cpu->env_ptr;
    int status, child_pid;
    target_ulong addr = handle_page.addr;
    MMUAccessType access_type = handle_page.prot;        
    int mmu_idx = handle_page.mmu_idx; 
    current_cpu = cpu;

    SyncClocks sc = { 0 };
    init_delay_params(&sc, cpu);
    cpu->interrupt_request = 0;// need???????????????
    cpu->exception_index = -1;
    int ret = mips_cpu_handle_mmu_fault(cpu, addr, access_type, mmu_idx);
    int index = (addr >> 12) & (256 - 1);
#ifdef TARGET_MIPS
    target_ulong orig_pc = env->active_tc.PC;
#elif defined TARGET_ARM 
    target_ulong orig_pc = env->regs[15];
#endif
    
    void *t = env->tlb_table[mmu_idx][index].addend;
    if (qemu_mutex_iothread_locked()) {
        qemu_mutex_unlock_iothread();
    }
    while(ret == 1)
    {

        if (sigsetjmp(cpu->jmp_env, 0) != 0) {
            cpu->can_do_io = 1;
            tb_lock_reset();
            if (qemu_mutex_iothread_locked()) {
                qemu_mutex_unlock_iothread();
            }
        }

        //printf("ret:%x, exception:%d, interupt:%d, pc:%x\n", ret, cpu->exception_index, cpu->interrupt_request, env->active_tc.PC);
        int ret_excep;
        while(true){
            while (!cpu_handle_exception(cpu, &ret_excep)) {
                TranslationBlock *last_tb = NULL;
                int tb_exit = 0; 
                while (!cpu_handle_interrupt(cpu, &last_tb)) {
#ifdef TARGET_MIPS
                    target_ulong cur_pc = env->active_tc.PC;
#elif defined TARGET_ARM 
                    target_ulong cur_pc = env->regs[15];
#endif                   
                     if(cur_pc < 0x80000000) {   
                        if(orig_pc == cur_pc)
                        {
                            goto label;
                        }                     
                        
                    }
                    TranslationBlock *tb = tb_find(cpu, last_tb, tb_exit); 
                    cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
                    if(mem_mapping_exit)
                    {
                        target_ulong pgd = DECAF_getPGD(cpu);
                        if(pgd == httpd_pgd)
                        {
                            mem_mapping_exit = 0;
                            printf("handle addr error\n");
                            afl_wants_cpu_to_stop = 1; // BEFORE WRITE STATE
                            goto fail;
                        }
                    }
                    align_clocks(&sc, cpu);
                }
            } 
            //printf("handler addr out of exception loop:%d,%d,%x\n", cpu->interrupt_request, cpu->exception_index, env->active_tc.PC);
        }
label:      
        //printf("label ret:%d,%x\n", ret, addr); 
        ret = mips_cpu_handle_mmu_fault(cpu, addr, access_type, mmu_idx);
        t = env->tlb_table[mmu_idx][index].addend;
    }
    res_addr = ((uintptr_t)addr + t);
    return;
fail:
    res_addr = 0;
}

#elif defined(TARGET_ARM)

MISSING_PAGE handle_page;
int ask_addr = 0;
uintptr_t res_addr;
int tcg_handle_addr = 0;
void *qemu_handle_addr_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    CPUArchState * env = cpu->env_ptr;
    int status, child_pid;
    target_ulong addr = handle_page.addr;
    MMUAccessType access_type = handle_page.prot;        
    int mmu_idx = handle_page.mmu_idx; 
    current_cpu = cpu;

    SyncClocks sc = { 0 };
    init_delay_params(&sc, cpu);
    cpu->interrupt_request = 0;// need???????????????
    cpu->exception_index = -1;
    
    uint32_t fsr = 0;
    ARMMMUFaultInfo fi = {};
    int ret = tlb_fill_helper(cpu, addr, access_type, mmu_idx);
    int index = (addr >> 12) & (256 - 1);
#ifdef TARGET_MIPS
    target_ulong orig_pc = env->active_tc.PC;
#elif defined TARGET_ARM 
    target_ulong orig_pc = env->regs[15];
#endif
    
    void *t = env->tlb_table[mmu_idx][index].addend;
    if (qemu_mutex_iothread_locked()) {
        qemu_mutex_unlock_iothread();
    }
    while(ret == 1)
    {

        if (sigsetjmp(cpu->jmp_env, 0) != 0) {
            cpu->can_do_io = 1;
            tb_lock_reset();
            if (qemu_mutex_iothread_locked()) {
                qemu_mutex_unlock_iothread();
            }
        }

        //printf("ret:%x, exception:%d, interupt:%d, pc:%x\n", ret, cpu->exception_index, cpu->interrupt_request, env->active_tc.PC);
        int ret_excep;
        while(true){
            while (!cpu_handle_exception(cpu, &ret_excep)) {
                TranslationBlock *last_tb = NULL;
                int tb_exit = 0; 
                while (!cpu_handle_interrupt(cpu, &last_tb)) {
#ifdef TARGET_MIPS
                    target_ulong cur_pc = env->active_tc.PC;
#elif defined TARGET_ARM 
                    target_ulong cur_pc = env->regs[15];
#endif                   
                     if(cur_pc < 0x80000000) {   
                        if(orig_pc == cur_pc)
                        {
                            goto label;
                        }                     
                        
                    }
                    TranslationBlock *tb = tb_find(cpu, last_tb, tb_exit); 
                    cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
                    if(mem_mapping_exit)
                    {
                        target_ulong pgd = DECAF_getPGD(cpu);
                        if(pgd == httpd_pgd)
                        {
                            mem_mapping_exit = 0;
                            printf("handle addr error\n");
                            afl_wants_cpu_to_stop = 1; // BEFORE WRITE STATE
                            goto fail;
                        }
                    }
                    align_clocks(&sc, cpu);
                }
            } 
            //printf("handler addr out of exception loop:%d,%d,%x\n", cpu->interrupt_request, cpu->exception_index, env->active_tc.PC);
        }
label:      
        //printf("label ret:%d,%x\n", ret, addr); 
        ret = tlb_fill_helper(cpu, addr, access_type, mmu_idx);
        t = env->tlb_table[mmu_idx][index].addend;
    }
    res_addr = ((uintptr_t)addr + t);
    return;
fail:
    res_addr = 0;
}


#endif


extern CPUState *restart_cpu;
extern void out_of_cpu_exec(CPUState *cpu);
void handlePiperead(void *ctx)
{

    //restart();
    //return;

    
    //CPUArchState *env = first_cpu->env_ptr;
    CPUState *cpu = restart_cpu;
    CPUArchState *env = restart_cpu->env_ptr;
    MISSING_PAGE page;

    int res = read_state(env, &page, &handle_addr);
    //printf("********read error addr:%x, %d\n", handle_addr, res);

    
// read addr
    if(res == -1)
    {
        //qemu_mutex_lock_iothread();
        return;  //zyw exit if in child process
    }
    if(res == 0)
    {
        ask_addr = page.addr;
        handle_page.addr = page.addr;
        handle_page.prot = page.prot;        
        handle_page.mmu_idx = page.mmu_idx; 
        tcg_handle_addr = 1;

        restart();
    }
    else if(res == 1){

        restart();

    }

}


#endif
