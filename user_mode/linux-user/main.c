/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/path.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "elf.h"
#include "exec/log.h"
#include "trace/control.h"
#include "glib-compat.h"

#include "zyw_config.h"

//g2h(x) ((void *)((unsigned long)(target_ulong)(x) + guest_base))

void* g2h_helper(target_ulong x)
{
    return g2h(x);
}

static void handler_s_ill(int sig_num, siginfo_t *si, void *ptr)
{
    printf("meet illegal instruction\n");
    normal_exit(0);

}


extern target_ulong last_pc;
extern pthread_mutex_t *p_mutex_shared;
int optimization_level = 0;

int program_id = 0;
int first_syscall = 0;
int accept_fd = 0;
int CP0_UserLocal = 0;

char * mem_file = "mem_file";
int parent_pid = 0;
extern int print_debug;
extern pthread_mutex_t op_mutex;
int user_syscall_flag = 0;

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

/*
static void write_ptr(CPUState* cpu, int vaddr, int pptr_addr)
{
#ifdef TARGET_WORDS_BIGENDIAN
    convert_endian_4b(&pptr_addr);
#endif
    cpu_memory_rw_debug(cpu, vaddr, &pptr_addr, 4, 1);

}
*/

char program_analysis[256];
char * aflFile;
struct timeval handle_addr_start;
struct timeval handle_addr_end;
struct timeval handle_state_start;
struct timeval handle_state_end;
struct timeval handle_syscall_start;
struct timeval handle_syscall_end;
struct timeval store_page_start;
struct timeval store_page_end;
struct timeval restore_page_start;
struct timeval restore_page_end;

double handle_addr_total = 0.0;
double handle_state_total = 0.0;
double handle_syscall_total = 0.0;
double store_page_total = 0.0;
double restore_page_total = 0.0;
int store_count = 0;
int user_syscall_count = 0;

void getconfig(char *keywords, char *final_value)
{
    FILE *fp = fopen("FirmAFL_config", "r");
    char StrLine[256];
    assert(fp);
    while (!feof(fp)) 
    { 
        char * res = fgets(StrLine,256,fp);
        if(res == NULL)
        {
            printf("FirmAFL_config has no content\n");
            exit(0);
        }
        char * key = strtok(StrLine, "=");
        char * value = strtok(NULL, "=");
        int val_len = strlen(value);
        if(value[val_len-1] == '\n')
        {
            value[val_len-1] = '\0';
        } 
        if(strcmp(keywords, key) == 0)
        {
            strcpy(final_value, value);
            break;
        }
    }
    fclose(fp); 
}


#ifdef MEM_MAPPING
#include <sys/shm.h>
#define VIRTUAL_SPA 500
int mem_file_fd;
uintptr_t hva_start;
int start_fork_pc = 0;
extern abi_ulong afl_entry_point;
extern abi_ulong afl_start_code;
extern abi_ulong afl_end_code;
int init_regs[36];

int gva_start[VIRTUAL_SPA];
int gva_end[VIRTUAL_SPA];
int gva_type[VIRTUAL_SPA];
char gva_name[VIRTUAL_SPA][100];
int gva_seq[VIRTUAL_SPA];
char last_name[100];
int vir_spa_index;

int virt_addr[VIRTUAL_SPA];
int phys_addr[VIRTUAL_SPA];
int prot[VIRTUAL_SPA];
int vir_phy_index;

int pipe_read_fd = -1;
int pipe_write_fd = -1;


extern void * snapshot_shmem_start;
extern void * snapshot_shmem_pt;
extern int snapshot_shmem_id;



typedef struct MISSING_PAGE{
    target_ulong addr;
    int prot;
    int mmu_idx; 
} MISSING_PAGE;


int file_fds[100];
int fd_index = 0;


int write_state(CPUArchState *env, target_ulong address, int prot);
int write_addr(MISSING_PAGE *page);
int read_state(target_ulong pc, CPUArchState *env);
int read_addr(target_ulong ori_addr, uintptr_t *addr);

extern void cross_process_mutex_first_init(void);
extern void cross_process_mutex_init(void);
extern void cross_shamem_disconn(void);

void add_local_fd(int fd)
{
    file_fds[fd_index++] = fd;
}

int if_exist_local_fd(int fd)
{
    if(fd == 0)
    {
        return 0;
    }
    for(int i=0; i<100; i++)
    {
        if(fd == file_fds[i])
            return 1;
    }
    return 0;
}

int if_standard_io(int fd)
{
    if(fd == 1 || fd == 2 || fd == 3)
    {
        return 1;
    }
    return 0;
}

int syscall_addr_check_flag = -1;
void syscall_addr_check(int addr, int len, int syscall)
{   
    for(int page = addr & 0xfffff000; page <= ((addr +len) & 0xfffff000); page+=0x1000)
    {

        //printf("check page:%x\n", page);
        uintptr_t *host_addr = g2h(page);
        if(syscall == 3) //read
        {

            syscall_addr_check_flag = 1; // write memory
        	*host_addr = 0;
        }
        else if(syscall == 4) //write
        {
            syscall_addr_check_flag = 0;  // read memory
            uintptr_t a = *host_addr;
            
        }
        else
        {
            syscall_addr_check_flag = 0;  // read memory
            uintptr_t a = *host_addr; //read memory
        }
    }
}





//#########################
MISSING_PAGE special_page;

#ifdef FEED_INPUT
//feed httpd
char recv_buf[4096];
int total_len = 0;
int buf_read_index = 0;

char lib_name[256];
int environ_offset; 
char feed_type[256];

//feed env
int global_addr = 0;
int environ_addr = 0;
int content_addr = 0; //replace addr
extern int libuclibc_addr;
int libuclibc_addr_flag = 0;
int replace_addr = 0;

//feed http
char http_package[50][4096];
char tmp_http_package[50][4096];
char http_key[50][100];
char http_value[50][4096];
int package_index = 0;
int feed_addr = 0;
int feed_input_times = 0; //161161

#endif

void FirmAFL_config()
{
    char opti_str[50];
    getconfig("opti", opti_str);
    if(strcmp(opti_str,"no") == 0)
    {
        optimization_level = 0;
    }
    else if(strcmp(opti_str,"yes") == 0)
    {
        optimization_level = 1;
    }
    else
    {
        printf("optimization not assigned\n");
        sleep(100);
    }

#ifdef FEED_INPUT
    getconfig("feed_type",feed_type);
    assert(strlen(feed_type)>0);

    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
        getconfig("lib_name", lib_name);
        char offset_str[256];
        getconfig("environ_offset", offset_str);
        environ_offset = strtol(offset_str, NULL, 16);
        assert(strlen(lib_name) > 0);
        assert(environ_offset!=0);
    }
#endif

    char id_str[256];
    memset(id_str, 256, 0);
    getconfig("id", id_str);
    if(strlen(id_str) > 0)
    {
        program_id = strtol(id_str, NULL, 10);
    }
}

#ifndef FEED_INPUT
void get_input(CPUState * cpu){}
#endif

#ifdef FEED_INPUT


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






int write_package(int vir_addr, char* cont)
{
    memcpy(g2h(vir_addr), cont, strlen(cont));
    //char sym = 0xd;
    //cpu_memory_rw_debug(first_cpu, vir_addr + strlen(cont), &sym , 1, 1);
    //sym = 0xa;
    //cpu_memory_rw_debug(first_cpu, vir_addr + strlen(cont) + 1, &sym, 1, 1);
    return vir_addr + strlen(cont);
}


void prepare_feed_input(CPUState * cpu)
{
    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
        int tmp_content_addr = 0;
        global_addr = libuclibc_addr + environ_offset;
        read_ptr(cpu, global_addr, &environ_addr);
        //read_ptr(cpu, environ_addr, &tmp_content_addr);         
        int tmp_env_addr = environ_addr;
        while(true)
        {
            read_ptr(cpu, tmp_env_addr, &tmp_content_addr);
            if(tmp_content_addr==0) //changed on May, 4
                break;
            char * env_content = g2h(tmp_content_addr);
            if(strstr(env_content, "HTTP_ACCEPT_ENCODING"))
            {
                content_addr = tmp_content_addr;
            }
            printf("tmp_content_addr:%x, %x, content is:%s\n", tmp_env_addr, tmp_content_addr, g2h(tmp_content_addr));
            tmp_env_addr+=4;
        }
        printf("global addr:%lx, %lx,%lx\n", global_addr,environ_addr, content_addr);
        assert(global_addr!=0 && environ_addr!=0 && content_addr!=0);
        
    }
    else if (strcmp(feed_type, "FEED_HTTP") == 0)
    {
        /*
        CPUArchState *env = cpu->env_ptr;
        feed_addr = env->active_tc.gpr[5];
        */
    }
    else if (strcmp(feed_type, "FEED_CMD") == 0)
    {
        CPUArchState *env = cpu->env_ptr;
#ifdef TARGET_MIPS
        int argv = env->active_tc.gpr[5];
#elif defined(TARGET_ARM)
        int argv = env->regs[1];
#endif
        int cmd_addr = 0;

        int content_addr = 0;
        read_ptr(cpu, argv + 4, &cmd_addr);
        read_ptr(cpu, argv + 8, &content_addr);
        printf("argv:%x,%x\n", argv, cmd_addr, content_addr);
        char * cmd = g2h(cmd_addr);
        feed_addr = content_addr;
        printf("cmd is %s, content is %s\n", cmd, g2h(feed_addr));
        
    }
    else if (strcmp(feed_type, "NONE") == 0)
    {
    }
    else
    {
        printf("prepare_feed_input error\n");
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


void get_input(CPUState * cpu)
{
    if(strcmp(feed_type, "FEED_ENV") == 0)
    {
//debug
        /*
        int tmp_env_addr = environ_addr;
        int tmp_content_addr = 0;
        //assert(tmp_env_addr!=0);
        while(true)
        {
            read_ptr(cpu, tmp_env_addr, &tmp_content_addr);
            if(tmp_content_addr==0) //changed on May, 4
                break;
            printf("tmp_content_addr:%x, %x, content is:%s\n", tmp_env_addr, tmp_content_addr, g2h(tmp_content_addr));
            tmp_env_addr+=4;
        }
        */
//

       // printf("content:%s\n\n\n", g2h(content_addr));
        CPUArchState *env = cpu->env_ptr;
        char input_buf[MAX_LEN];
        int get_len = getWork(input_buf, MAX_LEN);

        printf("check input:%d\n", getpid());
        if(check_input(input_buf, 1) == 0)
        {
            normal_exit(0);
        }

        memcpy(g2h(content_addr), input_buf, get_len); //need change exploit py code
        memset(g2h(content_addr) + get_len, 0, 1);
        //write_ptr(cpu, environ_addr + 4, 0); //important

        printf("input_buf:%s, len:%d\n", input_buf,get_len);
        //printf("content:%s\n\n\n", g2h(content_addr));

    }
    else if(strcmp(feed_type, "FEED_HTTP") == 0)
    {
        /*
        CPUArchState * env = cpu->env_ptr;
        
        memset(input_buf, 0, 4096);
        int recv_buf_len = env->active_tc.gpr[6];
        printf("recv buf len %x\n", recv_buf_len);
        int get_len = getWork(input_buf, recv_buf_len);
        //memset(g2h(feed_addr),0, 4096);
        target_ulong tmp_addr = feed_addr;

        tmp_addr = write_package(feed_addr, input_buf);
        memcpy(g2h(tmp_addr), "\0", 1); //important

        //printf("ori len:%d\n", env->active_tc.gpr[2]);
        env->active_tc.gpr[2] = strlen(g2h(feed_addr));
        printf("content is:%s, len:%d\n", g2h(feed_addr), env->active_tc.gpr[2]);
        return;
        */
        total_len = getWork(recv_buf, 4096);
        if(check_http_header(recv_buf) == 0)
        {
            //printf("recv_buf:%s\n", recv_buf);
            normal_exit(0);
        }
    }
    else if (strcmp(feed_type, "FEED_CMD") == 0)
    {
        CPUArchState * env = cpu->env_ptr;
        char input_buf[MAX_LEN];
        int get_len = getWork(input_buf, MAX_LEN);
        target_ulong tmp_addr = feed_addr;
        tmp_addr = write_package(feed_addr, input_buf);
        memcpy(g2h(tmp_addr), "\0", 1); //important

        printf("content is:%s, len:%d\n", g2h(feed_addr), tmp_addr - feed_addr);
        return;
    }
    else if(strcmp(feed_type, "NONE") == 0)
    {

    }
    else
    {
        printf("feed type error\n");
        sleep(100);
    }
}


abi_long feed_input(int syscall_num, CPUArchState *env, int *network_handle)
{
    abi_long ret = -1;
    *network_handle = 1;
    if(strcmp(feed_type,"FEED_HTTP") == 0)
    {
#ifdef TARGET_MIPS
            target_ulong pc = env->active_tc.PC;
            target_ulong a0 = env->active_tc.gpr[4];
            target_ulong a1 =env->active_tc.gpr[5];
            target_ulong a2 = env->active_tc.gpr[6];
            target_ulong a3 = env->active_tc.gpr[7];
            target_ulong ra = env->active_tc.gpr[31];

#elif defined(TARGET_ARM)
            target_ulong pc = env->regs[15];
            target_ulong a0 = env->regs[0];
            target_ulong a1 = env->regs[1];
            target_ulong a2 = env->regs[2];
            target_ulong a3 = env->regs[3];
            target_ulong ra = env->regs[14];
#endif
        if((syscall_num == 175  || syscall_num == 3 || syscall_num == 176) && (a0 == accept_fd) && feed_input_times == 0)
        {
            if(program_id == 161161)
            {
                feed_input_times++;
            }

            int flag = a3;
            int len = a2;
            char *buf = g2h(a1);

            //printf("recv :%d,%d,%d, %s\n", accept_fd, len,buf_read_index, recv_buf);
            int rest_len = total_len - buf_read_index;
            //printf("hook flag:%x, %x\n", MSG_PEEK, flag);
            if(rest_len > len)
            {
                ret = len;
                memcpy(buf, recv_buf + buf_read_index, ret);
            }
            else
            {
                ret  = rest_len;
                memcpy(buf, recv_buf + buf_read_index, ret);
            }

            if(MSG_PEEK == flag && (syscall_num == 175 || syscall_num == 176))
            {
                //printf("recv msg_peek\n");
            }
            else
            {
                buf_read_index+=ret;
                
            }
        }
        else if((a0 == accept_fd) && syscall_num == 140 )
        {
            ret = 0;
        }
        
        else if((a0 == accept_fd) && syscall_num == 178 )
        {
            ret = a2; //len
        }
        /*
        else if((env->active_tc.gpr[4]== accept_fd) && syscall_num == 55)
        {
            ret = env->active_tc.gpr[5];
        }
        */
        else if((a0 == accept_fd) && syscall_num == 4)
        {
            if(program_id == 161161)
            {
               normal_exit(syscall_num);
            }
            else
            {
                ret = a2; //len
            }
        }
        else
        {
            *network_handle = 0;
        }
    }
    
    else
    {
        *network_handle = 0;
    }
    return ret;
}           


#endif //FEED_INPUT


char mem_r_bm[65536];
char mem_w_bm[65536]; //0x7fffffff
void add_memory_rw(int page_addr, int rw)
{
    //int virt_p = page_addr &0x0fffffff;
    int virt_p = page_addr;
    int value = virt_p >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    if(rw == 0)
    {
        assert(mem_r_bm);
        mem_r_bm[index] |= 1<<position;
    }
    else if(rw == 1)
    {
        assert(mem_w_bm);
        mem_w_bm[index] |= 1<<position;
    }
}

int if_memory_rw(int page_addr, int rw)
{
#ifdef TARGET_MIPS
    /*
    int page_addr_high = page_addr & 0xf0000000;
    if( (page_addr_high != 0x70000000) && (page_addr_high != 0))
        return 0;
    int virt_p = page_addr &0x0fffffff;
    */
    if(page_addr > 0x7fffffff || page_addr < 0)
    {
        return 0;
    }
    int page_addr_high = page_addr & 0xff000000;
    if(page_addr_high == 0x7f000000)
    {
        return 1;
    }
    int virt_p = page_addr;
    int value = virt_p >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    if(rw == 0)
    {
        assert(mem_r_bm);
        return (mem_r_bm[index] & (1 << position)) !=0; 
    }
    else if(rw == 1)
    {
        assert(mem_w_bm);
        return (mem_w_bm[index] & (1 << position)) !=0; 
    }
    else
    {
        printf("error in if_memory_rw\n");
        assert(-1);
        return 0;
    }
#elif defined(TARGET_ARM)
    return 1;
#endif
}


static void handler(int, siginfo_t *si, void *ptr);

#ifdef SNAPSHOT_SYNC
extern char *phys_addr_stored_bitmap;
extern int syn_shmem_id;
#endif

#ifdef STORE_PAGE_FUNC
typedef struct{
    int virt_page;
    int phys_page;
} virt_phys_pair;

virt_phys_pair addr_pair[1000];
int addr_pair_index = 0;
#endif

#endif

#ifdef MEM_MAPPING
int exception_count = 0;

void exception_exit(int syscall_num)
{
    exception_count++;
    printf("exception count:%d\n", exception_count);
    gettimeofday(&restore_page_start, NULL);
#ifdef STORE_PAGE_FUNC
    printf("exception restore_page start\n");
    restore_page_exception();  //zyw
    printf("exception restore_page end\n");
#endif
    gettimeofday(&restore_page_end, NULL);
    restore_page_total += (double)restore_page_end.tv_sec - restore_page_start.tv_sec + (restore_page_end.tv_usec - restore_page_start.tv_usec)/1000000.0;
    /*
    if(program_id == 129780 || program_id == 129781)
    {
        remove_tmp_files();
    }
    */
    printf("gettimeofday over\n");
    if( remove("/var/tmp") != 0 )
    {
        printf("remove var/tmp error\n");
    }
    if(mkdir("var/tmp", 0777)==-1)  
    {   
        printf("mkdir  var/tmp error\n");      
    }
    printf("clean var/tmp over\n");
    if(program_id == 129781)
    {
        copy_file("/var/config/net.conf_ori", "/var/config/net.conf");
    }     
    printf("copy over\n");
    int cmd = 0x20;// restore page
    USER_MODE_TIME user_mode_time;
    user_mode_time.handle_state_time = handle_state_total;
    user_mode_time.handle_addr_time = handle_addr_total;
    user_mode_time.handle_syscall_time = handle_syscall_total;
    user_mode_time.store_page_time = store_page_total;
    user_mode_time.restore_page_time = restore_page_total;
    user_mode_time.user_syscall_count = user_syscall_count;
    user_mode_time.store_count = store_count;
    printf("exit status:%d\n\n\n\n\n\n", syscall_num);
    //write_aflcmd(cmd, &user_mode_time);
    write_aflcmd_complete(cmd, &user_mode_time);
    if(print_debug)
    {
        printf("exit syscall:%d\n\n\n\n\n\n", syscall_num);
    }
}

void normal_exit(int syscall_num)
{
    gettimeofday(&restore_page_start, NULL);
#ifdef STORE_PAGE_FUNC
    restore_page();  //zyw
#endif
    gettimeofday(&restore_page_end, NULL);
    restore_page_total += (double)restore_page_end.tv_sec - restore_page_start.tv_sec + (restore_page_end.tv_usec - restore_page_start.tv_usec)/1000000.0;
    if(program_id == 129780 || program_id == 129781)
    {
        remove_tmp_files();
    }
    if(program_id == 129781)
    {
        copy_file("/var/config/net.conf_ori", "/var/config/net.conf");
    }     
    
    int cmd = 0x20;// restore page
    USER_MODE_TIME user_mode_time;
    user_mode_time.handle_state_time = handle_state_total;
    user_mode_time.handle_addr_time = handle_addr_total;
    user_mode_time.handle_syscall_time = handle_syscall_total;
    user_mode_time.store_page_time = store_page_total;
    user_mode_time.restore_page_time = restore_page_total;
    user_mode_time.user_syscall_count = user_syscall_count;
    user_mode_time.store_count = store_count;
    printf("exit syscall:%d\n\n\n\n\n\n", syscall_num);
    //write_aflcmd(cmd, &user_mode_time);
    write_aflcmd_complete(cmd, &user_mode_time);

    exit(0);
}

void bug_exit(target_ulong addr)
{
    gettimeofday(&restore_page_start, NULL);
#ifdef STORE_PAGE_FUNC
    restore_page();  //zyw
#endif
    gettimeofday(&restore_page_end, NULL);
    restore_page_total += (double)restore_page_end.tv_sec - restore_page_start.tv_sec + (restore_page_end.tv_usec - restore_page_start.tv_usec)/1000000.0;

    if(program_id == 129780 || program_id == 129781)
    {
        remove_tmp_files();
    }
    if(program_id == 129781)
    {
        copy_file("/var/config/net.conf_ori", "/var/config/net.conf");
    }   
    int cmd = 0x20;// restore page
    USER_MODE_TIME user_mode_time;
    user_mode_time.handle_state_time = handle_state_total;
    user_mode_time.handle_addr_time = handle_addr_total;
    user_mode_time.handle_syscall_time = handle_syscall_total;
    user_mode_time.store_page_time = store_page_total;
    user_mode_time.restore_page_time = restore_page_total;
    user_mode_time.user_syscall_count = user_syscall_count;
    user_mode_time.store_count = store_count;
    //write_aflcmd(cmd, &user_mode_time);
    write_aflcmd_complete(cmd, &user_mode_time);
    /*
    if(pipe_read_fd != -1)
    {
        close(pipe_read_fd);
    }
    if(pipe_write_fd != -1)
    {
        close(pipe_write_fd);
    }
    */
    if(addr == 0)
    {
        printf("page addr 0\n");
        exit(0);
    }
    else
    {
#ifdef TARGET_MIPS
        CPUArchState *env = first_cpu->env_ptr;
        printf("exit with error:%x\n", addr);
        //printf("last pc:%x,CP0_UserLocal:%x\n", last_pc,env->active_tc.CP0_UserLocal);
#endif
        exit(32);
    }
}
#endif

int tmp_file_count = 0;
char tmp_file_names[200][100];
void add_tmp_file(char * filename)
{   
    //printf("filename:%s\n", filename);
    if(strstr(filename,"/tmp/tmpf"))
    {
        //printf("add tmp file:%s\n", filename);
        strncpy(tmp_file_names[tmp_file_count], filename, 100);
        tmp_file_count++;
    }   
}


int copy_file(char *ori, char *dst)
{

    FILE *in,*out;
    char buff[1024];
    int len;

    in = fopen(ori,"r+");
    out = fopen(dst,"w+");
    //printf("$$$$$$copy file:%d,%d\n",in, out);
 
    while(len = fread(buff,1,sizeof(buff),in))
    {
        fwrite(buff,1,len,out);
    }
    fclose(in);
    fclose(out);
    return 0;
}

void remove_tmp_files()
{
    //4010 unlink remove file
    for(int i=0; i<tmp_file_count; i++)
    {
        //printf("remove file:%s\n", tmp_file_names[i]);
        remove(tmp_file_names[i]);
    }
}

int count_142 = 0;
int count_20 = 0;

int last_syscall = 0;
int count_3 = 0;
int monitor_fd = 0;

void exit_func(int syscall_num, int program_id)
{
#ifdef MEM_MAPPING

        first_syscall++;
#ifdef TARGET_MIPS
        if (syscall_num == 1 || syscall_num == 246)
#elif defined(TARGET_ARM)
        if (syscall_num == 1 || syscall_num == 248)
#endif
        {          
            normal_exit(syscall_num);
        }
        else if(syscall_num == 142)
        {
            if(program_id == 10853 || program_id == 9925 || program_id == 105600 || program_id == 161160)
            {
                normal_exit(syscall_num); 
            }
            else if(program_id == 161161)
            {
                if(last_syscall == 142)
                {
                    last_syscall = 0;
                    normal_exit(syscall_num); 
                }
            }
        }
        else if(syscall_num == 45)
        {

            if(program_id == 10853)
            {
                normal_exit(syscall_num);
            }
            if(program_id == 161161)
            {
                 normal_exit(syscall_num);
            }
        }
        else if(syscall_num == 3)
        {
            if(program_id == 161161)
            {
                count_3++;
                if(count_3 == 3)
                {
                    count_3 = 0;
                    last_syscall = 0;
                    normal_exit(syscall_num);
                }
            }
        }
        if(syscall_num != 3)
        {
            count_3 = 0;
        }
#endif
}


int determine_local_or_not(int syscall_num, int program_id, CPUArchState *env, int *file_opti)
{  
    int file_syscall_fd = -1;
    int local_or_not = 0;
#ifdef TARGET_MIPS
    target_ulong a0 = env->active_tc.gpr[4];
    target_ulong a1 = env->active_tc.gpr[5];
#elif defined(TARGET_ARM)
    target_ulong a0 = env->regs[0];
    target_ulong a1 = env->regs[1];
#endif
    if(syscall_num == 5)
    {
        char *file_name = g2h(a0);
        printf("open file:%s, flag:%x\n", file_name, a1);
        if(program_id == 129780 || program_id == 129781)
        {
            add_tmp_file(file_name);
            chdir("/server/cgi-bin/");
        }
        if(access(file_name, 0) == 0)
        {
            *file_opti = 1;
        }
        else if((a1&0xf) !=0 )
        {
            char* c = strrchr(file_name, '/');
            char dir_name[256];
            memset(dir_name, 0, 256);
            //printf("$$$$$$$$$%lx,%lx\n", c, file_name);
            strncpy(dir_name, file_name, c - file_name);
            if(access(dir_name, 0) == 0)
            {
                *file_opti = 1;
            }
            else
            {
                *file_opti = 0;
                printf("file write dir:%s not exist\n", dir_name);
            }

        }
        else
        {
            *file_opti = 0;
        }
        if(program_id == 129780 || program_id == 129781)
        {
            //printf("current working directory: %s\n", getcwd(NULL, NULL));
            chdir("/");
        }
    }
    else if(syscall_num == 183) //socket
    {
        if(a1 == 2 || a1 == 10)
        {
            *file_opti = 1;
        } 
    }
    //read, write, close, ioctl, fcntl, _llseek, fstat
    else if(syscall_num == 3 || syscall_num == 4 || syscall_num == 6 || syscall_num == 54 
        || syscall_num == 55 || syscall_num == 140 || syscall_num == 108)
    {
        file_syscall_fd = a0;
    }
    else if(syscall_num == 170 || syscall_num == 178 || syscall_num == 142) //connect, send, _newselect
    {
        file_syscall_fd = a0;
    }
    else
    {
        file_syscall_fd = -1;
    }
//local_or_not

    if(program_id == 90501)
    {
        local_or_not = 1;
    }
    else if(syscall_num == 85 || syscall_num == 10 || syscall_num == 38 || syscall_num == 40)// readlink, unlink, rename , rmdir
    {
        char *file_name = g2h(a0);
        if(access(file_name, 0) == 0)
        {
            local_or_not = 1;
        }
    }
    else if(syscall_num == 106) //stat
    {
        char *file_name = g2h(a0);
        local_or_not = 1;
    }
                   
    else if (if_standard_io(file_syscall_fd))
    {
        if(program_id== 90500 || program_id == 90501) 
        {
            local_or_not = 1; //zyw
        }
        else
        {   
            
            local_or_not = 2;
        }
    }
    else if((*file_opti == 1) || if_exist_local_fd(file_syscall_fd))
    {
        local_or_not = 1;
    }
    else if(program_id == 10566 || program_id == 9054) //hnap
    {
        if(syscall_num == 194) // rt_sigaction
        {
            local_or_not = 1;
        }
    }
    //nbench_new
     //else if(syscall_num == 283 || syscall_num == 43) //set_thread_area
    else if(syscall_num == 283 || syscall_num == 90 || syscall_num == 91 || syscall_num == 43) //set_thread_area
    {
        if(program_id == 90500 || program_id == 90501)
        {
            local_or_not = 1;
        }
    }
    
    //lat_syscall null
    else if(syscall_num == 64 && program_id == 90501) //getppid
    {
        local_or_not = 1;
    }
    
    //else if(syscall_num == 42 || syscall_num == 77 || syscall_num == 78) //pipe
    //{
    //    local_or_not = 1;
    //}
   
    
    //else if(syscall_num == 39 || syscall_num == 40) //mkdir, rmdir
    //{
    //    char *file_name = g2h(env->active_tc.gpr[4]);
    //    printf("************dir syscall %d:%s\n",syscall_num, file_name);
    //    local_or_not = 1;
    //}


    int condition = 0;
    if(optimization_level== 0)
    {
        condition = 0;
    }
    else if(optimization_level== 1)
    {
        
        if(program_id == 105609)
        {
            condition = 1;
        }
        else if(program_id == 10853)
        {
            if(syscall_num == 178)
            {
                condition = 1;
            }
            else
            {
                condition = local_or_not;
                printf("opti:%d\n", condition);
            }
        }
        else
        {

            condition = local_or_not;
        }             
    }
    return condition;
}


char *exec_path;

int singlestep;
static const char *filename;
static const char *argv0;
static int gdbstub_port;
static envlist_t *envlist;
static const char *cpu_model;
unsigned long mmap_min_addr;
unsigned long guest_base;
int have_guest_base;

#define EXCP_DUMP(env, fmt, ...)                                        \
do {                                                                    \
    CPUState *cs = ENV_GET_CPU(env);                                    \
    fprintf(stderr, fmt , ## __VA_ARGS__);                              \
    cpu_dump_state(cs, stderr, fprintf, 0);                             \
    if (qemu_log_separate()) {                                          \
        qemu_log(fmt, ## __VA_ARGS__);                                  \
        log_cpu_state(cs, 0);                                           \
    }                                                                   \
} while (0)

#if (TARGET_LONG_BITS == 32) && (HOST_LONG_BITS == 64)
/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 */
# if defined(TARGET_MIPS) || defined(TARGET_NIOS2)
/*
 * MIPS only supports 31 bits of virtual address space for user space.
 * Nios2 also only supports 31 bits.
 */
#ifdef MEM_MAPPING 
unsigned long reserved_va = 0x80000000;
#else
unsigned long reserved_va = 0x77000000;
#endif
# else
unsigned long reserved_va = 0xf7000000;
# endif
#else
unsigned long reserved_va;
#endif

static void usage(int exitcode);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    cpu_list_lock();
    qemu_mutex_lock(&tcg_ctx.tb_ctx.tb_lock);
    mmap_fork_start();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu;
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE(&cpus, cpu, node);
            }
        }
        qemu_mutex_init(&tcg_ctx.tb_ctx.tb_lock);
        qemu_init_cpu_list();
        gdbserver_fork(thread_cpu);
    } else {
        qemu_mutex_unlock(&tcg_ctx.tb_ctx.tb_lock);
        cpu_list_unlock();
    }
}

#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_host_ticks();
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
                     int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
#ifdef TARGET_X86_64
static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}
#else
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
                     uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate(idt_table + n, 0, dpl, 0, 0);
}
#endif

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;
    abi_ulong pc;
    abi_ulong ret;
    target_siginfo_t info;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case 0x80:
            /* linux syscall from int $0x80 */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EBX],
                             env->regs[R_ECX],
                             env->regs[R_EDX],
                             env->regs[R_ESI],
                             env->regs[R_EDI],
                             env->regs[R_EBP],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
#ifndef TARGET_ABI32
        case EXCP_SYSCALL:
            /* linux syscall from syscall instruction */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EDI],
                             env->regs[R_ESI],
                             env->regs[R_EDX],
                             env->regs[10],
                             env->regs[8],
                             env->regs[9],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
#endif
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP0E_PAGE:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP00_DIVZ:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                /* division by zero */
                info.si_signo = TARGET_SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = TARGET_SIGTRAP;
                info.si_errno = 0;
                if (trapnr == EXCP01_DB) {
                    info.si_code = TARGET_TRAP_BRKPT;
                    info._sifields._sigfault._addr = env->eip;
                } else {
                    info.si_code = TARGET_SI_KERNEL;
                    info._sifields._sigfault._addr = 0;
                }
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP06_ILLOP:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            EXCP_DUMP(env, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                      (long)pc, trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif

#ifdef TARGET_ARM

#define get_user_code_u32(x, gaddr, env)                \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && bswap_code(arm_sctlr_b(env))) {     \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_code_u16(x, gaddr, env)                \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && bswap_code(arm_sctlr_b(env))) {     \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_data_u32(x, gaddr, env)                \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && arm_cpu_bswap_data(env)) {          \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_data_u16(x, gaddr, env)                \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && arm_cpu_bswap_data(env)) {          \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

#define put_user_data_u32(x, gaddr, env)                \
    ({ typeof(x) __x = (x);                             \
        if (arm_cpu_bswap_data(env)) {                  \
            __x = bswap32(__x);                         \
        }                                               \
        put_user_u32(__x, (gaddr));                     \
    })

#define put_user_data_u16(x, gaddr, env)                \
    ({ typeof(x) __x = (x);                             \
        if (arm_cpu_bswap_data(env)) {                  \
            __x = bswap16(__x);                         \
        }                                               \
        put_user_u16(__x, (gaddr));                     \
    })

#ifdef TARGET_ABI32
/* Commpage handling -- there is no commpage for AArch64 */

/*
 * See the Linux kernel's Documentation/arm/kernel_user_helpers.txt
 * Input:
 * r0 = pointer to oldval
 * r1 = pointer to newval
 * r2 = pointer to target value
 *
 * Output:
 * r0 = 0 if *ptr was changed, non-0 if no exchange happened
 * C set if *ptr was changed, clear if no exchange happened
 *
 * Note segv's in kernel helpers are a bit tricky, we can set the
 * data address sensibly but the PC address is just the entry point.
 */
static void arm_kernel_cmpxchg64_helper(CPUARMState *env)
{
    uint64_t oldval, newval, val;
    uint32_t addr, cpsr;
    target_siginfo_t info;

    /* Based on the 32 bit code in do_kernel_trap */

    /* XXX: This only works between threads, not between processes.
       It's probably possible to implement this with native host
       operations. However things like ldrex/strex are much harder so
       there's not much point trying.  */
    start_exclusive();
    cpsr = cpsr_read(env);
    addr = env->regs[2];

    if (get_user_u64(oldval, env->regs[0])) {
        env->exception.vaddress = env->regs[0];
        goto segv;
    };

    if (get_user_u64(newval, env->regs[1])) {
        env->exception.vaddress = env->regs[1];
        goto segv;
    };

    if (get_user_u64(val, addr)) {
        env->exception.vaddress = addr;
        goto segv;
    }

    if (val == oldval) {
        val = newval;

        if (put_user_u64(val, addr)) {
            env->exception.vaddress = addr;
            goto segv;
        };

        env->regs[0] = 0;
        cpsr |= CPSR_C;
    } else {
        env->regs[0] = -1;
        cpsr &= ~CPSR_C;
    }
    cpsr_write(env, cpsr, CPSR_C, CPSRWriteByInstr);
    end_exclusive();
    return;

segv:
    end_exclusive();
    /* We get the PC of the entry address - which is as good as anything,
       on a real kernel what you get depends on which mode it uses. */
    info.si_signo = TARGET_SIGSEGV;
    info.si_errno = 0;
    /* XXX: check env->error_code */
    info.si_code = TARGET_SEGV_MAPERR;
    info._sifields._sigfault._addr = env->exception.vaddress;
    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
}

/* Handle a jump to the kernel code page.  */
static int
do_kernel_trap(CPUARMState *env)
{
    uint32_t addr;
    uint32_t cpsr;
    uint32_t val;

    switch (env->regs[15]) {
    case 0xffff0fa0: /* __kernel_memory_barrier */
        /* ??? No-op. Will need to do better for SMP.  */
        break;
    case 0xffff0fc0: /* __kernel_cmpxchg */
         /* XXX: This only works between threads, not between processes.
            It's probably possible to implement this with native host
            operations. However things like ldrex/strex are much harder so
            there's not much point trying.  */
        start_exclusive();
        cpsr = cpsr_read(env);
        addr = env->regs[2];
        /* FIXME: This should SEGV if the access fails.  */
        if (get_user_u32(val, addr))
            val = ~env->regs[0];
        if (val == env->regs[0]) {
            val = env->regs[1];
            /* FIXME: Check for segfaults.  */
            put_user_u32(val, addr);
            env->regs[0] = 0;
            cpsr |= CPSR_C;
        } else {
            env->regs[0] = -1;
            cpsr &= ~CPSR_C;
        }
        cpsr_write(env, cpsr, CPSR_C, CPSRWriteByInstr);
        end_exclusive();
        break;
    case 0xffff0fe0: /* __kernel_get_tls */
        env->regs[0] = cpu_get_tls(env);
        break;
    case 0xffff0f60: /* __kernel_cmpxchg64 */
        arm_kernel_cmpxchg64_helper(env);
        break;

    default:
        return 1;
    }
    /* Jump back to the caller.  */
    addr = env->regs[14];
    if (addr & 1) {
        env->thumb = 1;
        addr &= ~1;
    }
    env->regs[15] = addr;

    return 0;
}

void cpu_loop(CPUARMState *env)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int trapnr;
    unsigned int n, insn;
    target_siginfo_t info;
    uint32_t addr;
    abi_ulong ret;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case EXCP_UDEF:
        case EXCP_NOCP:
        case EXCP_INVSTATE:
            {
                TaskState *ts = cs->opaque;
                uint32_t opcode;
                int rc;

                /* we handle the FPU emulation here, as Linux */
                /* we get the opcode */
                /* FIXME - what to do if get_user() fails? */
                get_user_code_u32(opcode, env->regs[15], env);

                rc = EmulateAll(opcode, &ts->fpa, env);
                if (rc == 0) { /* illegal instruction */
                    info.si_signo = TARGET_SIGILL;
                    info.si_errno = 0;
                    info.si_code = TARGET_ILL_ILLOPN;
                    info._sifields._sigfault._addr = env->regs[15];
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                } else if (rc < 0) { /* FP exception */
                    int arm_fpe=0;

                    /* translate softfloat flags to FPSR flags */
                    if (-rc & float_flag_invalid)
                      arm_fpe |= BIT_IOC;
                    if (-rc & float_flag_divbyzero)
                      arm_fpe |= BIT_DZC;
                    if (-rc & float_flag_overflow)
                      arm_fpe |= BIT_OFC;
                    if (-rc & float_flag_underflow)
                      arm_fpe |= BIT_UFC;
                    if (-rc & float_flag_inexact)
                      arm_fpe |= BIT_IXC;

                    FPSR fpsr = ts->fpa.fpsr;
                    //printf("fpsr 0x%x, arm_fpe 0x%x\n",fpsr,arm_fpe);

                    if (fpsr & (arm_fpe << 16)) { /* exception enabled? */
                      info.si_signo = TARGET_SIGFPE;
                      info.si_errno = 0;

                      /* ordered by priority, least first */
                      if (arm_fpe & BIT_IXC) info.si_code = TARGET_FPE_FLTRES;
                      if (arm_fpe & BIT_UFC) info.si_code = TARGET_FPE_FLTUND;
                      if (arm_fpe & BIT_OFC) info.si_code = TARGET_FPE_FLTOVF;
                      if (arm_fpe & BIT_DZC) info.si_code = TARGET_FPE_FLTDIV;
                      if (arm_fpe & BIT_IOC) info.si_code = TARGET_FPE_FLTINV;

                      info._sifields._sigfault._addr = env->regs[15];
                      queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                    } else {
                      env->regs[15] += 4;
                    }

                    /* accumulate unenabled exceptions */
                    if ((!(fpsr & BIT_IXE)) && (arm_fpe & BIT_IXC))
                      fpsr |= BIT_IXC;
                    if ((!(fpsr & BIT_UFE)) && (arm_fpe & BIT_UFC))
                      fpsr |= BIT_UFC;
                    if ((!(fpsr & BIT_OFE)) && (arm_fpe & BIT_OFC))
                      fpsr |= BIT_OFC;
                    if ((!(fpsr & BIT_DZE)) && (arm_fpe & BIT_DZC))
                      fpsr |= BIT_DZC;
                    if ((!(fpsr & BIT_IOE)) && (arm_fpe & BIT_IOC))
                      fpsr |= BIT_IOC;
                    ts->fpa.fpsr=fpsr;
                } else { /* everything OK */
                    /* increment PC */
                    env->regs[15] += 4;
                }
            }
            break;
        case EXCP_SWI:
        case EXCP_BKPT:
            {
                env->eabi = 1;
                /* system call */
                if (trapnr == EXCP_BKPT) {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15], env);
                        n = insn & 0xff;
                        env->regs[15] += 2;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15], env);
                        n = (insn & 0xf) | ((insn >> 4) & 0xff0);
                        env->regs[15] += 4;
                    }
                } else {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15] - 2, env);
                        n = insn & 0xff;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15] - 4, env);
                        n = insn & 0xffffff;
                    }
                }

                if (n == ARM_NR_cacheflush) {
                    /* nop */
                } else if (n == ARM_NR_semihosting
                           || n == ARM_NR_thumb_semihosting) {
                    env->regs[0] = do_arm_semihosting (env);
                } else if (n == 0 || n >= ARM_SYSCALL_BASE || env->thumb) {
                    /* linux syscall */
                    if (env->thumb || n == 0) {
                        n = env->regs[7];
                    } else {
                        n -= ARM_SYSCALL_BASE;
                        env->eabi = 0;
                    }
                    if ( n > ARM_NR_BASE) {
                        switch (n) {
                        case ARM_NR_cacheflush:
                            /* nop */
                            break;
                        case ARM_NR_set_tls:
                            cpu_set_tls(env, env->regs[0]);
                            env->regs[0] = 0;
                            break;
                        case ARM_NR_breakpoint:
                            env->regs[15] -= env->thumb ? 2 : 4;
                            goto excp_debug;
                        default:
                            gemu_log("qemu: Unsupported ARM syscall: 0x%x\n",
                                     n);
                            env->regs[0] = -TARGET_ENOSYS;
                            break;
                        }
                    } else {
                        printf("syscall:%d\n", n);
                        printf("syscall start pc:%x\n", env->regs[15]);
                        exit_func(n, program_id);
#ifdef MEM_MAPPING
                        int file_opti = 0;        
                        int local_or_not = determine_local_or_not(n, program_id, env, &file_opti);
                        if(local_or_not)
                        {
#endif
                        ret = do_syscall(env,
                                         n,
                                         env->regs[0],
                                         env->regs[1],
                                         env->regs[2],
                                         env->regs[3],
                                         env->regs[4],
                                         env->regs[5],
                                         0, 0);
                        printf("syscall end pc:%x\n", env->regs[15]);
#ifdef MEM_MAPPING
                        }
                        else
                        {
                            env->regs[15] -= 4; //very important
                            write_state(env, 0, 0);
                            read_state(env->regs[15], env);
                            ret = env->regs[0];
                            printf("remote syscall end:%d\n", ret);
                            printf("syscall end pc:%x\n", env->regs[15]);
                            if(n == 20)
                            {
                                int ttttbuf;
                                cpu_memory_rw_debug(cs, 0x9c904, &ttttbuf, 4, 0);
                                printf("9c904:%x\n", ttttbuf);

                            }
                        }
#endif
                        if (ret == -TARGET_ERESTARTSYS) {
                            env->regs[15] -= env->thumb ? 2 : 4;
                        } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                            env->regs[0] = ret;
                        }
                    }
                } else {
                    goto error;
                }
            }
            break;
        case EXCP_SEMIHOST:
            env->regs[0] = do_arm_semihosting(env);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_PREFETCH_ABORT:
        case EXCP_DATA_ABORT:
            addr = env->exception.vaddress;
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = addr;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DEBUG:
        excp_debug:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_KERNEL_TRAP:
            if (do_kernel_trap(env))
              goto error;
            break;
        case EXCP_YIELD:
            /* nothing to do here for user-mode, just resume guest code */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
        error:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}

#else

/* AArch64 main loop */
void cpu_loop(CPUARMState *env)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int trapnr, sig;
    abi_long ret;
    target_siginfo_t info;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_SWI:
            ret = do_syscall(env,
                             env->xregs[8],
                             env->xregs[0],
                             env->xregs[1],
                             env->xregs[2],
                             env->xregs[3],
                             env->xregs[4],
                             env->xregs[5],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->xregs[0] = ret;
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_UDEF:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_PREFETCH_ABORT:
        case EXCP_DATA_ABORT:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            /* XXX: check env->error_code */
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->exception.vaddress;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_DEBUG:
        case EXCP_BKPT:
            sig = gdb_handlesig(cs, TARGET_SIGTRAP);
            if (sig) {
                info.si_signo = sig;
                info.si_errno = 0;
                info.si_code = TARGET_TRAP_BRKPT;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_SEMIHOST:
            env->xregs[0] = do_arm_semihosting(env);
            break;
        case EXCP_YIELD:
            /* nothing to do here for user-mode, just resume guest code */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
        /* Exception return on AArch64 always clears the exclusive monitor,
         * so any return to running guest code implies this.
         */
        env->exclusive_addr = -1;
    }
}
#endif /* ndef TARGET_ABI32 */

#endif

#ifdef TARGET_UNICORE32

void cpu_loop(CPUUniCore32State *env)
{
    CPUState *cs = CPU(uc32_env_get_cpu(env));
    int trapnr;
    unsigned int n, insn;
    target_siginfo_t info;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case UC32_EXCP_PRIV:
            {
                /* system call */
                get_user_u32(insn, env->regs[31] - 4);
                n = insn & 0xffffff;

                if (n >= UC32_SYSCALL_BASE) {
                    /* linux syscall */
                    n -= UC32_SYSCALL_BASE;
                    if (n == UC32_SYSCALL_NR_set_tls) {
                            cpu_set_tls(env, env->regs[0]);
                            env->regs[0] = 0;
                    } else {
                        abi_long ret = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                        if (ret == -TARGET_ERESTARTSYS) {
                            env->regs[31] -= 4;
                        } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                            env->regs[0] = ret;
                        }
                    }
                } else {
                    goto error;
                }
            }
            break;
        case UC32_EXCP_DTRAP:
        case UC32_EXCP_ITRAP:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            /* XXX: check env->error_code */
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->cp0.c4_faultaddr;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig) {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            goto error;
        }
        process_pending_signals(env);
    }

error:
    EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
    abort();
}
#endif

#ifdef TARGET_SPARC
#define SPARC64_STACK_BIAS 2047

//#define DEBUG_WIN

/* WARNING: dealing with register windows _is_ complicated. More info
   can be found at http://www.sics.se/~psm/sparcstack.html */
static inline int get_reg_index(CPUSPARCState *env, int cwp, int index)
{
    index = (index + cwp * 16) % (16 * env->nwindows);
    /* wrap handling : if cwp is on the last window, then we use the
       registers 'after' the end */
    if (index < 8 && env->cwp == env->nwindows - 1)
        index += 16 * env->nwindows;
    return index;
}

/* save the register window 'cwp1' */
static inline void save_window_offset(CPUSPARCState *env, int cwp1)
{
    unsigned int i;
    abi_ulong sp_ptr;

    sp_ptr = env->regbase[get_reg_index(env, cwp1, 6)];
#ifdef TARGET_SPARC64
    if (sp_ptr & 3)
        sp_ptr += SPARC64_STACK_BIAS;
#endif
#if defined(DEBUG_WIN)
    printf("win_overflow: sp_ptr=0x" TARGET_ABI_FMT_lx " save_cwp=%d\n",
           sp_ptr, cwp1);
#endif
    for(i = 0; i < 16; i++) {
        /* FIXME - what to do if put_user() fails? */
        put_user_ual(env->regbase[get_reg_index(env, cwp1, 8 + i)], sp_ptr);
        sp_ptr += sizeof(abi_ulong);
    }
}

static void save_window(CPUSPARCState *env)
{
#ifndef TARGET_SPARC64
    unsigned int new_wim;
    new_wim = ((env->wim >> 1) | (env->wim << (env->nwindows - 1))) &
        ((1LL << env->nwindows) - 1);
    save_window_offset(env, cpu_cwp_dec(env, env->cwp - 2));
    env->wim = new_wim;
#else
    save_window_offset(env, cpu_cwp_dec(env, env->cwp - 2));
    env->cansave++;
    env->canrestore--;
#endif
}

static void restore_window(CPUSPARCState *env)
{
#ifndef TARGET_SPARC64
    unsigned int new_wim;
#endif
    unsigned int i, cwp1;
    abi_ulong sp_ptr;

#ifndef TARGET_SPARC64
    new_wim = ((env->wim << 1) | (env->wim >> (env->nwindows - 1))) &
        ((1LL << env->nwindows) - 1);
#endif

    /* restore the invalid window */
    cwp1 = cpu_cwp_inc(env, env->cwp + 1);
    sp_ptr = env->regbase[get_reg_index(env, cwp1, 6)];
#ifdef TARGET_SPARC64
    if (sp_ptr & 3)
        sp_ptr += SPARC64_STACK_BIAS;
#endif
#if defined(DEBUG_WIN)
    printf("win_underflow: sp_ptr=0x" TARGET_ABI_FMT_lx " load_cwp=%d\n",
           sp_ptr, cwp1);
#endif
    for(i = 0; i < 16; i++) {
        /* FIXME - what to do if get_user() fails? */
        get_user_ual(env->regbase[get_reg_index(env, cwp1, 8 + i)], sp_ptr);
        sp_ptr += sizeof(abi_ulong);
    }
#ifdef TARGET_SPARC64
    env->canrestore++;
    if (env->cleanwin < env->nwindows - 1)
        env->cleanwin++;
    env->cansave--;
#else
    env->wim = new_wim;
#endif
}

static void flush_windows(CPUSPARCState *env)
{
    int offset, cwp1;

    offset = 1;
    for(;;) {
        /* if restore would invoke restore_window(), then we can stop */
        cwp1 = cpu_cwp_inc(env, env->cwp + offset);
#ifndef TARGET_SPARC64
        if (env->wim & (1 << cwp1))
            break;
#else
        if (env->canrestore == 0)
            break;
        env->cansave++;
        env->canrestore--;
#endif
        save_window_offset(env, cwp1);
        offset++;
    }
    cwp1 = cpu_cwp_inc(env, env->cwp + 1);
#ifndef TARGET_SPARC64
    /* set wim so that restore will reload the registers */
    env->wim = 1 << cwp1;
#endif
#if defined(DEBUG_WIN)
    printf("flush_windows: nb=%d\n", offset - 1);
#endif
}

void cpu_loop (CPUSPARCState *env)
{
    CPUState *cs = CPU(sparc_env_get_cpu(env));
    int trapnr;
    abi_long ret;
    target_siginfo_t info;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        /* Compute PSR before exposing state.  */
        if (env->cc_op != CC_OP_FLAGS) {
            cpu_get_psr(env);
        }

        switch (trapnr) {
#ifndef TARGET_SPARC64
        case 0x88:
        case 0x90:
#else
        case 0x110:
        case 0x16d:
#endif
            ret = do_syscall (env, env->gregs[1],
                              env->regwptr[0], env->regwptr[1],
                              env->regwptr[2], env->regwptr[3],
                              env->regwptr[4], env->regwptr[5],
                              0, 0);
            if (ret == -TARGET_ERESTARTSYS || ret == -TARGET_QEMU_ESIGRETURN) {
                break;
            }
            if ((abi_ulong)ret >= (abi_ulong)(-515)) {
#if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
                env->xcc |= PSR_CARRY;
#else
                env->psr |= PSR_CARRY;
#endif
                ret = -ret;
            } else {
#if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
                env->xcc &= ~PSR_CARRY;
#else
                env->psr &= ~PSR_CARRY;
#endif
            }
            env->regwptr[0] = ret;
            /* next instruction */
            env->pc = env->npc;
            env->npc = env->npc + 4;
            break;
        case 0x83: /* flush windows */
#ifdef TARGET_ABI32
        case 0x103:
#endif
            flush_windows(env);
            /* next instruction */
            env->pc = env->npc;
            env->npc = env->npc + 4;
            break;
#ifndef TARGET_SPARC64
        case TT_WIN_OVF: /* window overflow */
            save_window(env);
            break;
        case TT_WIN_UNF: /* window underflow */
            restore_window(env);
            break;
        case TT_TFAULT:
        case TT_DFAULT:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->mmuregs[4];
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
#else
        case TT_SPILL: /* window overflow */
            save_window(env);
            break;
        case TT_FILL: /* window underflow */
            restore_window(env);
            break;
        case TT_TFAULT:
        case TT_DFAULT:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                if (trapnr == TT_DFAULT)
                    info._sifields._sigfault._addr = env->dmmu.mmuregs[4];
                else
                    info._sifields._sigfault._addr = cpu_tsptr(env)->tpc;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
#ifndef TARGET_ABI32
        case 0x16e:
            flush_windows(env);
            sparc64_get_context(env);
            break;
        case 0x16f:
            flush_windows(env);
            sparc64_set_context(env);
            break;
#endif
#endif
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case TT_ILL_INSN:
            {
                info.si_signo = TARGET_SIGILL;
                info.si_errno = 0;
                info.si_code = TARGET_ILL_ILLOPC;
                info._sifields._sigfault._addr = env->pc;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);
    }
}

#endif

#ifdef TARGET_PPC
static inline uint64_t cpu_ppc_get_tb(CPUPPCState *env)
{
    return cpu_get_host_ticks();
}

uint64_t cpu_ppc_load_tbl(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env);
}

uint32_t cpu_ppc_load_tbu(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env) >> 32;
}

uint64_t cpu_ppc_load_atbl(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env);
}

uint32_t cpu_ppc_load_atbu(CPUPPCState *env)
{
    return cpu_ppc_get_tb(env) >> 32;
}

uint32_t cpu_ppc601_load_rtcu(CPUPPCState *env)
__attribute__ (( alias ("cpu_ppc_load_tbu") ));

uint32_t cpu_ppc601_load_rtcl(CPUPPCState *env)
{
    return cpu_ppc_load_tbl(env) & 0x3FFFFF80;
}

/* XXX: to be fixed */
int ppc_dcr_read (ppc_dcr_t *dcr_env, int dcrn, uint32_t *valp)
{
    return -1;
}

int ppc_dcr_write (ppc_dcr_t *dcr_env, int dcrn, uint32_t val)
{
    return -1;
}

static int do_store_exclusive(CPUPPCState *env)
{
    target_ulong addr;
    target_ulong page_addr;
    target_ulong val, val2 __attribute__((unused)) = 0;
    int flags;
    int segv = 0;

    addr = env->reserve_ea;
    page_addr = addr & TARGET_PAGE_MASK;
    start_exclusive();
    mmap_lock();
    flags = page_get_flags(page_addr);
    if ((flags & PAGE_READ) == 0) {
        segv = 1;
    } else {
        int reg = env->reserve_info & 0x1f;
        int size = env->reserve_info >> 5;
        int stored = 0;

        if (addr == env->reserve_addr) {
            switch (size) {
            case 1: segv = get_user_u8(val, addr); break;
            case 2: segv = get_user_u16(val, addr); break;
            case 4: segv = get_user_u32(val, addr); break;
#if defined(TARGET_PPC64)
            case 8: segv = get_user_u64(val, addr); break;
            case 16: {
                segv = get_user_u64(val, addr);
                if (!segv) {
                    segv = get_user_u64(val2, addr + 8);
                }
                break;
            }
#endif
            default: abort();
            }
            if (!segv && val == env->reserve_val) {
                val = env->gpr[reg];
                switch (size) {
                case 1: segv = put_user_u8(val, addr); break;
                case 2: segv = put_user_u16(val, addr); break;
                case 4: segv = put_user_u32(val, addr); break;
#if defined(TARGET_PPC64)
                case 8: segv = put_user_u64(val, addr); break;
                case 16: {
                    if (val2 == env->reserve_val2) {
                        if (msr_le) {
                            val2 = val;
                            val = env->gpr[reg+1];
                        } else {
                            val2 = env->gpr[reg+1];
                        }
                        segv = put_user_u64(val, addr);
                        if (!segv) {
                            segv = put_user_u64(val2, addr + 8);
                        }
                    }
                    break;
                }
#endif
                default: abort();
                }
                if (!segv) {
                    stored = 1;
                }
            }
        }
        env->crf[0] = (stored << 1) | xer_so;
        env->reserve_addr = (target_ulong)-1;
    }
    if (!segv) {
        env->nip += 4;
    }
    mmap_unlock();
    end_exclusive();
    return segv;
}

void cpu_loop(CPUPPCState *env)
{
    CPUState *cs = CPU(ppc_env_get_cpu(env));
    target_siginfo_t info;
    int trapnr;
    target_ulong ret;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case POWERPC_EXCP_NONE:
            /* Just go on */
            break;
        case POWERPC_EXCP_CRITICAL: /* Critical input                        */
            cpu_abort(cs, "Critical interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_MCHECK:   /* Machine check exception               */
            cpu_abort(cs, "Machine check exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_DSI:      /* Data storage exception                */
            /* XXX: check this. Seems bugged */
            switch (env->error_code & 0xFF000000) {
            case 0x40000000:
            case 0x42000000:
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                break;
            case 0x04000000:
                info.si_signo = TARGET_SIGILL;
                info.si_errno = 0;
                info.si_code = TARGET_ILL_ILLADR;
                break;
            case 0x08000000:
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_ACCERR;
                break;
            default:
                /* Let's send a regular segfault... */
                EXCP_DUMP(env, "Invalid segfault errno (%02x)\n",
                          env->error_code);
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                break;
            }
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_ISI:      /* Instruction storage exception         */
            /* XXX: check this */
            switch (env->error_code & 0xFF000000) {
            case 0x40000000:
                info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                break;
            case 0x10000000:
            case 0x08000000:
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_ACCERR;
                break;
            default:
                /* Let's send a regular segfault... */
                EXCP_DUMP(env, "Invalid segfault errno (%02x)\n",
                          env->error_code);
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                break;
            }
            info._sifields._sigfault._addr = env->nip - 4;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_EXTERNAL: /* External input                        */
            cpu_abort(cs, "External interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_ALIGN:    /* Alignment exception                   */
            /* XXX: check this */
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_BUS_ADRALN;
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_PROGRAM:  /* Program exception                     */
        case POWERPC_EXCP_HV_EMU:   /* HV emulation                          */
            /* XXX: check this */
            switch (env->error_code & ~0xF) {
            case POWERPC_EXCP_FP:
                info.si_signo = TARGET_SIGFPE;
                info.si_errno = 0;
                switch (env->error_code & 0xF) {
                case POWERPC_EXCP_FP_OX:
                    info.si_code = TARGET_FPE_FLTOVF;
                    break;
                case POWERPC_EXCP_FP_UX:
                    info.si_code = TARGET_FPE_FLTUND;
                    break;
                case POWERPC_EXCP_FP_ZX:
                case POWERPC_EXCP_FP_VXZDZ:
                    info.si_code = TARGET_FPE_FLTDIV;
                    break;
                case POWERPC_EXCP_FP_XX:
                    info.si_code = TARGET_FPE_FLTRES;
                    break;
                case POWERPC_EXCP_FP_VXSOFT:
                    info.si_code = TARGET_FPE_FLTINV;
                    break;
                case POWERPC_EXCP_FP_VXSNAN:
                case POWERPC_EXCP_FP_VXISI:
                case POWERPC_EXCP_FP_VXIDI:
                case POWERPC_EXCP_FP_VXIMZ:
                case POWERPC_EXCP_FP_VXVC:
                case POWERPC_EXCP_FP_VXSQRT:
                case POWERPC_EXCP_FP_VXCVI:
                    info.si_code = TARGET_FPE_FLTSUB;
                    break;
                default:
                    EXCP_DUMP(env, "Unknown floating point exception (%02x)\n",
                              env->error_code);
                    break;
                }
                break;
            case POWERPC_EXCP_INVAL:
                info.si_signo = TARGET_SIGILL;
                info.si_errno = 0;
                switch (env->error_code & 0xF) {
                case POWERPC_EXCP_INVAL_INVAL:
                    info.si_code = TARGET_ILL_ILLOPC;
                    break;
                case POWERPC_EXCP_INVAL_LSWX:
                    info.si_code = TARGET_ILL_ILLOPN;
                    break;
                case POWERPC_EXCP_INVAL_SPR:
                    info.si_code = TARGET_ILL_PRVREG;
                    break;
                case POWERPC_EXCP_INVAL_FP:
                    info.si_code = TARGET_ILL_COPROC;
                    break;
                default:
                    EXCP_DUMP(env, "Unknown invalid operation (%02x)\n",
                              env->error_code & 0xF);
                    info.si_code = TARGET_ILL_ILLADR;
                    break;
                }
                break;
            case POWERPC_EXCP_PRIV:
                info.si_signo = TARGET_SIGILL;
                info.si_errno = 0;
                switch (env->error_code & 0xF) {
                case POWERPC_EXCP_PRIV_OPC:
                    info.si_code = TARGET_ILL_PRVOPC;
                    break;
                case POWERPC_EXCP_PRIV_REG:
                    info.si_code = TARGET_ILL_PRVREG;
                    break;
                default:
                    EXCP_DUMP(env, "Unknown privilege violation (%02x)\n",
                              env->error_code & 0xF);
                    info.si_code = TARGET_ILL_PRVOPC;
                    break;
                }
                break;
            case POWERPC_EXCP_TRAP:
                cpu_abort(cs, "Tried to call a TRAP\n");
                break;
            default:
                /* Should not happen ! */
                cpu_abort(cs, "Unknown program exception (%02x)\n",
                          env->error_code);
                break;
            }
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_FPU:      /* Floating-point unavailable exception  */
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_COPROC;
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_SYSCALL:  /* System call exception                 */
            cpu_abort(cs, "Syscall exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_APU:      /* Auxiliary processor unavailable       */
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_COPROC;
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_DECR:     /* Decrementer exception                 */
            cpu_abort(cs, "Decrementer interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_FIT:      /* Fixed-interval timer interrupt        */
            cpu_abort(cs, "Fix interval timer interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_WDT:      /* Watchdog timer interrupt              */
            cpu_abort(cs, "Watchdog timer interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_DTLB:     /* Data TLB error                        */
            cpu_abort(cs, "Data TLB exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_ITLB:     /* Instruction TLB error                 */
            cpu_abort(cs, "Instruction TLB exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_SPEU:     /* SPE/embedded floating-point unavail.  */
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_COPROC;
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_EFPDI:    /* Embedded floating-point data IRQ      */
            cpu_abort(cs, "Embedded floating-point data IRQ not handled\n");
            break;
        case POWERPC_EXCP_EFPRI:    /* Embedded floating-point round IRQ     */
            cpu_abort(cs, "Embedded floating-point round IRQ not handled\n");
            break;
        case POWERPC_EXCP_EPERFM:   /* Embedded performance monitor IRQ      */
            cpu_abort(cs, "Performance monitor exception not handled\n");
            break;
        case POWERPC_EXCP_DOORI:    /* Embedded doorbell interrupt           */
            cpu_abort(cs, "Doorbell interrupt while in user mode. "
                       "Aborting\n");
            break;
        case POWERPC_EXCP_DOORCI:   /* Embedded doorbell critical interrupt  */
            cpu_abort(cs, "Doorbell critical interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_RESET:    /* System reset exception                */
            cpu_abort(cs, "Reset interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_DSEG:     /* Data segment exception                */
            cpu_abort(cs, "Data segment exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_ISEG:     /* Instruction segment exception         */
            cpu_abort(cs, "Instruction segment exception "
                      "while in user mode. Aborting\n");
            break;
        /* PowerPC 64 with hypervisor mode support */
        case POWERPC_EXCP_HDECR:    /* Hypervisor decrementer exception      */
            cpu_abort(cs, "Hypervisor decrementer interrupt "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_TRACE:    /* Trace exception                       */
            /* Nothing to do:
             * we use this exception to emulate step-by-step execution mode.
             */
            break;
        /* PowerPC 64 with hypervisor mode support */
        case POWERPC_EXCP_HDSI:     /* Hypervisor data storage exception     */
            cpu_abort(cs, "Hypervisor data storage exception "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_HISI:     /* Hypervisor instruction storage excp   */
            cpu_abort(cs, "Hypervisor instruction storage exception "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_HDSEG:    /* Hypervisor data segment exception     */
            cpu_abort(cs, "Hypervisor data segment exception "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_HISEG:    /* Hypervisor instruction segment excp   */
            cpu_abort(cs, "Hypervisor instruction segment exception "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_VPU:      /* Vector unavailable exception          */
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_COPROC;
            info._sifields._sigfault._addr = env->nip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case POWERPC_EXCP_PIT:      /* Programmable interval timer IRQ       */
            cpu_abort(cs, "Programmable interval timer interrupt "
                      "while in user mode. Aborting\n");
            break;
        case POWERPC_EXCP_IO:       /* IO error exception                    */
            cpu_abort(cs, "IO error exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_RUNM:     /* Run mode exception                    */
            cpu_abort(cs, "Run mode exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_EMUL:     /* Emulation trap exception              */
            cpu_abort(cs, "Emulation trap exception not handled\n");
            break;
        case POWERPC_EXCP_IFTLB:    /* Instruction fetch TLB error           */
            cpu_abort(cs, "Instruction fetch TLB exception "
                      "while in user-mode. Aborting");
            break;
        case POWERPC_EXCP_DLTLB:    /* Data load TLB miss                    */
            cpu_abort(cs, "Data load TLB exception while in user-mode. "
                      "Aborting");
            break;
        case POWERPC_EXCP_DSTLB:    /* Data store TLB miss                   */
            cpu_abort(cs, "Data store TLB exception while in user-mode. "
                      "Aborting");
            break;
        case POWERPC_EXCP_FPA:      /* Floating-point assist exception       */
            cpu_abort(cs, "Floating-point assist exception not handled\n");
            break;
        case POWERPC_EXCP_IABR:     /* Instruction address breakpoint        */
            cpu_abort(cs, "Instruction address breakpoint exception "
                      "not handled\n");
            break;
        case POWERPC_EXCP_SMI:      /* System management interrupt           */
            cpu_abort(cs, "System management interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_THERM:    /* Thermal interrupt                     */
            cpu_abort(cs, "Thermal interrupt interrupt while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_PERFM:   /* Embedded performance monitor IRQ      */
            cpu_abort(cs, "Performance monitor exception not handled\n");
            break;
        case POWERPC_EXCP_VPUA:     /* Vector assist exception               */
            cpu_abort(cs, "Vector assist exception not handled\n");
            break;
        case POWERPC_EXCP_SOFTP:    /* Soft patch exception                  */
            cpu_abort(cs, "Soft patch exception not handled\n");
            break;
        case POWERPC_EXCP_MAINT:    /* Maintenance exception                 */
            cpu_abort(cs, "Maintenance exception while in user mode. "
                      "Aborting\n");
            break;
        case POWERPC_EXCP_STOP:     /* stop translation                      */
            /* We did invalidate the instruction cache. Go on */
            break;
        case POWERPC_EXCP_BRANCH:   /* branch instruction:                   */
            /* We just stopped because of a branch. Go on */
            break;
        case POWERPC_EXCP_SYSCALL_USER:
            /* system call in user-mode emulation */
            /* WARNING:
             * PPC ABI uses overflow flag in cr0 to signal an error
             * in syscalls.
             */
            env->crf[0] &= ~0x1;
            env->nip += 4;
            ret = do_syscall(env, env->gpr[0], env->gpr[3], env->gpr[4],
                             env->gpr[5], env->gpr[6], env->gpr[7],
                             env->gpr[8], 0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->nip -= 4;
                break;
            }
            if (ret == (target_ulong)(-TARGET_QEMU_ESIGRETURN)) {
                /* Returning from a successful sigreturn syscall.
                   Avoid corrupting register state.  */
                break;
            }
            if (ret > (target_ulong)(-515)) {
                env->crf[0] |= 0x1;
                ret = -ret;
            }
            env->gpr[3] = ret;
            break;
        case POWERPC_EXCP_STCX:
            if (do_store_exclusive(env)) {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->nip;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig) {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            cpu_abort(cs, "Unknown exception 0x%x. Aborting\n", trapnr);
            break;
        }
        process_pending_signals(env);
    }
}
#endif

#ifdef TARGET_MIPS

# ifdef TARGET_ABI_MIPSO32
#  define MIPS_SYS(name, args) args,
static const uint8_t mips_syscall_args[] = {
	MIPS_SYS(sys_syscall	, 8)	/* 4000 */
	MIPS_SYS(sys_exit	, 1)
	MIPS_SYS(sys_fork	, 0)
	MIPS_SYS(sys_read	, 3)
	MIPS_SYS(sys_write	, 3)
	MIPS_SYS(sys_open	, 3)	/* 4005 */
	MIPS_SYS(sys_close	, 1)
	MIPS_SYS(sys_waitpid	, 3)
	MIPS_SYS(sys_creat	, 2)
	MIPS_SYS(sys_link	, 2)
	MIPS_SYS(sys_unlink	, 1)	/* 4010 */
	MIPS_SYS(sys_execve	, 0)
	MIPS_SYS(sys_chdir	, 1)
	MIPS_SYS(sys_time	, 1)
	MIPS_SYS(sys_mknod	, 3)
	MIPS_SYS(sys_chmod	, 2)	/* 4015 */
	MIPS_SYS(sys_lchown	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_stat */
	MIPS_SYS(sys_lseek	, 3)
	MIPS_SYS(sys_getpid	, 0)	/* 4020 */
	MIPS_SYS(sys_mount	, 5)
	MIPS_SYS(sys_umount	, 1)
	MIPS_SYS(sys_setuid	, 1)
	MIPS_SYS(sys_getuid	, 0)
	MIPS_SYS(sys_stime	, 1)	/* 4025 */
	MIPS_SYS(sys_ptrace	, 4)
	MIPS_SYS(sys_alarm	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_fstat */
	MIPS_SYS(sys_pause	, 0)
	MIPS_SYS(sys_utime	, 2)	/* 4030 */
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_access	, 2)
	MIPS_SYS(sys_nice	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4035 */
	MIPS_SYS(sys_sync	, 0)
	MIPS_SYS(sys_kill	, 2)
	MIPS_SYS(sys_rename	, 2)
	MIPS_SYS(sys_mkdir	, 2)
	MIPS_SYS(sys_rmdir	, 1)	/* 4040 */
	MIPS_SYS(sys_dup		, 1)
	MIPS_SYS(sys_pipe	, 0)
	MIPS_SYS(sys_times	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_brk		, 1)	/* 4045 */
	MIPS_SYS(sys_setgid	, 1)
	MIPS_SYS(sys_getgid	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was signal(2) */
	MIPS_SYS(sys_geteuid	, 0)
	MIPS_SYS(sys_getegid	, 0)	/* 4050 */
	MIPS_SYS(sys_acct	, 0)
	MIPS_SYS(sys_umount2	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ioctl	, 3)
	MIPS_SYS(sys_fcntl	, 3)	/* 4055 */
	MIPS_SYS(sys_ni_syscall	, 2)
	MIPS_SYS(sys_setpgid	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_olduname	, 1)
	MIPS_SYS(sys_umask	, 1)	/* 4060 */
	MIPS_SYS(sys_chroot	, 1)
	MIPS_SYS(sys_ustat	, 2)
	MIPS_SYS(sys_dup2	, 2)
	MIPS_SYS(sys_getppid	, 0)
	MIPS_SYS(sys_getpgrp	, 0)	/* 4065 */
	MIPS_SYS(sys_setsid	, 0)
	MIPS_SYS(sys_sigaction	, 3)
	MIPS_SYS(sys_sgetmask	, 0)
	MIPS_SYS(sys_ssetmask	, 1)
	MIPS_SYS(sys_setreuid	, 2)	/* 4070 */
	MIPS_SYS(sys_setregid	, 2)
	MIPS_SYS(sys_sigsuspend	, 0)
	MIPS_SYS(sys_sigpending	, 1)
	MIPS_SYS(sys_sethostname	, 2)
	MIPS_SYS(sys_setrlimit	, 2)	/* 4075 */
	MIPS_SYS(sys_getrlimit	, 2)
	MIPS_SYS(sys_getrusage	, 2)
	MIPS_SYS(sys_gettimeofday, 2)
	MIPS_SYS(sys_settimeofday, 2)
	MIPS_SYS(sys_getgroups	, 2)	/* 4080 */
	MIPS_SYS(sys_setgroups	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)	/* old_select */
	MIPS_SYS(sys_symlink	, 2)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_lstat */
	MIPS_SYS(sys_readlink	, 3)	/* 4085 */
	MIPS_SYS(sys_uselib	, 1)
	MIPS_SYS(sys_swapon	, 2)
	MIPS_SYS(sys_reboot	, 3)
	MIPS_SYS(old_readdir	, 3)
	MIPS_SYS(old_mmap	, 6)	/* 4090 */
	MIPS_SYS(sys_munmap	, 2)
	MIPS_SYS(sys_truncate	, 2)
	MIPS_SYS(sys_ftruncate	, 2)
	MIPS_SYS(sys_fchmod	, 2)
	MIPS_SYS(sys_fchown	, 3)	/* 4095 */
	MIPS_SYS(sys_getpriority	, 2)
	MIPS_SYS(sys_setpriority	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_statfs	, 2)
	MIPS_SYS(sys_fstatfs	, 2)	/* 4100 */
	MIPS_SYS(sys_ni_syscall	, 0)	/* was ioperm(2) */
	MIPS_SYS(sys_socketcall	, 2)
	MIPS_SYS(sys_syslog	, 3)
	MIPS_SYS(sys_setitimer	, 3)
	MIPS_SYS(sys_getitimer	, 2)	/* 4105 */
	MIPS_SYS(sys_newstat	, 2)
	MIPS_SYS(sys_newlstat	, 2)
	MIPS_SYS(sys_newfstat	, 2)
	MIPS_SYS(sys_uname	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4110 was iopl(2) */
	MIPS_SYS(sys_vhangup	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_idle() */
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_vm86 */
	MIPS_SYS(sys_wait4	, 4)
	MIPS_SYS(sys_swapoff	, 1)	/* 4115 */
	MIPS_SYS(sys_sysinfo	, 1)
	MIPS_SYS(sys_ipc		, 6)
	MIPS_SYS(sys_fsync	, 1)
	MIPS_SYS(sys_sigreturn	, 0)
	MIPS_SYS(sys_clone	, 6)	/* 4120 */
	MIPS_SYS(sys_setdomainname, 2)
	MIPS_SYS(sys_newuname	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_modify_ldt */
	MIPS_SYS(sys_adjtimex	, 1)
	MIPS_SYS(sys_mprotect	, 3)	/* 4125 */
	MIPS_SYS(sys_sigprocmask	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was create_module */
	MIPS_SYS(sys_init_module	, 5)
	MIPS_SYS(sys_delete_module, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4130	was get_kernel_syms */
	MIPS_SYS(sys_quotactl	, 0)
	MIPS_SYS(sys_getpgid	, 1)
	MIPS_SYS(sys_fchdir	, 1)
	MIPS_SYS(sys_bdflush	, 2)
	MIPS_SYS(sys_sysfs	, 3)	/* 4135 */
	MIPS_SYS(sys_personality	, 1)
	MIPS_SYS(sys_ni_syscall	, 0)	/* for afs_syscall */
	MIPS_SYS(sys_setfsuid	, 1)
	MIPS_SYS(sys_setfsgid	, 1)
	MIPS_SYS(sys_llseek	, 5)	/* 4140 */
	MIPS_SYS(sys_getdents	, 3)
	MIPS_SYS(sys_select	, 5)
	MIPS_SYS(sys_flock	, 2)
	MIPS_SYS(sys_msync	, 3)
	MIPS_SYS(sys_readv	, 3)	/* 4145 */
	MIPS_SYS(sys_writev	, 3)
	MIPS_SYS(sys_cacheflush	, 3)
	MIPS_SYS(sys_cachectl	, 3)
	MIPS_SYS(sys_sysmips	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4150 */
	MIPS_SYS(sys_getsid	, 1)
	MIPS_SYS(sys_fdatasync	, 0)
	MIPS_SYS(sys_sysctl	, 1)
	MIPS_SYS(sys_mlock	, 2)
	MIPS_SYS(sys_munlock	, 2)	/* 4155 */
	MIPS_SYS(sys_mlockall	, 1)
	MIPS_SYS(sys_munlockall	, 0)
	MIPS_SYS(sys_sched_setparam, 2)
	MIPS_SYS(sys_sched_getparam, 2)
	MIPS_SYS(sys_sched_setscheduler, 3)	/* 4160 */
	MIPS_SYS(sys_sched_getscheduler, 1)
	MIPS_SYS(sys_sched_yield	, 0)
	MIPS_SYS(sys_sched_get_priority_max, 1)
	MIPS_SYS(sys_sched_get_priority_min, 1)
	MIPS_SYS(sys_sched_rr_get_interval, 2)	/* 4165 */
	MIPS_SYS(sys_nanosleep,	2)
	MIPS_SYS(sys_mremap	, 5)
	MIPS_SYS(sys_accept	, 3)
	MIPS_SYS(sys_bind	, 3)
	MIPS_SYS(sys_connect	, 3)	/* 4170 */
	MIPS_SYS(sys_getpeername	, 3)
	MIPS_SYS(sys_getsockname	, 3)
	MIPS_SYS(sys_getsockopt	, 5)
	MIPS_SYS(sys_listen	, 2)
	MIPS_SYS(sys_recv	, 4)	/* 4175 */
	MIPS_SYS(sys_recvfrom	, 6)
	MIPS_SYS(sys_recvmsg	, 3)
	MIPS_SYS(sys_send	, 4)
	MIPS_SYS(sys_sendmsg	, 3)
	MIPS_SYS(sys_sendto	, 6)	/* 4180 */
	MIPS_SYS(sys_setsockopt	, 5)
	MIPS_SYS(sys_shutdown	, 2)
	MIPS_SYS(sys_socket	, 3)
	MIPS_SYS(sys_socketpair	, 4)
	MIPS_SYS(sys_setresuid	, 3)	/* 4185 */
	MIPS_SYS(sys_getresuid	, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* was sys_query_module */
	MIPS_SYS(sys_poll	, 3)
	MIPS_SYS(sys_nfsservctl	, 3)
	MIPS_SYS(sys_setresgid	, 3)	/* 4190 */
	MIPS_SYS(sys_getresgid	, 3)
	MIPS_SYS(sys_prctl	, 5)
	MIPS_SYS(sys_rt_sigreturn, 0)
	MIPS_SYS(sys_rt_sigaction, 4)
	MIPS_SYS(sys_rt_sigprocmask, 4)	/* 4195 */
	MIPS_SYS(sys_rt_sigpending, 2)
	MIPS_SYS(sys_rt_sigtimedwait, 4)
	MIPS_SYS(sys_rt_sigqueueinfo, 3)
	MIPS_SYS(sys_rt_sigsuspend, 0)
	MIPS_SYS(sys_pread64	, 6)	/* 4200 */
	MIPS_SYS(sys_pwrite64	, 6)
	MIPS_SYS(sys_chown	, 3)
	MIPS_SYS(sys_getcwd	, 2)
	MIPS_SYS(sys_capget	, 2)
	MIPS_SYS(sys_capset	, 2)	/* 4205 */
	MIPS_SYS(sys_sigaltstack	, 2)
	MIPS_SYS(sys_sendfile	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_mmap2	, 6)	/* 4210 */
	MIPS_SYS(sys_truncate64	, 4)
	MIPS_SYS(sys_ftruncate64	, 4)
	MIPS_SYS(sys_stat64	, 2)
	MIPS_SYS(sys_lstat64	, 2)
	MIPS_SYS(sys_fstat64	, 2)	/* 4215 */
	MIPS_SYS(sys_pivot_root	, 2)
	MIPS_SYS(sys_mincore	, 3)
	MIPS_SYS(sys_madvise	, 3)
	MIPS_SYS(sys_getdents64	, 3)
	MIPS_SYS(sys_fcntl64	, 3)	/* 4220 */
	MIPS_SYS(sys_ni_syscall	, 0)
	MIPS_SYS(sys_gettid	, 0)
	MIPS_SYS(sys_readahead	, 5)
	MIPS_SYS(sys_setxattr	, 5)
	MIPS_SYS(sys_lsetxattr	, 5)	/* 4225 */
	MIPS_SYS(sys_fsetxattr	, 5)
	MIPS_SYS(sys_getxattr	, 4)
	MIPS_SYS(sys_lgetxattr	, 4)
	MIPS_SYS(sys_fgetxattr	, 4)
	MIPS_SYS(sys_listxattr	, 3)	/* 4230 */
	MIPS_SYS(sys_llistxattr	, 3)
	MIPS_SYS(sys_flistxattr	, 3)
	MIPS_SYS(sys_removexattr	, 2)
	MIPS_SYS(sys_lremovexattr, 2)
	MIPS_SYS(sys_fremovexattr, 2)	/* 4235 */
	MIPS_SYS(sys_tkill	, 2)
	MIPS_SYS(sys_sendfile64	, 5)
	MIPS_SYS(sys_futex	, 6)
	MIPS_SYS(sys_sched_setaffinity, 3)
	MIPS_SYS(sys_sched_getaffinity, 3)	/* 4240 */
	MIPS_SYS(sys_io_setup	, 2)
	MIPS_SYS(sys_io_destroy	, 1)
	MIPS_SYS(sys_io_getevents, 5)
	MIPS_SYS(sys_io_submit	, 3)
	MIPS_SYS(sys_io_cancel	, 3)	/* 4245 */
	MIPS_SYS(sys_exit_group	, 1)
	MIPS_SYS(sys_lookup_dcookie, 3)
	MIPS_SYS(sys_epoll_create, 1)
	MIPS_SYS(sys_epoll_ctl	, 4)
	MIPS_SYS(sys_epoll_wait	, 3)	/* 4250 */
	MIPS_SYS(sys_remap_file_pages, 5)
	MIPS_SYS(sys_set_tid_address, 1)
	MIPS_SYS(sys_restart_syscall, 0)
	MIPS_SYS(sys_fadvise64_64, 7)
	MIPS_SYS(sys_statfs64	, 3)	/* 4255 */
	MIPS_SYS(sys_fstatfs64	, 2)
	MIPS_SYS(sys_timer_create, 3)
	MIPS_SYS(sys_timer_settime, 4)
	MIPS_SYS(sys_timer_gettime, 2)
	MIPS_SYS(sys_timer_getoverrun, 1)	/* 4260 */
	MIPS_SYS(sys_timer_delete, 1)
	MIPS_SYS(sys_clock_settime, 2)
	MIPS_SYS(sys_clock_gettime, 2)
	MIPS_SYS(sys_clock_getres, 2)
	MIPS_SYS(sys_clock_nanosleep, 4)	/* 4265 */
	MIPS_SYS(sys_tgkill	, 3)
	MIPS_SYS(sys_utimes	, 2)
	MIPS_SYS(sys_mbind	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_get_mempolicy */
	MIPS_SYS(sys_ni_syscall	, 0)	/* 4270 sys_set_mempolicy */
	MIPS_SYS(sys_mq_open	, 4)
	MIPS_SYS(sys_mq_unlink	, 1)
	MIPS_SYS(sys_mq_timedsend, 5)
	MIPS_SYS(sys_mq_timedreceive, 5)
	MIPS_SYS(sys_mq_notify	, 2)	/* 4275 */
	MIPS_SYS(sys_mq_getsetattr, 3)
	MIPS_SYS(sys_ni_syscall	, 0)	/* sys_vserver */
	MIPS_SYS(sys_waitid	, 4)
	MIPS_SYS(sys_ni_syscall	, 0)	/* available, was setaltroot */
	MIPS_SYS(sys_add_key	, 5)
	MIPS_SYS(sys_request_key, 4)
	MIPS_SYS(sys_keyctl	, 5)
	MIPS_SYS(sys_set_thread_area, 1)
	MIPS_SYS(sys_inotify_init, 0)
	MIPS_SYS(sys_inotify_add_watch, 3) /* 4285 */
	MIPS_SYS(sys_inotify_rm_watch, 2)
	MIPS_SYS(sys_migrate_pages, 4)
	MIPS_SYS(sys_openat, 4)
	MIPS_SYS(sys_mkdirat, 3)
	MIPS_SYS(sys_mknodat, 4)	/* 4290 */
	MIPS_SYS(sys_fchownat, 5)
	MIPS_SYS(sys_futimesat, 3)
	MIPS_SYS(sys_fstatat64, 4)
	MIPS_SYS(sys_unlinkat, 3)
	MIPS_SYS(sys_renameat, 4)	/* 4295 */
	MIPS_SYS(sys_linkat, 5)
	MIPS_SYS(sys_symlinkat, 3)
	MIPS_SYS(sys_readlinkat, 4)
	MIPS_SYS(sys_fchmodat, 3)
	MIPS_SYS(sys_faccessat, 3)	/* 4300 */
	MIPS_SYS(sys_pselect6, 6)
	MIPS_SYS(sys_ppoll, 5)
	MIPS_SYS(sys_unshare, 1)
	MIPS_SYS(sys_splice, 6)
	MIPS_SYS(sys_sync_file_range, 7) /* 4305 */
	MIPS_SYS(sys_tee, 4)
	MIPS_SYS(sys_vmsplice, 4)
	MIPS_SYS(sys_move_pages, 6)
	MIPS_SYS(sys_set_robust_list, 2)
	MIPS_SYS(sys_get_robust_list, 3) /* 4310 */
	MIPS_SYS(sys_kexec_load, 4)
	MIPS_SYS(sys_getcpu, 3)
	MIPS_SYS(sys_epoll_pwait, 6)
	MIPS_SYS(sys_ioprio_set, 3)
	MIPS_SYS(sys_ioprio_get, 2)
        MIPS_SYS(sys_utimensat, 4)
        MIPS_SYS(sys_signalfd, 3)
        MIPS_SYS(sys_ni_syscall, 0)     /* was timerfd */
        MIPS_SYS(sys_eventfd, 1)
        MIPS_SYS(sys_fallocate, 6)      /* 4320 */
        MIPS_SYS(sys_timerfd_create, 2)
        MIPS_SYS(sys_timerfd_gettime, 2)
        MIPS_SYS(sys_timerfd_settime, 4)
        MIPS_SYS(sys_signalfd4, 4)
        MIPS_SYS(sys_eventfd2, 2)       /* 4325 */
        MIPS_SYS(sys_epoll_create1, 1)
        MIPS_SYS(sys_dup3, 3)
        MIPS_SYS(sys_pipe2, 2)
        MIPS_SYS(sys_inotify_init1, 1)
        MIPS_SYS(sys_preadv, 5)         /* 4330 */
        MIPS_SYS(sys_pwritev, 5)
        MIPS_SYS(sys_rt_tgsigqueueinfo, 4)
        MIPS_SYS(sys_perf_event_open, 5)
        MIPS_SYS(sys_accept4, 4)
        MIPS_SYS(sys_recvmmsg, 5)       /* 4335 */
        MIPS_SYS(sys_fanotify_init, 2)
        MIPS_SYS(sys_fanotify_mark, 6)
        MIPS_SYS(sys_prlimit64, 4)
        MIPS_SYS(sys_name_to_handle_at, 5)
        MIPS_SYS(sys_open_by_handle_at, 3) /* 4340 */
        MIPS_SYS(sys_clock_adjtime, 2)
        MIPS_SYS(sys_syncfs, 1)
        MIPS_SYS(sys_sendmmsg, 4)
        MIPS_SYS(sys_setns, 2)
        MIPS_SYS(sys_process_vm_readv, 6) /* 345 */
        MIPS_SYS(sys_process_vm_writev, 6)
        MIPS_SYS(sys_kcmp, 5)
        MIPS_SYS(sys_finit_module, 3)
        MIPS_SYS(sys_sched_setattr, 2)
        MIPS_SYS(sys_sched_getattr, 3)  /* 350 */
        MIPS_SYS(sys_renameat2, 5)
        MIPS_SYS(sys_seccomp, 3)
        MIPS_SYS(sys_getrandom, 3)
        MIPS_SYS(sys_memfd_create, 2)
        MIPS_SYS(sys_bpf, 3)            /* 355 */
        MIPS_SYS(sys_execveat, 5)
        MIPS_SYS(sys_userfaultfd, 1)
        MIPS_SYS(sys_membarrier, 2)
        MIPS_SYS(sys_mlock2, 3)
        MIPS_SYS(sys_copy_file_range, 6) /* 360 */
        MIPS_SYS(sys_preadv2, 6)
        MIPS_SYS(sys_pwritev2, 6)
};
#  undef MIPS_SYS
# endif /* O32 */

static int do_store_exclusive(CPUMIPSState *env)
{
    target_ulong addr;
    target_ulong page_addr;
    target_ulong val;
    int flags;
    int segv = 0;
    int reg;
    int d;

    addr = env->lladdr;
    //page_addr = addr & TARGET_PAGE_MASK; //zyw
    page_addr = addr;
    start_exclusive();
    mmap_lock();
    flags = page_get_flags(page_addr);
    if ((flags & PAGE_READ) == 0) {
        segv = 1;
    } else {
        reg = env->llreg & 0x1f;
        d = (env->llreg & 0x20) != 0;
        if (d) {
            segv = get_user_s64(val, addr);
        } else {
            segv = get_user_s32(val, addr);
        }
        if (!segv) {
#ifdef MEM_MAPPING
            handle_store(env, env->active_tc.PC, page_addr);
            //printf("handle store finish:%x\n", addr);
#endif
            if (val != env->llval) {
                env->active_tc.gpr[reg] = 0;
            } else {
                if (d) {
                    segv = put_user_u64(env->llnewval, addr);
                } else {
                    segv = put_user_u32(env->llnewval, addr);
                    //printf("put addr:%x,segv:%d\n", addr, segv);
                }
                if (!segv) {
                    env->active_tc.gpr[reg] = 1;
                }
            }
        }
    }
    env->lladdr = -1;
    if (!segv) {
        env->active_tc.PC += 4;
    }
    mmap_unlock();
    end_exclusive();
    return segv;
}

/* Break codes */
enum {
    BRK_OVERFLOW = 6,
    BRK_DIVZERO = 7
};

static int do_break(CPUMIPSState *env, target_siginfo_t *info,
                    unsigned int code)
{
    int ret = -1;

    switch (code) {
    case BRK_OVERFLOW:
    case BRK_DIVZERO:
        info->si_signo = TARGET_SIGFPE;
        info->si_errno = 0;
        info->si_code = (code == BRK_OVERFLOW) ? FPE_INTOVF : FPE_INTDIV;
        queue_signal(env, info->si_signo, QEMU_SI_FAULT, &*info);
        ret = 0;
        break;
    default:
        info->si_signo = TARGET_SIGTRAP;
        info->si_errno = 0;
        queue_signal(env, info->si_signo, QEMU_SI_FAULT, &*info);
        ret = 0;
        break;
    }

    return ret;
}




void cpu_loop(CPUMIPSState *env)
{
    CPUState *cs = CPU(mips_env_get_cpu(env));
    target_siginfo_t info;
    int trapnr;
    abi_long ret;
# ifdef TARGET_ABI_MIPSO32
    unsigned int syscall_num;
# endif

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case EXCP_SYSCALL:
            env->active_tc.PC += 4;
# ifdef TARGET_ABI_MIPSO32
            syscall_num = env->active_tc.gpr[2] - 4000;
            printf("syscall num:%d\n", syscall_num);
            exit_func(syscall_num, program_id);//zyw

            if (syscall_num >= sizeof(mips_syscall_args)) {
                ret = -TARGET_ENOSYS;
            } else {
                int nb_args;
                abi_ulong sp_reg;
                abi_ulong arg5 = 0, arg6 = 0, arg7 = 0, arg8 = 0;

                nb_args = mips_syscall_args[syscall_num];
                sp_reg = env->active_tc.gpr[29];
                switch (nb_args) {
                /* these arguments are taken from the stack */
                case 8:
                    if ((ret = get_user_ual(arg8, sp_reg + 28)) != 0) {
                        goto done_syscall;
                    }
                case 7:
                    if ((ret = get_user_ual(arg7, sp_reg + 24)) != 0) {
                        goto done_syscall;
                    }
                case 6:
                    if ((ret = get_user_ual(arg6, sp_reg + 20)) != 0) {
                        goto done_syscall;
                    }
                case 5:
                    if ((ret = get_user_ual(arg5, sp_reg + 16)) != 0) {
                        goto done_syscall;
                    }
                default:
                    break;
                }

#ifdef MEM_MAPPING   
                int file_opti = 0;        
                int local_or_not = determine_local_or_not(syscall_num, program_id, env, &file_opti);

            
                /*
                else if(syscall_num == 178)
                {
                    ret = 100;
                }
                */
                //else if(local_or_not)
                //if(syscall_num != 45) //busybox
                //if(syscall_num == 5 || syscall_num == 106 || (file_fd!=-1 &&env->active_tc.gpr[4]==file_fd)) //busybox
                //if(syscall_num == 4 || syscall_num == 175 || syscall_num == 182 || syscall_num == 6) //httpd
                //if(syscall_num == 5 || syscall_num == 106 || (file_fd!=-1 &&env->active_tc.gpr[4]==file_fd) || env->active_tc.gpr[4] == 2) //lighttpd
                //if((syscall_num == 5)||(file_fd!=-1 &&env->active_tc.gpr[4]==file_fd) || env->active_tc.gpr[4] == 2) //jhttpd
                //if(syscall_num == 5 || syscall_num == 142 ||(file_fd!=-1 &&env->active_tc.gpr[4]==file_fd) || env->active_tc.gpr[4] == 2) //dropbear /dev/random 4142 user mode
                //if(syscall_num == 5 || syscall_num == 183 ||(file_fd!=-1 &&env->active_tc.gpr[4]==file_fd) || (sock_fd!=-1 &&env->active_tc.gpr[4]==sock_fd) ||env->active_tc.gpr[4] == 2) //dnsmasq
                //if(syscall_num == 184) //httpd
                //else if(syscall_num != 45) //cgibin
                //if(syscall_num == 146 || syscall_num == 20) //sample
                //if(syscall_num == 166) //network.cgi, tew httpd;
                //else if(0)
// do syscall
                user_syscall_flag = 1;
                int network_handle = 0;

#ifdef FEED_INPUT
                ret = feed_input(syscall_num, env, &network_handle);
#endif

#ifdef LMBENCH //lmbench use fork system call for lat_pipe
                if(local_or_not)
#else 
                if(network_handle == 1)//network operation already handle
                {

                }                  
                else if(syscall_num == 2 || syscall_num == 114)
                {
                    ret = 100;
                }
                else if(syscall_num == 166 || syscall_num == 117)
                {
                    ret = 0;
                }
                else if(syscall_num == 194 && program_id != 90501)
                {
                    ret = 0;
                }
                else if(local_or_not == 2) 
                {
                    ret = env->active_tc.gpr[6]; 
                }
                else if(local_or_not)
#endif//lmbench 
                {
                    //gettimeofday(&handle_syscall_start, NULL);

                    user_syscall_count++;
                    if(print_debug)
                    {
                        printf("time:%f, local sys num:%d, pc:%x, arg:%x,%x,%x\n",handle_syscall_start.tv_sec + handle_syscall_start.tv_usec/1000000.0, 
                            syscall_num, env->active_tc.PC, env->active_tc.gpr[4],env->active_tc.gpr[5],env->active_tc.gpr[6]);
                    }


                    if((program_id == 129780 || program_id == 129781) && syscall_num == 5)
                    {
                        //printf("current working directory: %s\n", getcwd(NULL, NULL));
                        chdir("/server/cgi-bin/"); 
                    }
                    else if(syscall_num == 3 || syscall_num == 4)
                    {
                        //very important for 129781
                        syscall_addr_check(env->active_tc.gpr[5], env->active_tc.gpr[6], syscall_num);
                    }
                    /*
                    else if(syscall_num == 170)
                    {
                        syscall_addr_check(env->active_tc.gpr[5], env->active_tc.gpr[6], syscall_num);
                        printf("connect %s\n", g2h(env->active_tc.gpr[5]));
                    }
                    */

#endif
                    user_syscall_flag = 1;
                    ret = do_syscall(env, env->active_tc.gpr[2],
                                     env->active_tc.gpr[4],
                                     env->active_tc.gpr[5],
                                     env->active_tc.gpr[6],
                                     env->active_tc.gpr[7],
                                     arg5, arg6, arg7, arg8);
                    //printf("do syscall end %d, args: %x,%x,%x,%x ret:%d\n",env->active_tc.gpr[2], env->active_tc.gpr[4], env->active_tc.gpr[5], env->active_tc.gpr[6], env->active_tc.gpr[7], ret);
                    
                    

#ifdef MEM_MAPPING    
   
                    if((program_id == 129780 || program_id == 129781) && syscall_num == 5)
                    {
                        chdir("/");
                    }
                    //optimization
                    if(file_opti == 1)
                    {
                        add_local_fd(ret);
                    }
                    //gettimeofday(&handle_syscall_end, NULL);
                    if(print_debug)
                    {
                        printf("time:%f, sys num ret:%x\n",handle_syscall_end.tv_sec + handle_syscall_end.tv_usec/1000000.0, ret);
                    }
                    handle_syscall_total += (double)handle_syscall_end.tv_sec - handle_syscall_start.tv_sec + (handle_syscall_end.tv_usec - handle_syscall_start.tv_usec)/1000000.0;
                    
                }

                else{
                    printf("remote sys num:%d, pc:%x, arg:%x,%x,%x\n", syscall_num, env->active_tc.PC, env->active_tc.gpr[4],env->active_tc.gpr[5],env->active_tc.gpr[6]);
                    user_syscall_flag = 0;
                    env->active_tc.PC -= 4; //very important
                    gettimeofday(&handle_state_start, NULL);
                    //printf("time:%f, remote syscall:%d, arg:%x,%x,%x,%x\n",handle_state_start.tv_sec + handle_state_start.tv_usec/1000000.0, 
                        //syscall_num, env->active_tc.gpr[4],env->active_tc.gpr[5],env->active_tc.gpr[6]);
                    //printf("syscall:%d\n", syscall_num);
                    write_state(cs->env_ptr, 0, 0);
                    read_state(env->active_tc.PC, cs->env_ptr);
                    if(env->active_tc.PC == 0)
                    {
                        printf("meet singal 4194\n");
                        normal_exit(0);
                    }
                      
                    ret = env->active_tc.gpr[2];
                    if(syscall_num == 45)
                    {
                        //sprintf("brk new memory:%x\n", env->active_tc.gpr[2]);
                        target_ulong tmp_page;
                        if((env->active_tc.gpr[2] & 0xfff) != 0)
                        {
                            tmp_page= (env->active_tc.gpr[2] & 0xfffff000);
                        }
                        else
                        {
                            tmp_page = (env->active_tc.gpr[2] & 0xfffff000) -0x1000;
                        }
                        while(1)
                        {
                            if(if_memory_rw(tmp_page, 1))
                            {
                                break;
                            }
                            //printf("add mem:%x\n", tmp_page);
                            add_memory_rw(tmp_page,1);
                            add_memory_rw(tmp_page,0);
                            tmp_page = tmp_page - 0x1000;
                        }
                    }
                    if(syscall_num == 90)
                    {
                        printf("**********need to handle mmap");
                        sleep(1000);
                        
                    }
                    if(syscall_num == 175)
                    {
                        printf("recv is:%s\n", g2h(env->active_tc.gpr[5]));
                    }
//zywconfig jjhttpd
                    /*
                    if(env->active_tc.gpr[7]!=0)
                    {
                        ret = 0xffffffff;
                    }
                    */
                    gettimeofday(&handle_state_end, NULL);
                    //printf("time: %f, ret value:%x\n", handle_state_end.tv_sec + handle_state_end.tv_usec/1000000.0, ret);
                    handle_state_total += (double)handle_state_end.tv_sec - handle_state_start.tv_sec + (handle_state_end.tv_usec - handle_state_start.tv_usec)/1000000.0;
                }
#endif
            }
            last_syscall = syscall_num;
done_syscall:
# else
            ret = do_syscall(env, env->active_tc.gpr[2],
                             env->active_tc.gpr[4], env->active_tc.gpr[5],
                             env->active_tc.gpr[6], env->active_tc.gpr[7],
                             env->active_tc.gpr[8], env->active_tc.gpr[9],
                             env->active_tc.gpr[10], env->active_tc.gpr[11]);
# endif /* O32 */
            if (ret == -TARGET_ERESTARTSYS) {
                env->active_tc.PC -= 4;
                break;
            }
            if (ret == -TARGET_QEMU_ESIGRETURN) {
                /* Returning from a successful sigreturn syscall.
                   Avoid clobbering register state.  */
                break;
            }
            //zyw 
            if(user_syscall_flag)
            {
                if ((abi_ulong)ret >= (abi_ulong)-1133) {
                env->active_tc.gpr[7] = 1; /* error flag */
                ret = -ret;
                } else {
                    env->active_tc.gpr[7] = 0; /* error flag */
                }
            }
            env->active_tc.gpr[2] = ret;
            break;
        case EXCP_TLBL:
        case EXCP_TLBS:
        case EXCP_AdEL:
        case EXCP_AdES:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            /* XXX: check env->error_code */
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->CP0_BadVAddr;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_CpU:
        case EXCP_RI:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = 0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_SC:
            if (do_store_exclusive(env)) {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->active_tc.PC;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DSPDIS:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPC;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        /* The code below was inspired by the MIPS Linux kernel trap
         * handling code in arch/mips/kernel/traps.c.
         */
        case EXCP_BREAK:
            {
                abi_ulong trap_instr;
                unsigned int code;

                if (env->hflags & MIPS_HFLAG_M16) {
                    if (env->insn_flags & ASE_MICROMIPS) {
                        /* microMIPS mode */
                        ret = get_user_u16(trap_instr, env->active_tc.PC);
                        if (ret != 0) {
                            goto error;
                        }

                        if ((trap_instr >> 10) == 0x11) {
                            /* 16-bit instruction */
                            code = trap_instr & 0xf;
                        } else {
                            /* 32-bit instruction */
                            abi_ulong instr_lo;

                            ret = get_user_u16(instr_lo,
                                               env->active_tc.PC + 2);
                            if (ret != 0) {
                                goto error;
                            }
                            trap_instr = (trap_instr << 16) | instr_lo;
                            code = ((trap_instr >> 6) & ((1 << 20) - 1));
                            /* Unfortunately, microMIPS also suffers from
                               the old assembler bug...  */
                            if (code >= (1 << 10)) {
                                code >>= 10;
                            }
                        }
                    } else {
                        /* MIPS16e mode */
                        ret = get_user_u16(trap_instr, env->active_tc.PC);
                        if (ret != 0) {
                            goto error;
                        }
                        code = (trap_instr >> 6) & 0x3f;
                    }
                } else {
                    ret = get_user_u32(trap_instr, env->active_tc.PC);
                    if (ret != 0) {
                        goto error;
                    }

                    /* As described in the original Linux kernel code, the
                     * below checks on 'code' are to work around an old
                     * assembly bug.
                     */
                    code = ((trap_instr >> 6) & ((1 << 20) - 1));
                    if (code >= (1 << 10)) {
                        code >>= 10;
                    }
                }

                if (do_break(env, &info, code) != 0) {
                    goto error;
                }
            }
            break;
        case EXCP_TRAP:
            {
                abi_ulong trap_instr;
                unsigned int code = 0;

                if (env->hflags & MIPS_HFLAG_M16) {
                    /* microMIPS mode */
                    abi_ulong instr[2];

                    ret = get_user_u16(instr[0], env->active_tc.PC) ||
                          get_user_u16(instr[1], env->active_tc.PC + 2);

                    trap_instr = (instr[0] << 16) | instr[1];
                } else {
                    ret = get_user_u32(trap_instr, env->active_tc.PC);
                }

                if (ret != 0) {
                    goto error;
                }

                /* The immediate versions don't provide a code.  */
                if (!(trap_instr & 0xFC000000)) {
                    if (env->hflags & MIPS_HFLAG_M16) {
                        /* microMIPS mode */
                        code = ((trap_instr >> 12) & ((1 << 4) - 1));
                    } else {
                        code = ((trap_instr >> 6) & ((1 << 10) - 1));
                    }
                }

                if (do_break(env, &info, code) != 0) {
                    goto error;
                }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
error:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif

#ifdef TARGET_NIOS2

void cpu_loop(CPUNios2State *env)
{
    CPUState *cs = ENV_GET_CPU(env);
    Nios2CPU *cpu = NIOS2_CPU(cs);
    target_siginfo_t info;
    int trapnr, gdbsig, ret;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        gdbsig = 0;

        switch (trapnr) {
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_TRAP:
            if (env->regs[R_AT] == 0) {
                abi_long ret;
                qemu_log_mask(CPU_LOG_INT, "\nSyscall\n");

                ret = do_syscall(env, env->regs[2],
                                 env->regs[4], env->regs[5], env->regs[6],
                                 env->regs[7], env->regs[8], env->regs[9],
                                 0, 0);

                if (env->regs[2] == 0) {    /* FIXME: syscall 0 workaround */
                    ret = 0;
                }

                env->regs[2] = abs(ret);
                /* Return value is 0..4096 */
                env->regs[7] = (ret > 0xfffffffffffff000ULL);
                env->regs[CR_ESTATUS] = env->regs[CR_STATUS];
                env->regs[CR_STATUS] &= ~0x3;
                env->regs[R_EA] = env->regs[R_PC] + 4;
                env->regs[R_PC] += 4;
                break;
            } else {
                qemu_log_mask(CPU_LOG_INT, "\nTrap\n");

                env->regs[CR_ESTATUS] = env->regs[CR_STATUS];
                env->regs[CR_STATUS] &= ~0x3;
                env->regs[R_EA] = env->regs[R_PC] + 4;
                env->regs[R_PC] = cpu->exception_addr;

                gdbsig = TARGET_SIGTRAP;
                break;
            }
        case 0xaa:
            switch (env->regs[R_PC]) {
            /*case 0x1000:*/  /* TODO:__kuser_helper_version */
            case 0x1004:      /* __kuser_cmpxchg */
                start_exclusive();
                if (env->regs[4] & 0x3) {
                    goto kuser_fail;
                }
                ret = get_user_u32(env->regs[2], env->regs[4]);
                if (ret) {
                    end_exclusive();
                    goto kuser_fail;
                }
                env->regs[2] -= env->regs[5];
                if (env->regs[2] == 0) {
                    put_user_u32(env->regs[6], env->regs[4]);
                }
                end_exclusive();
                env->regs[R_PC] = env->regs[R_RA];
                break;
            /*case 0x1040:*/  /* TODO:__kuser_sigtramp */
            default:
                ;
kuser_fail:
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* TODO: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->regs[R_PC];
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        default:
            EXCP_DUMP(env, "\nqemu: unhandled CPU exception %#x - aborting\n",
                     trapnr);
            gdbsig = TARGET_SIGILL;
            break;
        }
        if (gdbsig) {
            gdb_handlesig(cs, gdbsig);
            if (gdbsig != TARGET_SIGTRAP) {
                exit(EXIT_FAILURE);
            }
        }

        process_pending_signals(env);
    }
}

#endif /* TARGET_NIOS2 */

#ifdef TARGET_OPENRISC

void cpu_loop(CPUOpenRISCState *env)
{
    CPUState *cs = CPU(openrisc_env_get_cpu(env));
    int trapnr;
    abi_long ret;
    target_siginfo_t info;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_SYSCALL:
            env->pc += 4;   /* 0xc00; */
            ret = do_syscall(env,
                             cpu_get_gpr(env, 11), /* return value       */
                             cpu_get_gpr(env, 3),  /* r3 - r7 are params */
                             cpu_get_gpr(env, 4),
                             cpu_get_gpr(env, 5),
                             cpu_get_gpr(env, 6),
                             cpu_get_gpr(env, 7),
                             cpu_get_gpr(env, 8), 0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                cpu_set_gpr(env, 11, ret);
            }
            break;
        case EXCP_DPF:
        case EXCP_IPF:
        case EXCP_RANGE:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_ALIGN:
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_BUS_ADRALN;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_ILLEGAL:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPC;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_FPE:
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = 0;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_INTERRUPT:
            /* We processed the pending cpu work above.  */
            break;
        case EXCP_DEBUG:
            trapnr = gdb_handlesig(cs, TARGET_SIGTRAP);
            if (trapnr) {
                info.si_signo = trapnr;
                info.si_errno = 0;
                info.si_code = TARGET_TRAP_BRKPT;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            g_assert_not_reached();
        }
        process_pending_signals(env);
    }
}

#endif /* TARGET_OPENRISC */

#ifdef TARGET_SH4
void cpu_loop(CPUSH4State *env)
{
    CPUState *cs = CPU(sh_env_get_cpu(env));
    int trapnr, ret;
    target_siginfo_t info;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case 0x160:
            env->pc += 2;
            ret = do_syscall(env,
                             env->gregs[3],
                             env->gregs[4],
                             env->gregs[5],
                             env->gregs[6],
                             env->gregs[7],
                             env->gregs[0],
                             env->gregs[1],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->gregs[0] = ret;
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
	case 0xa0:
	case 0xc0:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->tea;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
	    break;

        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);
    }
}
#endif

#ifdef TARGET_CRIS
void cpu_loop(CPUCRISState *env)
{
    CPUState *cs = CPU(cris_env_get_cpu(env));
    int trapnr, ret;
    target_siginfo_t info;
    
    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case 0xaa:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->pregs[PR_EDA];
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
	case EXCP_INTERRUPT:
	  /* just indicate that signals should be handled asap */
	  break;
        case EXCP_BREAK:
            ret = do_syscall(env, 
                             env->regs[9], 
                             env->regs[10], 
                             env->regs[11], 
                             env->regs[12], 
                             env->regs[13], 
                             env->pregs[7], 
                             env->pregs[11],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[10] = ret;
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);
    }
}
#endif

#ifdef TARGET_MICROBLAZE
void cpu_loop(CPUMBState *env)
{
    CPUState *cs = CPU(mb_env_get_cpu(env));
    int trapnr, ret;
    target_siginfo_t info;
    
    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case 0xaa:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
	case EXCP_INTERRUPT:
	  /* just indicate that signals should be handled asap */
	  break;
        case EXCP_BREAK:
            /* Return address is 4 bytes after the call.  */
            env->regs[14] += 4;
            env->sregs[SR_PC] = env->regs[14];
            ret = do_syscall(env, 
                             env->regs[12], 
                             env->regs[5], 
                             env->regs[6], 
                             env->regs[7], 
                             env->regs[8], 
                             env->regs[9], 
                             env->regs[10],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                /* Wind back to before the syscall. */
                env->sregs[SR_PC] -= 4;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[3] = ret;
            }
            /* All syscall exits result in guest r14 being equal to the
             * PC we return to, because the kernel syscall exit "rtbd" does
             * this. (This is true even for sigreturn(); note that r14 is
             * not a userspace-usable register, as the kernel may clobber it
             * at any point.)
             */
            env->regs[14] = env->sregs[SR_PC];
            break;
        case EXCP_HW_EXCP:
            env->regs[17] = env->sregs[SR_PC] + 4;
            if (env->iflags & D_FLAG) {
                env->sregs[SR_ESR] |= 1 << 12;
                env->sregs[SR_PC] -= 4;
                /* FIXME: if branch was immed, replay the imm as well.  */
            }

            env->iflags &= ~(IMM_FLAG | D_FLAG);

            switch (env->sregs[SR_ESR] & 31) {
                case ESR_EC_DIVZERO:
                    info.si_signo = TARGET_SIGFPE;
                    info.si_errno = 0;
                    info.si_code = TARGET_FPE_FLTDIV;
                    info._sifields._sigfault._addr = 0;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                    break;
                case ESR_EC_FPU:
                    info.si_signo = TARGET_SIGFPE;
                    info.si_errno = 0;
                    if (env->sregs[SR_FSR] & FSR_IO) {
                        info.si_code = TARGET_FPE_FLTINV;
                    }
                    if (env->sregs[SR_FSR] & FSR_DZ) {
                        info.si_code = TARGET_FPE_FLTDIV;
                    }
                    info._sifields._sigfault._addr = 0;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                    break;
                default:
                    printf ("Unhandled hw-exception: 0x%x\n",
                            env->sregs[SR_ESR] & ESR_EC_MASK);
                    cpu_dump_state(cs, stderr, fprintf, 0);
                    exit(EXIT_FAILURE);
                    break;
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);
    }
}
#endif

#ifdef TARGET_M68K

void cpu_loop(CPUM68KState *env)
{
    CPUState *cs = CPU(m68k_env_get_cpu(env));
    int trapnr;
    unsigned int n;
    target_siginfo_t info;
    TaskState *ts = cs->opaque;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case EXCP_ILLEGAL:
            {
                if (ts->sim_syscalls) {
                    uint16_t nr;
                    get_user_u16(nr, env->pc + 2);
                    env->pc += 4;
                    do_m68k_simcall(env, nr);
                } else {
                    goto do_sigill;
                }
            }
            break;
        case EXCP_HALT_INSN:
            /* Semihosing syscall.  */
            env->pc += 4;
            do_m68k_semihosting(env, env->dregs[0]);
            break;
        case EXCP_LINEA:
        case EXCP_LINEF:
        case EXCP_UNSUPPORTED:
        do_sigill:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_DIV0:
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = TARGET_FPE_INTDIV;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_TRAP0:
            {
                abi_long ret;
                ts->sim_syscalls = 0;
                n = env->dregs[0];
                env->pc += 2;
                ret = do_syscall(env,
                                 n,
                                 env->dregs[1],
                                 env->dregs[2],
                                 env->dregs[3],
                                 env->dregs[4],
                                 env->dregs[5],
                                 env->aregs[0],
                                 0, 0);
                if (ret == -TARGET_ERESTARTSYS) {
                    env->pc -= 2;
                } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                    env->dregs[0] = ret;
                }
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ACCESS:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->mmu.ar;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig(cs, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                  }
            }
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif /* TARGET_M68K */

#ifdef TARGET_ALPHA
void cpu_loop(CPUAlphaState *env)
{
    CPUState *cs = CPU(alpha_env_get_cpu(env));
    int trapnr;
    target_siginfo_t info;
    abi_long sysret;

    while (1) {
        bool arch_interrupt = true;

        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_RESET:
            fprintf(stderr, "Reset requested. Exit\n");
            exit(EXIT_FAILURE);
            break;
        case EXCP_MCHK:
            fprintf(stderr, "Machine check exception. Exit\n");
            exit(EXIT_FAILURE);
            break;
        case EXCP_SMP_INTERRUPT:
        case EXCP_CLK_INTERRUPT:
        case EXCP_DEV_INTERRUPT:
            fprintf(stderr, "External interrupt. Exit\n");
            exit(EXIT_FAILURE);
            break;
        case EXCP_MMFAULT:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = (page_get_flags(env->trap_arg0) & PAGE_VALID
                            ? TARGET_SEGV_ACCERR : TARGET_SEGV_MAPERR);
            info._sifields._sigfault._addr = env->trap_arg0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_UNALIGN:
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_BUS_ADRALN;
            info._sifields._sigfault._addr = env->trap_arg0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_OPCDEC:
        do_sigill:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPC;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_ARITH:
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = TARGET_FPE_FLTINV;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_FEN:
            /* No-op.  Linux simply re-enables the FPU.  */
            break;
        case EXCP_CALL_PAL:
            switch (env->error_code) {
            case 0x80:
                /* BPT */
                info.si_signo = TARGET_SIGTRAP;
                info.si_errno = 0;
                info.si_code = TARGET_TRAP_BRKPT;
                info._sifields._sigfault._addr = env->pc;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                break;
            case 0x81:
                /* BUGCHK */
                info.si_signo = TARGET_SIGTRAP;
                info.si_errno = 0;
                info.si_code = 0;
                info._sifields._sigfault._addr = env->pc;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                break;
            case 0x83:
                /* CALLSYS */
                trapnr = env->ir[IR_V0];
                sysret = do_syscall(env, trapnr,
                                    env->ir[IR_A0], env->ir[IR_A1],
                                    env->ir[IR_A2], env->ir[IR_A3],
                                    env->ir[IR_A4], env->ir[IR_A5],
                                    0, 0);
                if (sysret == -TARGET_ERESTARTSYS) {
                    env->pc -= 4;
                    break;
                }
                if (sysret == -TARGET_QEMU_ESIGRETURN) {
                    break;
                }
                /* Syscall writes 0 to V0 to bypass error check, similar
                   to how this is handled internal to Linux kernel.
                   (Ab)use trapnr temporarily as boolean indicating error.  */
                trapnr = (env->ir[IR_V0] != 0 && sysret < 0);
                env->ir[IR_V0] = (trapnr ? -sysret : sysret);
                env->ir[IR_A3] = trapnr;
                break;
            case 0x86:
                /* IMB */
                /* ??? We can probably elide the code using page_unprotect
                   that is checking for self-modifying code.  Instead we
                   could simply call tb_flush here.  Until we work out the
                   changes required to turn off the extra write protection,
                   this can be a no-op.  */
                break;
            case 0x9E:
                /* RDUNIQUE */
                /* Handled in the translator for usermode.  */
                abort();
            case 0x9F:
                /* WRUNIQUE */
                /* Handled in the translator for usermode.  */
                abort();
            case 0xAA:
                /* GENTRAP */
                info.si_signo = TARGET_SIGFPE;
                switch (env->ir[IR_A0]) {
                case TARGET_GEN_INTOVF:
                    info.si_code = TARGET_FPE_INTOVF;
                    break;
                case TARGET_GEN_INTDIV:
                    info.si_code = TARGET_FPE_INTDIV;
                    break;
                case TARGET_GEN_FLTOVF:
                    info.si_code = TARGET_FPE_FLTOVF;
                    break;
                case TARGET_GEN_FLTUND:
                    info.si_code = TARGET_FPE_FLTUND;
                    break;
                case TARGET_GEN_FLTINV:
                    info.si_code = TARGET_FPE_FLTINV;
                    break;
                case TARGET_GEN_FLTINE:
                    info.si_code = TARGET_FPE_FLTRES;
                    break;
                case TARGET_GEN_ROPRAND:
                    info.si_code = 0;
                    break;
                default:
                    info.si_signo = TARGET_SIGTRAP;
                    info.si_code = 0;
                    break;
                }
                info.si_errno = 0;
                info._sifields._sigfault._addr = env->pc;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
                break;
            default:
                goto do_sigill;
            }
            break;
        case EXCP_DEBUG:
            info.si_signo = gdb_handlesig(cs, TARGET_SIGTRAP);
            if (info.si_signo) {
                info.si_errno = 0;
                info.si_code = TARGET_TRAP_BRKPT;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            } else {
                arch_interrupt = false;
            }
            break;
        case EXCP_INTERRUPT:
            /* Just indicate that signals should be handled asap.  */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            arch_interrupt = false;
            break;
        default:
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);

        /* Most of the traps imply a transition through PALcode, which
           implies an REI instruction has been executed.  Which means
           that RX and LOCK_ADDR should be cleared.  But there are a
           few exceptions for traps internal to QEMU.  */
        if (arch_interrupt) {
            env->flags &= ~ENV_FLAG_RX_FLAG;
            env->lock_addr = -1;
        }
    }
}
#endif /* TARGET_ALPHA */

#ifdef TARGET_S390X
void cpu_loop(CPUS390XState *env)
{
    CPUState *cs = CPU(s390_env_get_cpu(env));
    int trapnr, n, sig;
    target_siginfo_t info;
    target_ulong addr;
    abi_long ret;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_INTERRUPT:
            /* Just indicate that signals should be handled asap.  */
            break;

        case EXCP_SVC:
            n = env->int_svc_code;
            if (!n) {
                /* syscalls > 255 */
                n = env->regs[1];
            }
            env->psw.addr += env->int_svc_ilen;
            ret = do_syscall(env, n, env->regs[2], env->regs[3],
                             env->regs[4], env->regs[5],
                             env->regs[6], env->regs[7], 0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->psw.addr -= env->int_svc_ilen;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[2] = ret;
            }
            break;

        case EXCP_DEBUG:
            sig = gdb_handlesig(cs, TARGET_SIGTRAP);
            if (sig) {
                n = TARGET_TRAP_BRKPT;
                goto do_signal_pc;
            }
            break;
        case EXCP_PGM:
            n = env->int_pgm_code;
            switch (n) {
            case PGM_OPERATION:
            case PGM_PRIVILEGED:
                sig = TARGET_SIGILL;
                n = TARGET_ILL_ILLOPC;
                goto do_signal_pc;
            case PGM_PROTECTION:
            case PGM_ADDRESSING:
                sig = TARGET_SIGSEGV;
                /* XXX: check env->error_code */
                n = TARGET_SEGV_MAPERR;
                addr = env->__excp_addr;
                goto do_signal;
            case PGM_EXECUTE:
            case PGM_SPECIFICATION:
            case PGM_SPECIAL_OP:
            case PGM_OPERAND:
            do_sigill_opn:
                sig = TARGET_SIGILL;
                n = TARGET_ILL_ILLOPN;
                goto do_signal_pc;

            case PGM_FIXPT_OVERFLOW:
                sig = TARGET_SIGFPE;
                n = TARGET_FPE_INTOVF;
                goto do_signal_pc;
            case PGM_FIXPT_DIVIDE:
                sig = TARGET_SIGFPE;
                n = TARGET_FPE_INTDIV;
                goto do_signal_pc;

            case PGM_DATA:
                n = (env->fpc >> 8) & 0xff;
                if (n == 0xff) {
                    /* compare-and-trap */
                    goto do_sigill_opn;
                } else {
                    /* An IEEE exception, simulated or otherwise.  */
                    if (n & 0x80) {
                        n = TARGET_FPE_FLTINV;
                    } else if (n & 0x40) {
                        n = TARGET_FPE_FLTDIV;
                    } else if (n & 0x20) {
                        n = TARGET_FPE_FLTOVF;
                    } else if (n & 0x10) {
                        n = TARGET_FPE_FLTUND;
                    } else if (n & 0x08) {
                        n = TARGET_FPE_FLTRES;
                    } else {
                        /* ??? Quantum exception; BFP, DFP error.  */
                        goto do_sigill_opn;
                    }
                    sig = TARGET_SIGFPE;
                    goto do_signal_pc;
                }

            default:
                fprintf(stderr, "Unhandled program exception: %#x\n", n);
                cpu_dump_state(cs, stderr, fprintf, 0);
                exit(EXIT_FAILURE);
            }
            break;

        do_signal_pc:
            addr = env->psw.addr;
        do_signal:
            info.si_signo = sig;
            info.si_errno = 0;
            info.si_code = n;
            info._sifields._sigfault._addr = addr;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;

        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            fprintf(stderr, "Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(cs, stderr, fprintf, 0);
            exit(EXIT_FAILURE);
        }
        process_pending_signals (env);
    }
}

#endif /* TARGET_S390X */

#ifdef TARGET_TILEGX

static void gen_sigill_reg(CPUTLGState *env)
{
    target_siginfo_t info;

    info.si_signo = TARGET_SIGILL;
    info.si_errno = 0;
    info.si_code = TARGET_ILL_PRVREG;
    info._sifields._sigfault._addr = env->pc;
    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
}

static void do_signal(CPUTLGState *env, int signo, int sigcode)
{
    target_siginfo_t info;

    info.si_signo = signo;
    info.si_errno = 0;
    info._sifields._sigfault._addr = env->pc;

    if (signo == TARGET_SIGSEGV) {
        /* The passed in sigcode is a dummy; check for a page mapping
           and pass either MAPERR or ACCERR.  */
        target_ulong addr = env->excaddr;
        info._sifields._sigfault._addr = addr;
        if (page_check_range(addr, 1, PAGE_VALID) < 0) {
            sigcode = TARGET_SEGV_MAPERR;
        } else {
            sigcode = TARGET_SEGV_ACCERR;
        }
    }
    info.si_code = sigcode;

    queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
}

static void gen_sigsegv_maperr(CPUTLGState *env, target_ulong addr)
{
    env->excaddr = addr;
    do_signal(env, TARGET_SIGSEGV, 0);
}

static void set_regval(CPUTLGState *env, uint8_t reg, uint64_t val)
{
    if (unlikely(reg >= TILEGX_R_COUNT)) {
        switch (reg) {
        case TILEGX_R_SN:
        case TILEGX_R_ZERO:
            return;
        case TILEGX_R_IDN0:
        case TILEGX_R_IDN1:
        case TILEGX_R_UDN0:
        case TILEGX_R_UDN1:
        case TILEGX_R_UDN2:
        case TILEGX_R_UDN3:
            gen_sigill_reg(env);
            return;
        default:
            g_assert_not_reached();
        }
    }
    env->regs[reg] = val;
}

/*
 * Compare the 8-byte contents of the CmpValue SPR with the 8-byte value in
 * memory at the address held in the first source register. If the values are
 * not equal, then no memory operation is performed. If the values are equal,
 * the 8-byte quantity from the second source register is written into memory
 * at the address held in the first source register. In either case, the result
 * of the instruction is the value read from memory. The compare and write to
 * memory are atomic and thus can be used for synchronization purposes. This
 * instruction only operates for addresses aligned to a 8-byte boundary.
 * Unaligned memory access causes an Unaligned Data Reference interrupt.
 *
 * Functional Description (64-bit)
 *       uint64_t memVal = memoryReadDoubleWord (rf[SrcA]);
 *       rf[Dest] = memVal;
 *       if (memVal == SPR[CmpValueSPR])
 *           memoryWriteDoubleWord (rf[SrcA], rf[SrcB]);
 *
 * Functional Description (32-bit)
 *       uint64_t memVal = signExtend32 (memoryReadWord (rf[SrcA]));
 *       rf[Dest] = memVal;
 *       if (memVal == signExtend32 (SPR[CmpValueSPR]))
 *           memoryWriteWord (rf[SrcA], rf[SrcB]);
 *
 *
 * This function also processes exch and exch4 which need not process SPR.
 */
static void do_exch(CPUTLGState *env, bool quad, bool cmp)
{
    target_ulong addr;
    target_long val, sprval;

    start_exclusive();

    addr = env->atomic_srca;
    if (quad ? get_user_s64(val, addr) : get_user_s32(val, addr)) {
        goto sigsegv_maperr;
    }

    if (cmp) {
        if (quad) {
            sprval = env->spregs[TILEGX_SPR_CMPEXCH];
        } else {
            sprval = sextract64(env->spregs[TILEGX_SPR_CMPEXCH], 0, 32);
        }
    }

    if (!cmp || val == sprval) {
        target_long valb = env->atomic_srcb;
        if (quad ? put_user_u64(valb, addr) : put_user_u32(valb, addr)) {
            goto sigsegv_maperr;
        }
    }

    set_regval(env, env->atomic_dstr, val);
    end_exclusive();
    return;

 sigsegv_maperr:
    end_exclusive();
    gen_sigsegv_maperr(env, addr);
}

static void do_fetch(CPUTLGState *env, int trapnr, bool quad)
{
    int8_t write = 1;
    target_ulong addr;
    target_long val, valb;

    start_exclusive();

    addr = env->atomic_srca;
    valb = env->atomic_srcb;
    if (quad ? get_user_s64(val, addr) : get_user_s32(val, addr)) {
        goto sigsegv_maperr;
    }

    switch (trapnr) {
    case TILEGX_EXCP_OPCODE_FETCHADD:
    case TILEGX_EXCP_OPCODE_FETCHADD4:
        valb += val;
        break;
    case TILEGX_EXCP_OPCODE_FETCHADDGEZ:
        valb += val;
        if (valb < 0) {
            write = 0;
        }
        break;
    case TILEGX_EXCP_OPCODE_FETCHADDGEZ4:
        valb += val;
        if ((int32_t)valb < 0) {
            write = 0;
        }
        break;
    case TILEGX_EXCP_OPCODE_FETCHAND:
    case TILEGX_EXCP_OPCODE_FETCHAND4:
        valb &= val;
        break;
    case TILEGX_EXCP_OPCODE_FETCHOR:
    case TILEGX_EXCP_OPCODE_FETCHOR4:
        valb |= val;
        break;
    default:
        g_assert_not_reached();
    }

    if (write) {
        if (quad ? put_user_u64(valb, addr) : put_user_u32(valb, addr)) {
            goto sigsegv_maperr;
        }
    }

    set_regval(env, env->atomic_dstr, val);
    end_exclusive();
    return;

 sigsegv_maperr:
    end_exclusive();
    gen_sigsegv_maperr(env, addr);
}

void cpu_loop(CPUTLGState *env)
{
    CPUState *cs = CPU(tilegx_env_get_cpu(env));
    int trapnr;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case TILEGX_EXCP_SYSCALL:
        {
            abi_ulong ret = do_syscall(env, env->regs[TILEGX_R_NR],
                                       env->regs[0], env->regs[1],
                                       env->regs[2], env->regs[3],
                                       env->regs[4], env->regs[5],
                                       env->regs[6], env->regs[7]);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 8;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[TILEGX_R_RE] = ret;
                env->regs[TILEGX_R_ERR] = TILEGX_IS_ERRNO(ret) ? -ret : 0;
            }
            break;
        }
        case TILEGX_EXCP_OPCODE_EXCH:
            do_exch(env, true, false);
            break;
        case TILEGX_EXCP_OPCODE_EXCH4:
            do_exch(env, false, false);
            break;
        case TILEGX_EXCP_OPCODE_CMPEXCH:
            do_exch(env, true, true);
            break;
        case TILEGX_EXCP_OPCODE_CMPEXCH4:
            do_exch(env, false, true);
            break;
        case TILEGX_EXCP_OPCODE_FETCHADD:
        case TILEGX_EXCP_OPCODE_FETCHADDGEZ:
        case TILEGX_EXCP_OPCODE_FETCHAND:
        case TILEGX_EXCP_OPCODE_FETCHOR:
            do_fetch(env, trapnr, true);
            break;
        case TILEGX_EXCP_OPCODE_FETCHADD4:
        case TILEGX_EXCP_OPCODE_FETCHADDGEZ4:
        case TILEGX_EXCP_OPCODE_FETCHAND4:
        case TILEGX_EXCP_OPCODE_FETCHOR4:
            do_fetch(env, trapnr, false);
            break;
        case TILEGX_EXCP_SIGNAL:
            do_signal(env, env->signo, env->sigcode);
            break;
        case TILEGX_EXCP_REG_IDN_ACCESS:
        case TILEGX_EXCP_REG_UDN_ACCESS:
            gen_sigill_reg(env);
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            fprintf(stderr, "trapnr is %d[0x%x].\n", trapnr, trapnr);
            g_assert_not_reached();
        }
        process_pending_signals(env);
    }
}

#endif

#ifdef TARGET_HPPA

static abi_ulong hppa_lws(CPUHPPAState *env)
{
    uint32_t which = env->gr[20];
    abi_ulong addr = env->gr[26];
    abi_ulong old = env->gr[25];
    abi_ulong new = env->gr[24];
    abi_ulong size, ret;

    switch (which) {
    default:
        return -TARGET_ENOSYS;

    case 0: /* elf32 atomic 32bit cmpxchg */
        if ((addr & 3) || !access_ok(VERIFY_WRITE, addr, 4)) {
            return -TARGET_EFAULT;
        }
        old = tswap32(old);
        new = tswap32(new);
        ret = atomic_cmpxchg((uint32_t *)g2h(addr), old, new);
        ret = tswap32(ret);
        break;

    case 2: /* elf32 atomic "new" cmpxchg */
        size = env->gr[23];
        if (size >= 4) {
            return -TARGET_ENOSYS;
        }
        if (((addr | old | new) & ((1 << size) - 1))
            || !access_ok(VERIFY_WRITE, addr, 1 << size)
            || !access_ok(VERIFY_READ, old, 1 << size)
            || !access_ok(VERIFY_READ, new, 1 << size)) {
            return -TARGET_EFAULT;
        }
        /* Note that below we use host-endian loads so that the cmpxchg
           can be host-endian as well.  */
        switch (size) {
        case 0:
            old = *(uint8_t *)g2h(old);
            new = *(uint8_t *)g2h(new);
            ret = atomic_cmpxchg((uint8_t *)g2h(addr), old, new);
            ret = ret != old;
            break;
        case 1:
            old = *(uint16_t *)g2h(old);
            new = *(uint16_t *)g2h(new);
            ret = atomic_cmpxchg((uint16_t *)g2h(addr), old, new);
            ret = ret != old;
            break;
        case 2:
            old = *(uint32_t *)g2h(old);
            new = *(uint32_t *)g2h(new);
            ret = atomic_cmpxchg((uint32_t *)g2h(addr), old, new);
            ret = ret != old;
            break;
        case 3:
            {
                uint64_t o64, n64, r64;
                o64 = *(uint64_t *)g2h(old);
                n64 = *(uint64_t *)g2h(new);
#ifdef CONFIG_ATOMIC64
                r64 = atomic_cmpxchg__nocheck((uint64_t *)g2h(addr), o64, n64);
                ret = r64 != o64;
#else
                start_exclusive();
                r64 = *(uint64_t *)g2h(addr);
                ret = 1;
                if (r64 == o64) {
                    *(uint64_t *)g2h(addr) = n64;
                    ret = 0;
                }
                end_exclusive();
#endif
            }
            break;
        }
        break;
    }

    env->gr[28] = ret;
    return 0;
}

void cpu_loop(CPUHPPAState *env)
{
    CPUState *cs = CPU(hppa_env_get_cpu(env));
    target_siginfo_t info;
    abi_ulong ret;
    int trapnr;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_SYSCALL:
            ret = do_syscall(env, env->gr[20],
                             env->gr[26], env->gr[25],
                             env->gr[24], env->gr[23],
                             env->gr[22], env->gr[21], 0, 0);
            switch (ret) {
            default:
                env->gr[28] = ret;
                /* We arrived here by faking the gateway page.  Return.  */
                env->iaoq_f = env->gr[31];
                env->iaoq_b = env->gr[31] + 4;
                break;
            case -TARGET_ERESTARTSYS:
            case -TARGET_QEMU_ESIGRETURN:
                break;
            }
            break;
        case EXCP_SYSCALL_LWS:
            env->gr[21] = hppa_lws(env);
            /* We arrived here by faking the gateway page.  Return.  */
            env->iaoq_f = env->gr[31];
            env->iaoq_b = env->gr[31] + 4;
            break;
        case EXCP_SIGSEGV:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->ior;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_SIGILL:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->iaoq_f;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_SIGFPE:
            info.si_signo = TARGET_SIGFPE;
            info.si_errno = 0;
            info.si_code = 0;
            info._sifields._sigfault._addr = env->iaoq_f;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_DEBUG:
            trapnr = gdb_handlesig(cs, TARGET_SIGTRAP);
            if (trapnr) {
                info.si_signo = trapnr;
                info.si_errno = 0;
                info.si_code = TARGET_TRAP_BRKPT;
                queue_signal(env, trapnr, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        default:
            g_assert_not_reached();
        }
        process_pending_signals(env);
    }
}

#endif /* TARGET_HPPA */

THREAD CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    ts->used = 1;
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUState *new_cpu = cpu_init(cpu_model);
    CPUArchState *new_env = new_cpu->env_ptr;
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&new_cpu->breakpoints);
    QTAILQ_INIT(&new_cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
    qemu_log_needs_buffers();
    qemu_set_log(mask);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg, &error_fatal);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage(EXIT_FAILURE);
    }

    if (*p == 'M') {
        guest_stack_size *= 1024 * 1024;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= 1024;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_randseed(const char *arg)
{
    unsigned long long seed;

    if (parse_uint_full(arg, &seed, 0) != 0 || seed > UINT_MAX) {
        fprintf(stderr, "Invalid seed number: %s\n", arg);
        exit(EXIT_FAILURE);
    }
    srand(seed);
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (((reserved_va >> shift) != unshifted)
#if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
            || (reserved_va > (1ul << TARGET_VIRT_ADDR_SPACE_BITS))
#endif
            ) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_VERSION QEMU_PKGVERSION
           "\n" QEMU_COPYRIGHT "\n");
    exit(EXIT_SUCCESS);
}

static char *trace_file;
static void handle_arg_trace(const char *arg)
{
    g_free(trace_file);
    trace_file = trace_opt_parse(arg);
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"help",       "",                 false, handle_arg_help,
     "",           ""},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_randseed,
     "",           "Seed for pseudo-random number generator"},
    {"trace",      "QEMU_TRACE",       true,  handle_arg_trace,
     "",           "[[enable=]<pattern>][,events=<file>][,file=<file>]"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n");

    exit(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        exit(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}


/*
char common_lib_name[50][50];
int common_lib_addr[50];
int common_index = 0;


int search_libname(char * name)
{
    for(int i = 0; i < common_index; i++)
    {
        if(strcmp(name, common_lib_name[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

void add_lib_addr_pair(char *name, int addr)
{
    int ind = search_libname(name);
    if(ind == -1)
    {
        strcpy(common_lib_name[common_index], name);
        common_lib_addr[common_index] = addr;
        common_index++;
    }
}

void helper_add_not_gencode(char *lib_name, int offset) 
{
    int ind = search_libname(lib_name);
    assert(ind!=-1);
    int base_addr = common_lib_addr[ind];
    add_not_gencode(base_addr + offset);
    
}
*/

int main(int argc, char **argv, char **envp)
{
#ifdef MEM_MAPPING
    cross_process_mutex_first_init(); //zyw

    vir_spa_index= 0;
    vir_phy_index = 0;
    hva_start = 0;
    
    parse_mapping_table("mapping_table");
    printf("hva_start:%lx\n", hva_start);
    printf("mem file %s\n", mem_file);
    mem_file_fd = open(mem_file, O_RDWR, 0);
    assert(mem_file_fd!=-1);


    getconfig("program_analysis", program_analysis); 
    printf("main is:%s\n", program_analysis);
    assert(strlen(program_analysis)>0);
    FirmAFL_config();
#endif
    
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    srand(time(NULL));

    qemu_add_opts(&qemu_trace_opts);

    optind = parse_args(argc, argv);

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    init_qemu_uname_release();

    if (cpu_model == NULL) {
#if defined(TARGET_I386)
#ifdef TARGET_X86_64
        cpu_model = "qemu64";
#else
        cpu_model = "qemu32";
#endif
#elif defined(TARGET_ARM)
        cpu_model = "any";
#elif defined(TARGET_UNICORE32)
        cpu_model = "any";
#elif defined(TARGET_M68K)
        cpu_model = "any";
#elif defined(TARGET_SPARC)
#ifdef TARGET_SPARC64
        cpu_model = "TI UltraSparc II";
#else
        cpu_model = "Fujitsu MB86904";
#endif
#elif defined(TARGET_MIPS)
#if defined(TARGET_ABI_MIPSN32) || defined(TARGET_ABI_MIPSN64)
        cpu_model = "5KEf";
#else
        cpu_model = "24Kf";
#endif
#elif defined TARGET_OPENRISC
        cpu_model = "or1200";
#elif defined(TARGET_PPC)
# ifdef TARGET_PPC64
        cpu_model = "POWER8";
# else
        cpu_model = "750";
# endif
#elif defined TARGET_SH4
        cpu_model = TYPE_SH7785_CPU;
#elif defined TARGET_S390X
        cpu_model = "qemu";
#else
        cpu_model = "any";
#endif
    }
    tcg_exec_init(0);
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    cpu = cpu_init(cpu_model);
    if (!cpu) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(EXIT_FAILURE);
    }
    env = cpu->env_ptr;
    cpu_reset(cpu);

    thread_cpu = cpu;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    if (getenv("QEMU_RAND_SEED")) {
        handle_arg_randseed(getenv("QEMU_RAND_SEED"));
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Now that page sizes are configured in cpu_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(EXIT_FAILURE);
        }

        if (reserved_va) {
            mmap_next_start = reserved_va;
        }
    }

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(EXIT_FAILURE);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }


#ifdef FEED_INPUT
    aflFile =  target_argv[1];
    target_argv[target_argc] = NULL;
#endif

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(filename, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", filename, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }

    ret = loader_exec(execfd, filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  0x%lx\n", guest_base);
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(&tcg_ctx);

#if defined(TARGET_I386)
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
#ifndef TARGET_ABI32
    /* enable 64 bit mode if possible */
    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
#ifndef TARGET_ABI32
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_EBP] = regs->rbp;
    env->regs[R_ESP] = regs->rsp;
    env->eip = regs->rip;
#else
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
#endif

    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h(env->idt.base);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ|PROT_WRITE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
#ifdef TARGET_ABI32
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
    /* This hack makes Wine work... */
    env->segs[R_FS].selector = 0;
#else
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
#endif
#elif defined(TARGET_AARCH64)
    {
        int i;

        if (!(arm_feature(env, ARM_FEATURE_AARCH64))) {
            fprintf(stderr,
                    "The selected ARM CPU does not support 64 bit mode\n");
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < 31; i++) {
            env->xregs[i] = regs->regs[i];
        }
        env->pc = regs->pc;
        env->xregs[31] = regs->sp;
    }
#elif defined(TARGET_ARM)
    {
        int i;
        cpsr_write(env, regs->uregs[16], CPSR_USER | CPSR_EXEC,
                   CPSRWriteByInstr);
        for(i = 0; i < 16; i++) {
            env->regs[i] = regs->uregs[i];
        }
#ifdef TARGET_WORDS_BIGENDIAN
        /* Enable BE8.  */
        if (EF_ARM_EABI_VERSION(info->elf_flags) >= EF_ARM_EABI_VER4
            && (info->elf_flags & EF_ARM_BE8)) {
            env->uncached_cpsr |= CPSR_E;
            env->cp15.sctlr_el[1] |= SCTLR_E0E;
        } else {
            env->cp15.sctlr_el[1] |= SCTLR_B;
        }
#endif
    }
#elif defined(TARGET_UNICORE32)
    {
        int i;
        cpu_asr_write(env, regs->uregs[32], 0xffffffff);
        for (i = 0; i < 32; i++) {
            env->regs[i] = regs->uregs[i];
        }
    }
#elif defined(TARGET_SPARC)
    {
        int i;
	env->pc = regs->pc;
	env->npc = regs->npc;
        env->y = regs->y;
        for(i = 0; i < 8; i++)
            env->gregs[i] = regs->u_regs[i];
        for(i = 0; i < 8; i++)
            env->regwptr[i] = regs->u_regs[i + 8];
    }
#elif defined(TARGET_PPC)
    {
        int i;

#if defined(TARGET_PPC64)
        int flag = (env->insns_flags2 & PPC2_BOOKE206) ? MSR_CM : MSR_SF;
#if defined(TARGET_ABI32)
        env->msr &= ~((target_ulong)1 << flag);
#else
        env->msr |= (target_ulong)1 << flag;
#endif
#endif
        env->nip = regs->nip;
        for(i = 0; i < 32; i++) {
            env->gpr[i] = regs->gpr[i];
        }
    }
#elif defined(TARGET_M68K)
    {
        env->pc = regs->pc;
        env->dregs[0] = regs->d0;
        env->dregs[1] = regs->d1;
        env->dregs[2] = regs->d2;
        env->dregs[3] = regs->d3;
        env->dregs[4] = regs->d4;
        env->dregs[5] = regs->d5;
        env->dregs[6] = regs->d6;
        env->dregs[7] = regs->d7;
        env->aregs[0] = regs->a0;
        env->aregs[1] = regs->a1;
        env->aregs[2] = regs->a2;
        env->aregs[3] = regs->a3;
        env->aregs[4] = regs->a4;
        env->aregs[5] = regs->a5;
        env->aregs[6] = regs->a6;
        env->aregs[7] = regs->usp;
        env->sr = regs->sr;
        ts->sim_syscalls = 1;
    }
#elif defined(TARGET_MICROBLAZE)
    {
        env->regs[0] = regs->r0;
        env->regs[1] = regs->r1;
        env->regs[2] = regs->r2;
        env->regs[3] = regs->r3;
        env->regs[4] = regs->r4;
        env->regs[5] = regs->r5;
        env->regs[6] = regs->r6;
        env->regs[7] = regs->r7;
        env->regs[8] = regs->r8;
        env->regs[9] = regs->r9;
        env->regs[10] = regs->r10;
        env->regs[11] = regs->r11;
        env->regs[12] = regs->r12;
        env->regs[13] = regs->r13;
        env->regs[14] = regs->r14;
        env->regs[15] = regs->r15;	    
        env->regs[16] = regs->r16;	    
        env->regs[17] = regs->r17;	    
        env->regs[18] = regs->r18;	    
        env->regs[19] = regs->r19;	    
        env->regs[20] = regs->r20;	    
        env->regs[21] = regs->r21;	    
        env->regs[22] = regs->r22;	    
        env->regs[23] = regs->r23;	    
        env->regs[24] = regs->r24;	    
        env->regs[25] = regs->r25;	    
        env->regs[26] = regs->r26;	    
        env->regs[27] = regs->r27;	    
        env->regs[28] = regs->r28;	    
        env->regs[29] = regs->r29;	    
        env->regs[30] = regs->r30;	    
        env->regs[31] = regs->r31;	    
        env->sregs[SR_PC] = regs->pc;
    }
#elif defined(TARGET_MIPS)
    {
        int i;

        for(i = 0; i < 32; i++) {
            env->active_tc.gpr[i] = regs->regs[i];
        }
        env->active_tc.PC = regs->cp0_epc & ~(target_ulong)1;
        if (regs->cp0_epc & 1) {
            env->hflags |= MIPS_HFLAG_M16;
        }
        if (((info->elf_flags & EF_MIPS_NAN2008) != 0) !=
            ((env->active_fpu.fcr31 & (1 << FCR31_NAN2008)) != 0)) {
            if ((env->active_fpu.fcr31_rw_bitmask &
                  (1 << FCR31_NAN2008)) == 0) {
                fprintf(stderr, "ELF binary's NaN mode not supported by CPU\n");
                exit(1);
            }
            if ((info->elf_flags & EF_MIPS_NAN2008) != 0) {
                env->active_fpu.fcr31 |= (1 << FCR31_NAN2008);
            } else {
                env->active_fpu.fcr31 &= ~(1 << FCR31_NAN2008);
            }
            restore_snan_bit_mode(env);
        }
    }
#elif defined(TARGET_NIOS2)
    {
        env->regs[0] = 0;
        env->regs[1] = regs->r1;
        env->regs[2] = regs->r2;
        env->regs[3] = regs->r3;
        env->regs[4] = regs->r4;
        env->regs[5] = regs->r5;
        env->regs[6] = regs->r6;
        env->regs[7] = regs->r7;
        env->regs[8] = regs->r8;
        env->regs[9] = regs->r9;
        env->regs[10] = regs->r10;
        env->regs[11] = regs->r11;
        env->regs[12] = regs->r12;
        env->regs[13] = regs->r13;
        env->regs[14] = regs->r14;
        env->regs[15] = regs->r15;
        /* TODO: unsigned long  orig_r2; */
        env->regs[R_RA] = regs->ra;
        env->regs[R_FP] = regs->fp;
        env->regs[R_SP] = regs->sp;
        env->regs[R_GP] = regs->gp;
        env->regs[CR_ESTATUS] = regs->estatus;
        env->regs[R_EA] = regs->ea;
        /* TODO: unsigned long  orig_r7; */

        /* Emulate eret when starting thread. */
        env->regs[R_PC] = regs->ea;
    }
#elif defined(TARGET_OPENRISC)
    {
        int i;

        for (i = 0; i < 32; i++) {
            cpu_set_gpr(env, i, regs->gpr[i]);
        }
        env->pc = regs->pc;
        cpu_set_sr(env, regs->sr);
    }
#elif defined(TARGET_SH4)
    {
        int i;

        for(i = 0; i < 16; i++) {
            env->gregs[i] = regs->regs[i];
        }
        env->pc = regs->pc;
    }
#elif defined(TARGET_ALPHA)
    {
        int i;

        for(i = 0; i < 28; i++) {
            env->ir[i] = ((abi_ulong *)regs)[i];
        }
        env->ir[IR_SP] = regs->usp;
        env->pc = regs->pc;
    }
#elif defined(TARGET_CRIS)
    {
	    env->regs[0] = regs->r0;
	    env->regs[1] = regs->r1;
	    env->regs[2] = regs->r2;
	    env->regs[3] = regs->r3;
	    env->regs[4] = regs->r4;
	    env->regs[5] = regs->r5;
	    env->regs[6] = regs->r6;
	    env->regs[7] = regs->r7;
	    env->regs[8] = regs->r8;
	    env->regs[9] = regs->r9;
	    env->regs[10] = regs->r10;
	    env->regs[11] = regs->r11;
	    env->regs[12] = regs->r12;
	    env->regs[13] = regs->r13;
	    env->regs[14] = info->start_stack;
	    env->regs[15] = regs->acr;	    
	    env->pc = regs->erp;
    }
#elif defined(TARGET_S390X)
    {
            int i;
            for (i = 0; i < 16; i++) {
                env->regs[i] = regs->gprs[i];
            }
            env->psw.mask = regs->psw.mask;
            env->psw.addr = regs->psw.addr;
    }
#elif defined(TARGET_TILEGX)
    {
        int i;
        for (i = 0; i < TILEGX_R_COUNT; i++) {
            env->regs[i] = regs->regs[i];
        }
        for (i = 0; i < TILEGX_SPR_COUNT; i++) {
            env->spregs[i] = 0;
        }
        env->pc = regs->pc;
    }
#elif defined(TARGET_HPPA)
    {
        int i;
        for (i = 1; i < 32; i++) {
            env->gr[i] = regs->gr[i];
        }
        env->iaoq_f = regs->iaoq[0];
        env->iaoq_b = regs->iaoq[1];
    }
#else
#error unsupported target CPU
#endif

#if defined(TARGET_ARM) || defined(TARGET_M68K) || defined(TARGET_UNICORE32)
    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
#endif

    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }

#ifdef MEM_MAPPING

    struct sigaction s_ill; //illegal instruction
    s_ill.sa_flags = SA_SIGINFO;
    s_ill.sa_sigaction = handler_s_ill;
    sigemptyset(&s_ill.sa_mask);
    sigaddset(&s_ill.sa_mask, SIGILL);
    sigaction(SIGILL, &s_ill, 0);

    struct sigaction s;
    s.sa_flags = SA_SIGINFO;
    s.sa_sigaction = handler;
    sigemptyset(&s.sa_mask);
    sigaddset(&s.sa_mask, SIGSEGV);
    sigaction(SIGSEGV, &s, 0);


    open_write_pipe();
    open_read_pipe();

#ifdef TARGET_MIPS
    for(int j=0x400; j <= 0x7ffff; j++)
    {
        target_munmap(j<<12, 1024*4);
    } 
#elif defined(TARGET_ARM)
    for(int j=0x0; j <= 0xbffff; j++)
    {
        target_munmap(j<<12, 1024*4);
    } 
#endif


//snapshot memory
#ifdef STORE_PAGE_FUNC
    snapshot_shmem_id = shmget(0, 1024*1024*16, IPC_CREAT|IPC_EXCL);
    snapshot_shmem_start = shmat(snapshot_shmem_id, 0x80200000 , 0); //zyw 
    snapshot_shmem_pt = snapshot_shmem_start + 8 * 0x1000; // 0x80200000 ~ 0x81200000
    printf("snapshot memory:%lx,%lx,%lx\n", snapshot_shmem_id, snapshot_shmem_start, snapshot_shmem_pt);
#endif

//memory for snapshot synchronization
#ifdef SNAPSHOT_SYNC
#ifdef TARGET_MIPS
      void * sync_shmem_start = shmat(syn_shmem_id, guest_base + 0x182000000 +  1024*1024*16,  1); 
#elif defined(TARGET_ARM)
      void * sync_shmem_start = shmat(syn_shmem_id, 0x81200000 +  1024*1024*16,  1); 
#endif
      //sync_shmem_start = shmat(syn_shmem_id, NULL,  1); 
      printf("snapshot phys addr:%d, %lx, %lx\n",syn_shmem_id, guest_base, sync_shmem_start);
      memset(sync_shmem_start, 0, 8192); //131071
      //phys_addr_stored = (int *)shmem_start; // make a big mistake here, cause two shared memory overlapping
      phys_addr_stored_bitmap = (char *)sync_shmem_start;  
      printf("snapshot phys addr end\n");
#endif
//



#if defined(PRE_MAPPING) && defined(TARGET_MIPS)
    printf("pre_mapping start\n");
    for(int k=0; k<vir_spa_index; k++)
    {
        MISSING_PAGE page;
        int phys_page;
        int page_prot = gva_type[k] & 0x7;

        //if(page_prot == 0) // not to ask these page, or it will crash //lighttpd 24 //jhttpd 11 25
        if(page_prot == 0) // not to ask these page, or it will crash //lighttpd 24 
        //if(page_prot == 0 || k == 11 || k == 25) //jhttpd >=0x7d000 >=0x72000
        {
            continue; //PAGE_NONE
        }
        else if(page_prot == 1 || page_prot == 5) // PAGE_READ, PAGE_READ|PAGE_EXEC
        {
            page.prot = 0;
        }
        else if(page_prot == 3 || page_prot == 7) //PAGE_READ|PAGE_WRITE, PAGE_READ|PAGE_WRITE|PAGE_EXEC
        {
            page.prot = 1;
        }
        else
        {
            printf("page prot error:%d\n", gva_type[k]);
        }
        page.mmu_idx = 2;
#ifdef FEED_INPUT
        if(strcmp(feed_type, "FEED_ENV") == 0)
        {             
            if(strcmp(gva_name[k],lib_name) == 0 && libuclibc_addr_flag == 0)
            {
                libuclibc_addr_flag = 1;
                libuclibc_addr =  gva_start[k];
                printf("libuclibc_addr:%x\n", libuclibc_addr);
            }
        }
#endif
        //printf("item :%s, %d\n", gva_name[k], gva_seq[k]);
        //add_lib_addr_pair(gva_name[k], gva_start[k]);
        if(program_id == 10853 && k == 37)
        {
            gva_start[k]-=0x26000;
        }

        for(int i = gva_start[k]; i < gva_end[k]; i = i+ 1024*4)
        {
            page.addr = i;

            //tplink dir-825 
            if(program_id == 10853)
            {
                 if(strcmp(gva_name[k], "libcrypto.so.0.9.8") == 0 && gva_seq[k] == 0)
                {
                    if(i-gva_start[k] == 0x87000 || i-gva_start[k] >=0x8f000)
                    {
                        continue;
                    }
                }
            }
           
            
            //tcapi
            if(strcmp(program_analysis, "tcapi_new") == 0)
            {
                
                if(strcmp(gva_name[k], "libc.so.0") == 0)
                {
                    if((i - gva_start[k]) == 0x18000)
                    {

                    }
                    else if((i - gva_start[k] >= 0x15000 && i - gva_start[k] < 0x31000) || (i - gva_start[k] > 0x33000 && i - gva_start[k] < 0x3a000) 
                        || (i -gva_start[k] >= 0x3e000 && i-gva_start[k] <= 0x54000))// || (i-gva_start[k] >=0x57000))
                    {
                        continue;
                    }
                }
            
                if(strcmp(gva_name[k], "libgcc_s.so.1") == 0)
                {
                    if((i - gva_start[k] == 0x27000) || (i - gva_start[k] == 0x28000))
                    {

                    }
                    else if(i - gva_start[k] >= 0xc000)
                    {
                        continue;
                    }
                }
            }
            /*
            if(strcmp(program_analysis, "nbench_new") == 0)
            {
                if((i - gva_start[k] >= 0x10000))
                {
                    continue;
                }
            }
            */

            add_premap_page(i);
            //

#ifdef TARGET_MIPS
            write_addr(&page);
            read_addr(page.addr, &phys_page);
#elif defined(TARGET_ARM)
            if(page_prot == 5)
            {
                printf("pre mapping:%x\n", page.addr);
                env->regs[15] = page.addr;
                write_state(env, page.addr, page.prot);
                uintptr_t phys_addr;
                read_addr(page.addr, &phys_addr);
            }
            
#endif     
            if(page.prot == 0)
            {
                target_mmap(i, 1024*4, PROT_READ, MAP_SHARED | MAP_FIXED,  mem_file_fd, phys_page & 0xfffff000); 
            }
            else
            {
                target_mmap(i, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, phys_page & 0xfffff000);
#ifdef STORE_PAGE_FUNC
                store_page(i, 0);
                addr_pair[addr_pair_index].virt_page = i;
                addr_pair[addr_pair_index].phys_page = phys_page & 0xfffff000;
                addr_pair_index++;
#ifdef SNAPSHOT_SYNC
                add_physical_page(phys_page & 0xfffff000);
#endif
#endif
                add_store_write_page(i);
            }
        }    
        for(int i = gva_start[k]; i < gva_end[k]; i = i+ 1024*4)
        {
            if(page.prot == 0)
            {
                add_memory_rw(i, 0);
            }
            else
            {
                add_memory_rw(i, 0);
                add_memory_rw(i, 1);
            }
        }  
    }

#else
    // if choose new_mapping ,this does not work.
    
    for(int k=0; k<vir_phy_index; k++)
    {
        target_ulong vaddr = virt_addr[k];
        target_ulong paddr = phys_addr[k];
        int pro = prot[k];
        if(pro == 0)
        {
            target_mmap(vaddr & 0xfffff000, 1024*4, PROT_READ, MAP_SHARED | MAP_FIXED,  mem_file_fd, paddr & 0xfffff000); 
            printf("target_mmap read:%x, %x\n", vaddr, paddr);
        }
        else
        {
            target_mmap(vaddr & 0xfffff000, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, paddr & 0xfffff000);
            printf("target_mmap write:%x, %x\n", vaddr, paddr);
#ifdef STORE_PAGE_FUNC
            store_page(vaddr  & 0xfffff000, 0);
            addr_pair[addr_pair_index].virt_page = i;
            addr_pair[addr_pair_index].phys_page = paddr & 0xfffff000;
            addr_pair_index++;
#ifdef SNAPSHOT_SYNC
            add_physical_page(paddr & 0xfffff000);
#endif
#endif
            add_store_write_page(vaddr  & 0xfffff000);

        }
    }
    printf("vir_spa_index:%d\n", vir_spa_index);
    for(int k=0; k<vir_spa_index; k++)
    {
        MISSING_PAGE page;
        int phys_page;
        int page_prot = gva_type[k] & 0x7;

        if(page_prot == 0) // not to ask these page, or it will crash //lighttpd 24 
        {
            continue; //PAGE_NONE
        }
        else if(page_prot == 1 || page_prot == 5) // PAGE_READ, PAGE_READ|PAGE_EXEC
        {
            page.prot = 0;
        }
        else if(page_prot == 3 || page_prot == 7) //PAGE_READ|PAGE_WRITE, PAGE_READ|PAGE_WRITE|PAGE_EXEC
        {
            page.prot = 1;
        }
        else
        {
            printf("page prot error:%d\n", gva_type[k]);
        }

        for(int i = gva_start[k]; i < gva_end[k]; i = i+ 1024*4)
        {
            if(page.prot == 0)
            {
                add_memory_rw(i, 0);
            }
            else
            {
                add_memory_rw(i, 0);
                add_memory_rw(i, 1);
            }
        }        
    }
    
#endif


#ifdef TARGET_MIPS

    env->active_tc.PC = init_regs[32];
    env->CP0_Status = init_regs[33];
    env->CP0_Cause = init_regs[34];
    env->CP0_EPC = init_regs[35];
    for(int k=0; k<32; k++)
    {
       env->active_tc.gpr[k] = init_regs[k]; //not i; should be k
    }
    printf("start pc:%x\n", env->active_tc.PC);

#elif defined(TARGET_ARM)
    for(int k=0; k<16; k++)
    {
       env->regs[k] = init_regs[k]; //not i; should be k
    }
    printf("start pc:%x\n", env->regs[15]);

#endif

    startTrace(0x0, 0x7fffffff);
    afl_entry_point = start_fork_pc;
    printf("afl_entry_point:%x, start:%x,end:%x\n", afl_entry_point, afl_start_code ,afl_end_code);
#endif //MEM_MAPPING

#ifdef FEED_INPUT
    prepare_feed_input(cpu);
#endif

#ifdef TARGET_MIPS
    if(CP0_UserLocal!=0)
    {
        env->active_tc.CP0_UserLocal = CP0_UserLocal;
        printf("CP0_UserLocal:%x\n", CP0_UserLocal);
    }
#endif
    cpu_loop(env);
    /* never exits */
    return 0;
}


#ifdef MEM_MAPPING

#ifdef TARGET_MIPS

typedef struct CPUSHSTATE{
    target_ulong regs[32];
    target_ulong PC;
    target_ulong CP0_Status;
    target_ulong CP0_EPC;
    target_ulong CP0_Cause;
} CPUSHSTATE;

void loadCPUShState(CPUSHSTATE *state, CPUArchState *env)
{
    for(int i=0; i<32; i++)
    {
        env->active_tc.gpr[i] = state->regs[i];
    }
    env->active_tc.PC = state->PC;
    env->CP0_Status = state->CP0_Status;
    env->CP0_Cause = state->CP0_Cause;
    env->CP0_EPC = state->CP0_EPC;  
    
}

void storeCPUShState(CPUSHSTATE *state, CPUArchState *env)
{
    for(int i=0; i<32; i++)
    {
        state->regs[i] = env->active_tc.gpr[i];
    }
    state->PC = env->active_tc.PC;
    state->CP0_Status = env->CP0_Status; 
    state->CP0_Cause = env->CP0_Cause; 
    state->CP0_EPC = env->CP0_EPC; 
}

#elif defined(TARGET_ARM)

typedef struct CPUSHSTATE{
    target_ulong regs[16];
} CPUSHSTATE;

void loadCPUShState(CPUSHSTATE *state, CPUArchState *env)
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
        state->regs[i] =  env->regs[i];
    }
}

#endif


char stored_vaddr_page[65536];
void add_store_write_page(int vaddr)
{
    int value = vaddr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    stored_vaddr_page[index] |=  1 << position;
}

void delete_store_write_page(int vaddr)
{
    int value = vaddr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    stored_vaddr_page[index] &= ~(1 << position);
}

int if_write_page_store(int vaddr) //vaddr <= 0x7ffff000
{   
    int value = vaddr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    return (stored_vaddr_page[index] & (1 << position)) !=0; 

}



target_ulong h2g_child(unsigned long x)
{
    if(h2g_valid(x)){
        return h2g_nocheck(x);
    }
    else
    {
        bug_exit(0xfffffffe);
    }
    return 0;
}


#ifdef NEW_MAPPING
static void handler(int sig_num, siginfo_t *si, void *ptr)
{
    CPUArchState *env = first_cpu->env_ptr;
    ucontext_t *uc = (ucontext_t *)ptr;
#ifdef TARGET_MIPS
    target_ulong error_addr = h2g(si->si_addr);
#elif defined(TARGET_ARM)
    target_ulong error_addr = h2g_nocheck(si->si_addr);
#endif
    int err = uc->uc_mcontext.gregs[REG_ERR];
    bool ins_fetch_fault = (err & 16);
    bool write_fault = (err & 2);
    int prot;
    if(ins_fetch_fault){
        prot = 2;
    }
    else if(write_fault){
        prot = 1;
    }
    else{
        prot = 0;
    }
    printf("error_addr:%lx, prot:%d\n", error_addr, prot);
    uint64_t cur_host_pc = uc->uc_mcontext.gregs[REG_RIP];
    target_ulong res_pc = ins_pc_analysis(cur_host_pc, error_addr);
    target_ulong cur_guest_pc;
    if(res_pc == 0) 
    {
        cur_guest_pc = error_addr;
    }
    else
    {
        cur_guest_pc = res_pc;
    }

    //if((cur_guest_pc > 0x70000000 && cur_guest_pc < 0x80000000) || (cur_guest_pc>0x400000 && cur_guest_pc<0x1000000)){
    if(1){
        int phys_page;

        int re;
        gettimeofday(&handle_addr_start, NULL);
        
        cross_process_mutex_init(); //zyw
        pthread_mutex_lock(p_mutex_shared);

        //printf("cur pc:%x, %x, %x, %d\n", cur_guest_pc, env->active_tc.PC, error_addr, prot);

        if(syscall_addr_check_flag !=-1)
        {
            printf("syscall addr check on read or write\n");
            MISSING_PAGE page;
            page.prot = syscall_addr_check_flag;
            page.addr = error_addr;
            page.mmu_idx = 2;
            write_addr(&page);
            syscall_addr_check_flag = -1;

        }
        else
        {
#ifdef TARGET_MIPS
            env->active_tc.PC = cur_guest_pc;
#elif defined(TARGET_ARM)
            env->regs[15] = cur_guest_pc;
#endif
            write_state(env, error_addr, prot);

        }
        uintptr_t phys_addr;
        read_addr(error_addr, &phys_addr);
        if(phys_addr == 0xffffffff)
        {
            pthread_mutex_unlock(p_mutex_shared);
            cross_shamem_disconn(); //ZYW 
            //printf("bug exit\n");
            bug_exit(error_addr);
        }
        if(phys_addr == 0)
        {
            printf("new_mapping handle addr error:%x\n",error_addr);
            normal_exit(0);
        }

        //phys_addr -= hva_start;
        //while(phys_addr != 0)
        //{
       
            //printf("target_mmap:%x, %x, %x\n", error_addr & 0xfffff000, phys_addr & 0xfffff000, prot);
            if(prot == 0 || prot == 2)
            {
                uintptr_t res = target_mmap(error_addr & 0xfffff000, 1024*4, PROT_READ, MAP_SHARED | MAP_FIXED,  mem_file_fd, phys_addr & 0xfffff000);
                assert(res>0);
            }
            else if(prot == 1)
            {
                uintptr_t res = target_mmap(error_addr & 0xfffff000, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, phys_addr & 0xfffff000);
                assert(res>0);
            }
        
            //read_addr(&phys_addr);
        //}
        	
        //read_state(env->active_tc.PC, env);
        pthread_mutex_unlock(p_mutex_shared);
        cross_shamem_disconn(); //ZYW 
    }
}

#else

static void handler(int sig_num, siginfo_t *si, void *ptr)
{
    ucontext_t *uc = (ucontext_t *)ptr;
    MISSING_PAGE page;

    page.addr = h2g_child(si->si_addr);

    if(page.addr == 0)
    {
        printf("last pc:%x\n", last_pc);
    }
    int err = uc->uc_mcontext.gregs[REG_ERR];
    bool ins_fetch_fault = (err & 16);
    bool write_fault = (err & 2);
    if(ins_fetch_fault){
        page.prot = 2;
    }
    else if(write_fault){
        page.prot = 1;
    }
    else{
        page.prot = 0;
    }  
    page.mmu_idx = 2;
/*
    uint64_t cur_host_pc = uc->uc_mcontext.gregs[REG_RIP];
    target_ulong res_pc = ins_pc_analysis(cur_host_pc);
    target_ulong cur_guest_pc;
    if(res_pc == 0) 
    {
        cur_guest_pc = page.addr;
    }
    else
    {
        cur_guest_pc = res_pc;
    }
    printf("cur pc:%x, %x\n", cur_guest_pc, page.addr);
*/
    int res = if_memory_rw(page.addr, page.prot);
    if(print_debug)
    {
        printf("handle:%x,%d, %d, %d\n", page.addr, page.prot, res, page.prot);
    }
#ifdef LMBENCH
    if((page.addr > 0x70000000 && page.addr < 0x80000000) || (page.addr>0x400000 && page.addr<0xf00000)){
#else
    if(res){
#endif
    //  
        if((page.addr & 0xff000000) == 0x7f000000)
        {
            if(program_id == 129781)
            {
                printf("handle special addr:%x\n", page.addr);
                normal_exit(0);
            }
        }

        int phys_page;

        int re;
        gettimeofday(&handle_addr_start, NULL);
        
        cross_process_mutex_init(); //zyw
        pthread_mutex_lock(p_mutex_shared);
        //printf("handler lock:%x\n", page.addr);
#ifdef LMBENCH //lat_pipe
        if((page.addr & 0xfffff000) == 0x4b4000)
        {
            page.prot = 1;
        }
#endif
        write_addr(&page);
        re = read_addr(page.addr, &phys_page);
        if(phys_page == 0)
        {
            printf("handle addr error:%x\n",page.addr);
            pthread_mutex_unlock(p_mutex_shared);
            cross_shamem_disconn(); //ZYW 

            normal_exit(0);
        }
        int file_offset = phys_page & 0xfffff000;
        if(page.prot == 0 || page.prot == 2)
        {
            uintptr_t res = target_mmap(h2g(si->si_addr) & 0xfffff000, 1024*4, PROT_READ, MAP_SHARED | MAP_FIXED,  mem_file_fd, file_offset);
            assert(res>0);
        }
        else if(page.prot == 1)
        {
            uintptr_t res = target_mmap(h2g(si->si_addr) & 0xfffff000, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, file_offset);
            assert(res>0);
        }
        else{
            printf("page prot error:%x\n", page.prot);
            sleep(10000);
        }
        //printf("handler lock over\n");
        pthread_mutex_unlock(p_mutex_shared);

        cross_shamem_disconn(); //ZYW 

        gettimeofday(&handle_addr_end, NULL);
        double handle_addr_time  =  (double)handle_addr_end.tv_sec - handle_addr_start.tv_sec + (handle_addr_end.tv_usec - handle_addr_start.tv_usec)/1000000.0;
        handle_addr_total += handle_addr_time;

        if(page.prot == 1)
        {
            //new
            gettimeofday(&store_page_start, NULL);

    #ifdef STORE_PAGE_FUNC
            store_page(h2g(si->si_addr) & 0xfffff000, 1);
            addr_pair[addr_pair_index].virt_page = h2g(si->si_addr) & 0xfffff000;
            addr_pair[addr_pair_index].phys_page = phys_page & 0xfffff000;
            addr_pair_index++;
    #ifdef SNAPSHOT_SYNC
            add_physical_page(phys_page & 0xfffff000);
    #endif       
    #endif
            add_store_write_page(h2g(si->si_addr) & 0xfffff000);
            gettimeofday(&store_page_end, NULL);
            store_page_total += (double)store_page_end.tv_sec - store_page_start.tv_sec + (store_page_end.tv_usec - store_page_start.tv_usec)/1000000.0;
        }
    #ifdef STORE_PAGE_FUNC
        if(addr_pair_index > 500)
        {
            printf("addr_pair_index over 1000:%d\n", addr_pair_index);
            bug_exit(0xffffffff);
        }

    #endif
        //printf("handler end\n");
    } 
    else{
#ifdef FEED_INPUT
        /*
        if(program_id == 129781)
        {
            FILE *fp = fopen("outputs/new_crash_case", "w+");
            printf("error addr:%x,%lx\n",page.addr, si->si_addr);
            printf("recv content:%s\n", g2h(content_addr));
            fputs(g2h(content_addr), fp);
            fclose(fp);        
        }
        */
#endif
        bug_exit(page.addr);

   }

}
#endif

void parse_mapping_table(char *filename)
{
    
    char strline[100];
    char * res;
    FILE *fp = fopen(filename, "r");
    if(fp == NULL){
        printf("file open error\n");sleep(1000);
        exit(32);
    }
    res = fgets(strline, 100, fp);
    hva_start = strtol(strline,NULL, 16);
    res = fgets(strline, 100, fp);
    start_fork_pc = strtol(strline, NULL, 16);
#ifdef TARGET_MIPS
    for(int i = 0; i < 36; i++)
#elif defined(TARGET_ARM)
    for(int i = 0; i < 16; i++)
#endif
    {
        res = fgets(strline, 100, fp);
        init_regs[i] = strtol(strline,NULL, 16);
    }

    for(int i=0; i<VIRTUAL_SPA; i++)
    {
        gva_start[i] = 0;
        gva_end[i] = 0;
    }
    while(res = fgets(strline, 100, fp)!=NULL){
        if(strstr(strline, "####"))
        {
            break;
        }
        if(strcmp(strline, "\n") == 0)
        {
            continue;
        }
        char *p1 = strtok(strline, ":");
        char *p2 = strtok(NULL, ":");
        char *p3 = strtok(NULL, ":");
        char *p4 = strtok(NULL, ":");
        p4[strlen(p4)-1]='\0';
        gva_start[vir_spa_index] = strtol(p1,NULL, 16);
        gva_end[vir_spa_index] = strtol(p2,NULL, 16);
        gva_type[vir_spa_index] = strtol(p3,NULL, 16);
        strcpy(gva_name[vir_spa_index], p4);
        if(strlen(gva_name[vir_spa_index]) == 0)
        {
            gva_seq[vir_spa_index] = 0;
        }
        else if(strcmp(gva_name[vir_spa_index], last_name)!=0)
        {
            strcpy(last_name, gva_name[vir_spa_index]);
            gva_seq[vir_spa_index] = 0;
            //printf("not equal:%s,%d\n", gva_name[vir_spa_index], gva_seq[vir_spa_index]);
        }
        else
        {
            gva_seq[vir_spa_index] = gva_seq[vir_spa_index -1] + 1;
            //printf("equal:%s,%d\n", gva_name[vir_spa_index], gva_seq[vir_spa_index]);
        }
        vir_spa_index ++;
    }

    while(res = fgets(strline, 100, fp)!=NULL){
        if(strstr(strline, "####"))
        {
            break;
        }
        char *p1 = strtok(strline, ":");
        char *p2 = strtok(NULL, ":");
        char *p3 = strtok(NULL, ":");
        virt_addr[vir_phy_index] = strtol(p1,NULL, 16);
        phys_addr[vir_phy_index] = strtol(p2,NULL, 16);
        prot[vir_phy_index] = strtol(p3,NULL, 16);
        vir_phy_index ++;
    }
#ifdef SNAPSHOT_SYNC
    res = fgets(strline, 100, fp);
    syn_shmem_id = strtol(strline,NULL, 10);
    printf("syn_shmem_id:%d\n", syn_shmem_id);
#endif
    res = fgets(strline, 100, fp);
    accept_fd = strtol(strline, NULL, 10);
    res = fgets(strline, 100, fp);
    CP0_UserLocal = strtol(strline, NULL, 16);
    fclose(fp);
}

void open_write_pipe()
{
    int res = 0;
    if(pipe_write_fd == -1){
        const char *fifo_name_user = "./user_cpu_state";  
        const int open_mode_user = O_WRONLY;      
      
        if(access(fifo_name_user, F_OK) == -1)  
        {  
            res = mkfifo(fifo_name_user, 0777);  
            if(res != 0)  
            { 
                fprintf(stderr, "Could not create fifo %s\n", fifo_name_user);  sleep(1000);
                exit(EXIT_FAILURE);  
            }  
        } 
        pipe_write_fd = open(fifo_name_user, open_mode_user); 
        printf("open write pipe:%d\n", pipe_write_fd);  
    }
}  

void open_read_pipe()
{
    int res = 0;
    if(pipe_read_fd == -1){
        const char *fifo_name_full = "./full_cpu_state";  
        const int open_mode_user = O_RDONLY|O_NONBLOCK;    
        if(access(fifo_name_full, F_OK) == -1)  
        {  
            res = mkfifo(fifo_name_full, 0777);  
            if(res != 0)  
            {  
                fprintf(stderr, "Could not create fifo %s\n", fifo_name_full);  sleep(1000);
                exit(EXIT_FAILURE);  
            }  
        } 
        pipe_read_fd = open(fifo_name_full, open_mode_user);
        if(pipe_read_fd == -1)
        {
              printf("read state open failed\n");  
              sleep(100);
        } 
        printf("open read pipe:%d,%d\n", pipe_read_fd, getpid());
    }
      
}  



int write_state(CPUArchState *env, target_ulong address, int prot)  
{  
    CPUSHSTATE cpustate;  
    storeCPUShState(&cpustate, env);
    int res = 0;
    int type = 1;  
    if(pipe_write_fd != -1)  
    {  
        int type = 1;
        res = write(pipe_write_fd, &type, sizeof(int));  
        if(res == -1)  
        {  
            fprintf(stderr, "Write type on pipe\n"); 
            printf("write type on pipe error\n"); sleep(1000);
            exit(EXIT_FAILURE);  
        } 
        res = write(pipe_write_fd, &cpustate, sizeof(CPUSHSTATE));  
        if(res == -1)  
        {  
            printf("Write error on pipe\n");sleep(1000);
            exit(EXIT_FAILURE);  
        }
        res = write(pipe_write_fd, &address, sizeof(target_ulong)); 
        if(res == -1)  
        {  
            printf("Write error on pipe\n");sleep(1000);
            exit(EXIT_FAILURE);  
        } 
        res = write(pipe_write_fd, &prot, sizeof(int)); 
        if(res == -1)  
        {  
            printf("Write error on pipe\n");sleep(1000);
            exit(EXIT_FAILURE);  
        }   
        //printf("write state ok %x,addr:%x\n",  cpustate.PC, address);
    }  
    else{
        printf("write error\n");
        sleep(1000);
        exit(EXIT_FAILURE);  
    }
  
    return 1;  
} 


/*
type 
0 addr
1 state
2 cmd

*/




int write_addr(MISSING_PAGE *page)  
{  
    int res = 0;
    if(pipe_write_fd != -1)  
    {  
        int type = 0;
        res = write(pipe_write_fd, &type, sizeof(int));
        if(res == -1){  
            fprintf(stderr, "Write type error:%x\n", page->addr);  
            perror("reason"); sleep(1000);
            exit(EXIT_FAILURE);  
        }  
        res = write(pipe_write_fd, page, sizeof(MISSING_PAGE));  
        if(res == -1){  
            fprintf(stderr, "Write addr error:%x\n", page->addr);  sleep(1000);
            exit(EXIT_FAILURE);  
        }  
        printf("write addr ok:%lx, prot:%d\n", page->addr, page->prot);   
    }  
    else { 
        printf("write addr pipe not open error\n");sleep(1000);
        exit(EXIT_FAILURE);  
    }

    return 1;  
}  


int read_state(target_ulong pc, CPUArchState *env)  
{  
    int res = 0;   
    CPUSHSTATE cpustate;
    CPUArchState env_read;
    if(pipe_read_fd != -1)  
    {  
        //printf("before read state:%d\n", pipe_read_fd);
        res = read_content(pipe_read_fd, &cpustate, sizeof(cpustate));  
        if(res == -1)  
        {  
            fprintf(stderr, "Write error on pipe\n");  sleep(1000);
            exit(EXIT_FAILURE);  
        }
        /*
        if(cpustate.PC != pc + 4){ //check
            //res = read(pipe_read_fd, &cpustate, sizeof(cpustate)); 
            printf("read state error:%x,%x\n", cpustate.PC, pc);
            //sleep(100);
        }
        */
        loadCPUShState(&cpustate, env);
#ifdef  TARGET_MIPS
        //printf("read state ok:%lx\n", env->active_tc.PC);
#endif
    }  
    else {
        printf("read pipe not open\n");sleep(1000);
        exit(EXIT_FAILURE);  
    }
    return 1;
} 


//zyw return 0 failed, 1 success
int read_addr(target_ulong ori_addr, uintptr_t *addr)  
{      
    int res = 0;  
    target_ulong low_three= 0;
    target_ulong low_bits = 0;
    target_ulong high_bits = 0;
    target_ulong ori_low_three = ori_addr & 0xfff;
    if(pipe_read_fd != -1)  
    {    
        *addr = 0;
        /*
        do
        {
            res = read_content(pipe_read_fd, addr, sizeof(uintptr_t));
            low_three = (*addr) & 0xfff;
            low_bits = (*addr) & 0xffffffff;
            high_bits = ((*addr)>>32) & 0xffffffff;
            printf("??????? read not right\n");
        }
        while(low_three != ori_low_three || low_bits == 0 || high_bits!=0);
        */
        res = read_content(pipe_read_fd, addr, sizeof(uintptr_t));
        if(res == -1)  
        {  
            fprintf(stderr, "read addr error on pipe\n");  sleep(1000);
            exit(EXIT_FAILURE);  
        }
        //printf("read addr:%lx, %x\n", *addr, res); 

    }  
    else {
        printf("read pipe not open\n");
        sleep(1000);
        exit(EXIT_FAILURE);  
    }
    return 1;
} 


/*
void close_all_pipe()
{
    printf("######### close all pipe\n");
    close(pipe_read_fd);
    close(pipe_write_fd);
    pipe_read_fd = -1;
    pipe_write_fd = -1;
}

void open_all_pipe()
{
    printf("######### open all pipe\n");
    open_write_pipe();
    open_read_pipe();
}
*/

#ifdef STORE_PAGE_FUNC
int find_phys_addr(int virt_addr, int * phys_addr)
{   
    for(int i=0; i<addr_pair_index; i++)
    {
        if(virt_addr == addr_pair[i].virt_page)
        {
            *phys_addr = addr_pair[i].phys_page;
            return i;
        }
    }
    return -1;
}
#endif

#ifdef NEW_MAPPING
void handle_store(CPUArchState *env, target_ulong cur_guest_pc, target_ulong page_addr)
{

    
    //zyw
    //printf("do_store_exclusive:%x\n", page_addr); //every time handle a store, it takes time.
    //gettimeofday(&handle_addr_start, NULL);
    store_count += 1;
    int store_res = if_write_page_store(page_addr);
    //gettimeofday(&handle_addr_end, NULL);
    //handle_addr_total += (double)handle_addr_end.tv_sec - handle_addr_start.tv_sec + (handle_addr_end.tv_usec - handle_addr_start.tv_usec)/1000000.0;
    if(!store_res)
    {
        //int map_res = if_vaddr_write_mapped(page_addr);
        //if(!map_res)
        //{
            //printf("cur pc:%x, %x, %x\n", cur_guest_pc, env->active_tc.PC, page_addr);
            gettimeofday(&handle_addr_start, NULL);
            MISSING_PAGE page;
            page.prot = 1;
            page.addr = page_addr;
            page.mmu_idx = 2;

            cross_process_mutex_init(); //zyw
            pthread_mutex_lock(p_mutex_shared);

#ifdef TARGET_MIPS
            env->active_tc.PC = cur_guest_pc;
#elif defined(TARGET_ARM)
            env->regs[15] = cur_guest_pc;
#endif
            write_state(env, page_addr, 1);
            uintptr_t phys_addr;
            read_addr(page_addr, &phys_addr);
            if(phys_addr == 0)
            {
                printf("handle addr error:%x\n",page.addr);
                pthread_mutex_unlock(p_mutex_shared);
                cross_shamem_disconn(); //zyw 
                normal_exit(0);
            }
            target_mmap(page_addr & 0Xfffff000, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, phys_addr & 0Xfffff000);
            //add_write_mapped_vaddr(page_addr);
#ifdef STORE_PAGE_FUNC
            addr_pair[addr_pair_index].virt_page = page_addr;
            addr_pair[addr_pair_index].phys_page = phys_addr;
            addr_pair_index++;
#endif

            pthread_mutex_unlock(p_mutex_shared);
            cross_shamem_disconn(); //zyw 

            gettimeofday(&handle_addr_end, NULL);
            double handle_addr_time  =  (double)handle_addr_end.tv_sec - handle_addr_start.tv_sec + (handle_addr_end.tv_usec - handle_addr_start.tv_usec)/1000000.0;
            //printf("write map time:%f, addr:%lx,%lx\n", handle_addr_time, page_addr, phys_addr);
            handle_addr_total += handle_addr_time;
        //}
//zyw part of lightweight snapshot 
        gettimeofday(&store_page_start, NULL);
#ifdef STORE_PAGE_FUNC
        store_page(page_addr,1);
        int phys_page;
        int index = find_phys_addr(page_addr, &phys_page);
        if(index == -1)
        {
            printf("could find_phys_addr:%x\n", page_addr);
            sleep(1000);
        }
        add_store_write_page(page_addr);
#ifdef SNAPSHOT_SYNC
        add_physical_page(phys_page);
#endif
#endif
        gettimeofday(&store_page_end, NULL);
        store_page_total += (double)store_page_end.tv_sec - store_page_start.tv_sec + (store_page_end.tv_usec - store_page_start.tv_usec)/1000000.0;
    }
}

#else

void handle_store(CPUArchState *env, target_ulong pc, target_ulong page_addr)
{

#ifdef LMBENCH
    return;
#endif
    
    //zyw
    //printf("do_store_exclusive:%x\n", page_addr); //every time handle a store, it takes time.
    //gettimeofday(&handle_addr_start, NULL);
    store_count += 1;
    int store_res = if_write_page_store(page_addr);
    //gettimeofday(&handle_addr_end, NULL);
    //handle_addr_total += (double)handle_addr_end.tv_sec - handle_addr_start.tv_sec + (handle_addr_end.tv_usec - handle_addr_start.tv_usec)/1000000.0;
    if(!store_res)
    {
        //int map_res = if_vaddr_write_mapped(page_addr);
        //if(!map_res)
        //{
            gettimeofday(&handle_addr_start, NULL);
            MISSING_PAGE page;
            int phys_page;;
            page.prot = 1;
            page.addr = page_addr;
            page.mmu_idx = 2;

            cross_process_mutex_init(); //zyw
            pthread_mutex_lock(p_mutex_shared);

            write_addr(&page);
            read_addr(page.addr, &phys_page);
            if(phys_page == 0)
            {
                printf("handle_store addr error:%x\n",page.addr);
                pthread_mutex_unlock(p_mutex_shared);
                cross_shamem_disconn(); //zyw 
                normal_exit(0);
            }
            int file_offset = phys_page & 0xfffff000;
            uintptr_t res  = target_mmap(page_addr, 1024*4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,  mem_file_fd, file_offset);
            assert(res>0);
            //add_write_mapped_vaddr(page_addr);
#ifdef STORE_PAGE_FUNC
            addr_pair[addr_pair_index].virt_page = page_addr;
            addr_pair[addr_pair_index].phys_page = file_offset;
            addr_pair_index++;
#endif

            pthread_mutex_unlock(p_mutex_shared);
            cross_shamem_disconn(); //zyw 

            gettimeofday(&handle_addr_end, NULL);
            double handle_addr_time  =  (double)handle_addr_end.tv_sec - handle_addr_start.tv_sec + (handle_addr_end.tv_usec - handle_addr_start.tv_usec)/1000000.0;
            //printf("handle store write map time:%f, addr:%lx,%lx\n", handle_addr_time, page_addr, file_offset);
            handle_addr_total += handle_addr_time;
        //}
//zyw part of lightweight snapshot 
        gettimeofday(&store_page_start, NULL);
#ifdef STORE_PAGE_FUNC
        store_page(page_addr,1);
        int phys_page;
        int index = find_phys_addr(page_addr, &phys_page);
        if(index == -1)
        {
            printf("could find_phys_addr:%x\n", page_addr);
            sleep(1000);
        }
        add_store_write_page(page_addr);
#ifdef SNAPSHOT_SYNC
        add_physical_page(phys_page);
#endif
#endif
        gettimeofday(&store_page_end, NULL);
        store_page_total += (double)store_page_end.tv_sec - store_page_start.tv_sec + (store_page_end.tv_usec - store_page_start.tv_usec)/1000000.0;
    }
}
#endif

#ifdef STORE_PAGE_FUNC
typedef struct STORE_PAGE{
    uintptr_t prev_addr;
    uintptr_t curr_addr;
    int flag;
    struct STORE_PAGE * page;
} STORE_PAGE;

extern int afl_fork_child;
void store_page(uintptr_t guest_addr, int flag)
{
    //only for tew632httpd
    /*
    if(parent_pid!=getpid() && afl_fork_child)
    {
        printf("store after fork\n");
        normal_exit(3333);
    }
    */
    int page_exist = 0;
    int index = (guest_addr >> 12) & 0xfff;
    uintptr_t *pt = snapshot_shmem_start + index * 8;
    STORE_PAGE *tmp_p = *pt;
    STORE_PAGE *last_p;
    uintptr_t host_addr = g2h(guest_addr);
    if(tmp_p == NULL)
    {
        STORE_PAGE * page = (STORE_PAGE *)snapshot_shmem_pt;
        snapshot_shmem_pt += sizeof(STORE_PAGE);
        void * dst = snapshot_shmem_pt;
        snapshot_shmem_pt += 0x1000;
        memset(dst, 0, 0x1000);
        void * src = host_addr;
        memcpy(dst, src, 0x1000); 
        //printf("index1:%x, copy finished from %lx(%lx) to %lx, guest_base:%lx\n", index, src, guest_addr, dst, guest_base);
        page->prev_addr = src;
        page->curr_addr = dst;
        page->flag = flag;
        page->page = NULL;  
        *pt = page;
        return;
    }
    while(tmp_p!= NULL)
    {
        last_p = tmp_p;
        tmp_p = tmp_p->page;
    }
    STORE_PAGE * page = (STORE_PAGE *)snapshot_shmem_pt;
    snapshot_shmem_pt += sizeof(STORE_PAGE);
    void * dst = (STORE_PAGE *)snapshot_shmem_pt;
    snapshot_shmem_pt += 0x1000;
    memset(dst, 0, 0x1000);
    void * src = host_addr;
    memcpy(dst, src, 0x1000); 
    //printf("index2:%x, copy finished from %lx to %lx, guest_base:%lx\n", index, src, dst, guest_base);
    page->prev_addr = src;
    page->curr_addr = dst;
    page->flag = flag;
    page->page = NULL;  
    last_p->page = page;

}


//remember not to free page 
void restore_page_exception()
{
    //printf("restore_page start\n");
    for(int i=0; i<0x1000; i++)
    {
        uintptr_t * pt = snapshot_shmem_start + i * 8;
        //printf("rpage addr:%lx,%lx,%lx\n", shmem_start, pt, *(uintptr_t* )shmem_start);   
        STORE_PAGE *tmp_p = *pt; 
        STORE_PAGE *last_p = NULL;
        while(tmp_p){
            //printf("page addr:%lx\n",tmp_p);
            uintptr_t dst = tmp_p-> prev_addr;
            uintptr_t src = tmp_p-> curr_addr;
            int flag = tmp_p->flag;
            printf("restore:%lx,%lx\n", src,dst);
            memcpy(dst, src, 0x1000);
            if(flag == 1)
            {
                if(last_p!=NULL)
                {
                    last_p->page = NULL;
                }
                else
                {
                    *pt = NULL;
                }
                
            }
            last_p = tmp_p; 
            tmp_p = tmp_p->page;
        }
    }
    //shmem_pt = snapshot_shmem_start + 8 * 0x1000;
    //printf("restore_page end\n");
}

//remember not to free page 
void restore_page(void)
{
    //printf("restore_page start\n");
    for(int i=0; i<0x1000; i++)
    {
        uintptr_t * pt = snapshot_shmem_start + i * 8;
        //printf("rpage addr:%lx,%lx,%lx\n", shmem_start, pt, *(uintptr_t* )shmem_start);   
        STORE_PAGE *tmp_p = *pt; 
        STORE_PAGE *last_p = NULL;
        while(tmp_p){
            //printf("page addr:%lx\n",tmp_p);
            uintptr_t dst = tmp_p-> prev_addr;
            uintptr_t src = tmp_p-> curr_addr;
            int flag = tmp_p->flag;
            memcpy(dst, src, 0x1000);
            if(flag == 1)
            {
                if(last_p!=NULL)
                {
                    last_p->page = NULL;
                }
                else
                {
                    *pt = NULL;
                }
                
            }
            last_p = tmp_p; 
            tmp_p = tmp_p->page;
        }
    }
    //shmem_pt = snapshot_shmem_start + 8 * 0x1000;
    //printf("restore_page end\n");
}
#endif //STORE_PAGE_FUNC

//snapshot consistence
#ifdef SNAPSHOT_SYNC
void add_physical_page(int phys_addr)
{
    int value = phys_addr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    assert(phys_addr_stored_bitmap);
    phys_addr_stored_bitmap[index] |=  1 << position;
}


//if not exist,add it and return -1; if exist, return index;
int if_physical_exist(int phys_addr) //phys_addr <= 0xfffff000
{   
    int value = phys_addr >> 12;
    int index = value >> 3;
    int position = value & 0x07;
    assert(phys_addr_stored_bitmap);
    return (phys_addr_stored_bitmap[index] & (1 << position)) !=0; 

}
#endif //SNAPSHOT_SYNC

#endif //MEM_MAPPING

