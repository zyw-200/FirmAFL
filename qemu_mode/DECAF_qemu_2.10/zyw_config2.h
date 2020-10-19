#define CAL_TIME
// #define CAL_TIME_ext //frequent opreration like code generation and page storing 

int program_start = 0;
int first_or_new_pgd = 1; //0 first 1 new; // 0 tplink httpd
//#define multiple_process //Trendnet jjhttpd Netgear lighttpd

int fork_times = 0;
double tlb_time_interval = 0.0; //tlb
double tlb_time_interval_total = 0.0; //tlb
double time_interval = 0.0; //syscall
double time_interval_total = 0.0; //syscall
int syscall_count = 0;
struct timeval loop_begin;
struct timeval loop_end;
struct timeval restore_begin;
struct timeval restore_end;
struct timeval store_begin;
struct timeval store_end;
double store_time = 0.0;
struct timeval save_snapshot_start;
struct timeval save_snapshot_end;
struct timeval load_snapshot_start;
struct timeval load_snapshot_end;
struct timeval tlb_handle_begin_new;
struct timeval tlb_handle_begin;
struct timeval tlb_handle_end;
struct timeval syscall_begin;
struct timeval syscall_end;
struct timeval syscall_codegen_begin;
struct timeval syscall_codegen_end;
double syscall_codegen_time = 0.0;
double total_syscall_codegen_time = 0.0;
int syscall_codegen_count = 0;
struct timeval user_codegen_begin;
struct timeval user_codegen_end;
double user_codegen_time = 0.0;
int user_codegen_count = 0;

int into_tlb_handle = 0;


int into_sys[50];
int curr_pc[50];
int syscall_index = -1;

void sysinfo_push(int syscall_num, int pc)
{
	syscall_index++;
	into_sys[syscall_index] = syscall_num;
	curr_pc[syscall_index] = pc;

}

void sysinfo_pop()
{
	syscall_index--;
}

int get_current_sysnum()
{	
	if(syscall_index==-1)
	{
		return 0;
	}
	else
	{
		return into_sys[syscall_index];
	}
	
}

int get_current_pc()
{	
	if(syscall_index==-1)
	{
		return 0;
	}
	else
	{
		return curr_pc[syscall_index];
	}
	
}

void truncate_sysinfo()
{
	syscall_index = -1;
}


//NEW_MAPPING
int into_normal_execution = 0;
int normal_execution_tb = 0;
int tlb_match = 0;


int print_debug = 0;
int print_pc_times = 0;
int print_loop_times = 1;
int print_loop_count = 0;


int target_pgd;
int afl_user_fork = 0;


int slow_print = 0;
int finish_recv = 0;
int global_into_syscall;
int into_syscall = 0;
int before_syscall_stack = 0;
int curr_state_pc = 0;
int last_syscall = 0;
