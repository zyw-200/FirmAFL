
typedef struct 
{
  double handle_state_time;
  double handle_addr_time;
  double handle_syscall_time;
  double store_page_time;
  double restore_page_time;
  int user_syscall_count;
  int store_count;
} USER_MODE_TIME;


//#define NO_MAPPING_AND_FUZZ

//#define LMBENCH

#ifdef LMBENCH

#define MAPPING_WITHOUT_FUZZ
#define MEM_MAPPING
#define PRE_MAPPING 

#else


//#define NO_MAPPING_AND_FUZZ
//#define MAPPING_WITHOUT_FUZZ
#define MEM_MAPPING
#define NEW_MAPPING
#define SNAPSHOT_SYNC
#define PRE_MAPPING //comment out if choose NEW_MAPPING ; only for mips
#define STORE_PAGE_FUNC
//#define PADDR_MAP_CHECK
#define FEED_INPUT //FEED_ENV or FEED_HTTP
#define MAX_LEN 3000



#endif

