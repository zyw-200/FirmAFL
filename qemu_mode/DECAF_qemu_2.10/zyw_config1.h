//#define FULL

#ifdef FULL

#define DECAF
#define FUZZ
#define FORK_OR_NOT
//#define STORE_PAGE_FUNC
#define AUTO_FIND_FORK_PC //pc need change
#define MAX_LEN 3000
//#define DEBUG
//#define SHOW_SYSCALL_TRACE
#else 


#define DECAF
#define MEM_MAPPING
#define NEW_MAPPING
//if use new_mapping, cannot user pre_mapping

//#define DEBUG
#define AUTO_FIND_FORK_PC //pc need change
#define MAX_LEN 3000
//#define LMBENCH
#define STORE_PAGE_FUNC
#define SNAPSHOT_SYNC
#endif
