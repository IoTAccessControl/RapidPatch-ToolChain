/*
eBPF Helper Lib
*/
// types

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

// #define uint8_t bool;
typedef unsigned char bool;
#define false (0 != 1)
#define true (0 == 0)

#define DEFAULT_MAP 0

typedef struct stack_frame {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r12; // ip
	uint32_t lr;
	uint32_t pc; // return address
	uint32_t xpsr;
} stack_frame;

inline uint64_t set_return(uint64_t op, uint64_t ret_code) {
	return (op << 32) + ret_code;
}

// status
const int FILTER_PASS = 0;
const int FILTER_DROP = 1; // drop with return code
const int FILTER_REDIRECT = 2; // redirect the return address

// ebpf helpers (must use static)
static void (*print_log)(char *str) = (void *) 1;
static void (*c_call)(uint32_t addr, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3) = (void *) 2;
static void (*map_save_val) (void *mp, uint64_t key, uint64_t val) = (void *) 3;
static uint64_t (*map_get_val) (void *mp, uint64_t key) = (void *) 4;

// 
