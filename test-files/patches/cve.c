
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

// AMNESIA33_cve_2020_17445
uint64_t filter(stack_frame *frame) {
    uint32_t opt_ptr = (uint32_t)(frame->r2);
    opt_ptr += (uint32_t)(2u);
    uint8_t *destopt = (uint8_t *)(frame->r0);
    uint8_t *option = (destopt + 2);
    uint8_t len = (uint8_t)(((*(destopt + 1) + 1) << 3) - 2);
    uint8_t optlen = 0;
    uint32_t op = 0;
    uint32_t ret_code = 0;

    while (len) {
        optlen = (uint8_t)(*(option + 1) + 2);
        if (opt_ptr + optlen <= opt_ptr || option + optlen <= option || len - optlen >= len) {
            ret_code = -1;
            break;
        }
        opt_ptr += optlen;
        option += optlen;
        len = (uint8_t)(len - optlen);
    }

    if (ret_code != 0) {
        // intercept
        op = 1;
    }
    return set_return(op, ret_code);
}