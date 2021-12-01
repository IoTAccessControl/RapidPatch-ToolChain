#include "ebpf_helper.h"

typedef unsigned long long uint64_t;

typedef struct frame_ctx {
	int r0;
	int r1;
	int r2;
} frame_ctx;

uint64_t filter(frame_ctx *ctx) {
	int op = 1;
	int ret_code = 555;
	return set_return(op, ret_code);
}
