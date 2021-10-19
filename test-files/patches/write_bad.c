#include "ebpf_helper.h"

uint64_t filter(stack_frame *ctx) {
    uint32_t op = FILTER_PASS;
    uint32_t ret_code = 0;

    uint32_t ptr = ctx->r0;
    (int *) (ptr) = 5;
    return set_return();
}

