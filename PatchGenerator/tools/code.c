#include "ebpf_helper.h"

/*
a5de:	0258      	lsls	r0, r3, #9
bpkt: here
*/
uint64_t filter(stack_frame *frame) {
    uint32_t target = frame->r0;
    // uint32_t mem_size = *(uint32_t *) (0x20000800);
    uint32_t mem_size = *(uint32_t *) (frame->r1);
    uint32_t op = 0;
    uint32_t ret_code = 0;
    if (target >= mem_size) {
        // lr: csw.Status = CSW_FAILED;
        // intercept
        //frame->lr = 0x977c;
        op = 1;
        ret_code = 0x977c;
    }
    return set_return(op, ret_code);
}