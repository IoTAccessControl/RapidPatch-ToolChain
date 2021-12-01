#include "ebpf_helper.h"

// PACKED_STRUCT_DEF pico_ipv6_exthdr {
//     uint8_t nxthdr;

//     PACKED_UNION_DEF ipv6_ext_u {
//         PEDANTIC_STRUCT_DEF hopbyhop_s {
//             uint8_t len;
//         } hopbyhop;

//         PEDANTIC_STRUCT_DEF destopt_s {
//             uint8_t len;
//         } destopt;

//         PEDANTIC_STRUCT_DEF routing_s {
//             uint8_t len;
//             uint8_t routtype;
//             uint8_t segleft;
//         } routing;

//         PEDANTIC_STRUCT_DEF fragmentation_s {
//             uint8_t res;
//             uint8_t om[2];
//             uint8_t id[4];
//         } frag;
//     } ext;
// };

// AMNESIA33_cve_2020_17445
uint64_t filter(stack_frame *frame) {
    uint32_t opt_ptr = (uint32_t)(frame->r2);
    opt_ptr += (uint32_t)(2u);
    uint8_t *destopt = (uint8_t *)(frame->r0);
    uint8_t *option = (destopt + 2);
    uint8_t len = (uint8_t)(((*(destopt + 1) + 1) << 3) - 2);
    uint8_t optlen = 0;
    uint32_t op = 0;
    uint32_t ret_code = 555;

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