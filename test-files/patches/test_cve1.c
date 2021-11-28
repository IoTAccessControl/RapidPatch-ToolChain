#include "ebpf_helper.h"

#define EINVAL 22
#define MQTT_LENGTH_CONTINUATION_BIT 0x80
#define MQTT_LENGTH_SHIFT 7
#define MQTT_LENGTH_VALUE_MASK 0x7F
#define MQTT_MAX_PAYLOAD_SIZE 0x0FFFFFFF

struct buf_ctx {
	unsigned char *cur;
    unsigned char *end;
};

uint64_t filter(stack_frame *frame) {
    struct buf_ctx *buf = (struct buf_ctx *)(frame->r0);
    uint32_t op = 0;
    uint32_t ret_code = 0;
    unsigned char end_index = 0;
    
    for (int i = 0; i < 5; i++) {
        if (((*(buf->cur + i)) & MQTT_LENGTH_CONTINUATION_BIT) == 0) {
            end_index = i;
            break;
        }
    }
    if (end_index >= 4) {
        op = 1;
        ret_code = -EINVAL;
        return set_return(op, ret_code);
    }
    
    // length limit validation
    uint32_t length = 0U;
    uint32_t shift = 0U;
    for (int i = 0; i <= end_index; ++i) {
		length += ((uint32_t)*(buf->cur + i) & MQTT_LENGTH_VALUE_MASK)
								<< shift;
		shift += MQTT_LENGTH_SHIFT;
    }

    if (length > MQTT_MAX_PAYLOAD_SIZE) {
        op = 1;
        ret_code = -EINVAL;
    }

    return set_return(op, ret_code);
}