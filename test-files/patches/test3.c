typedef unsigned long long uint64_t;

typedef struct frame_ctx {
	int r0;
	int r1;
	int r2;
} frame_ctx;

uint64_t str_hash(frame_ctx *ctx) {
    char *str = ctx->r0;
    int n = ctx->r1;
    uint64_t hash = 0;
    #pragma nounroll
    for (int i = 0; i < n; i++) {
        hash += str[i];
    }
    return hash;
}