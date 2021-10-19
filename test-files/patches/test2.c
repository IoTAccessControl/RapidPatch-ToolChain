
typedef unsigned long long uint64_t;

typedef struct frame_ctx {
	int r0;
	int r1;
	int r2;
} frame_ctx;

uint64_t filter(frame_ctx *ctx) {
	int s = ctx->r0;
	int t = ctx->r1;
	ctx->r2 = 5;
	return s * t + s + t;
}
