
typedef unsigned long long uint64_t;

typedef struct frame_ctx {
	int r0;
	int r1;
	int r2;
} frame_ctx;

uint64_t filter(frame_ctx *ctx) {
	int s = ctx->r0;
	int t = ctx->r1;
	int n = 0;
	for (int i = 0; i < t; i++) {
		s += i * t;
		n += i;
	}

	for (int i = n; i > 0; i--) {
		s += i;
	}
	return s;
}
