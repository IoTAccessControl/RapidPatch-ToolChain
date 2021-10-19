
struct args {
    char *s;
    char *e;
    int len;
};

int filer(struct args *ag) {
    int fx = 0;
    for (int i = 0; i < ag->len; i++) {
        fx += ag->s[i] * ag->e[i];
    }
    if (fx > 10) {
        return 1;
    }
    return fx;
}

int main() {
    struct args ag = {"xxs12345", "bbs12345", 8};
    filer(&ag);
    return 0;
}