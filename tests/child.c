#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#if defined(_WIN32) || defined(_WIN64)
#include "compat/unistd.h"
#else
#include <unistd.h>
#endif

#include <uv.h>

int std_out(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    int r = vfprintf(stdout, msg, ap);
    va_end(ap);
    if (r)
        fflush(stdout);

    return r;
}

char *std_in(size_t count) {
    char *buf = calloc(1, count + 1);
    if (buf && read(STDIN_FILENO, buf, count) > 0)
        return buf;

    if (buf)
        free(buf);

    return NULL;
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "\nThis is stderr\n");
    uv_sleep(25);

    std_out("This is stdout");
    uv_sleep(25);

    std_out("\tSleeping...");
    uv_sleep(500);

    std_out("`%s` argument received", argv[1]);
    uv_sleep(25);

    fprintf(stderr, "Exiting\n");

    return 0;
}
