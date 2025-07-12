#include "uv_coro.h"

const char *command;

void run_command(const char *filename, int events, int status) {
    fprintf(stderr, "Change detected in %s: ", fs_watch_path());
    if (events & UV_RENAME)
        fprintf(stderr, "renamed");
    if (events & UV_CHANGE)
        fprintf(stderr, "changed");

    fprintf(stderr, " %s\n", filename ? filename : "");
    if (system(command))
        fprintf(stderr, " then executed: %s\n", command);
}

int uv_main(int argc, char **argv) {
    if (argc <= 2) {
        fprintf(stderr, "Usage: %s <command> <file1> [file2 ...]\n", argv[0]);
        yield();
        return 1;
    }

    command = argv[1];
    while (argc-- > 2) {
        fprintf(stderr, "Adding watch on %s\n", argv[argc]);
        fs_watch(argv[argc], run_command);
    }

    return ((int)sleepfor(100000) < 0 ? coro_err_code(): 0);
}
