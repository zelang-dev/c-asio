#include "asio.h"

void _on_exit(int64_t exit_status, int term_signal) {
    fprintf(stderr, "\nProcess exited with status %" PRId64 ", signal %d\n",
            exit_status, term_signal);
}

int uv_main(int argc, char **argv) {
    spawn_t child = spawn("mkdir", "test-dir", nullptr);
    if (!spawn_atexit(child, _on_exit))
        fprintf(stderr, "\nLaunched process with ID %d\n", spawn_pid(child));

    return coro_err_code();
}
