
#include "asio.h"

int uv_main(int argc, char **argv) {
    printf("Now quitting.\n");
    yield();

    return coro_err_code();
}
