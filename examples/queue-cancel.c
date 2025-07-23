#include "uv_coro.h"

#define FIB_UNTIL 25

void signal_handler(void_t args) {
    if (catching("sig_int")) {
        printf("Signal received!\n");
        fprintf(stderr, "Calculation cancelled in coroutine: #%d\n", coro_active_id());
    }
}

long fib_(long t) {
    if (t == 0 || t == 1)
        return 1;
    else
        return fib_(t - 1) + fib_(t - 2);
}

void_t fib(params_t req) {
    defer_recover(signal_handler, nullptr);
    int n = req->integer;
    if (random() % 2)
        sleepfor(1000);
    else
        sleepfor(3000);

    long fib = fib_(n);
    fprintf(stderr, "%dth fibonacci is %lu in thrd: #%d\033[0K\n", n, fib, coro_thrd_id());

    return casting(fib);
}

void after_fib(int status, rid_t id) {
    fprintf(stderr, "Done calculating %dth fibonacci, result: %d\n", status, result_for(id).integer);
}

int uv_main(int argc, char **argv) {
    rid_t data[FIB_UNTIL];
    int i;

    defer_recover(signal_handler, nullptr);
    waitgroup_t wg = waitgroup_ex(FIB_UNTIL);
    for (i = 0; i < FIB_UNTIL; i++) {
        data[i] = go(fib, 1, casting(i));
    }
    waitresult_t wgr = waitfor(wg);

    if ($size(wgr) == FIB_UNTIL)
        for (i = 0; i < FIB_UNTIL; i++) {
            after_fib(i, data[i]);
        }

    return 0;
}
