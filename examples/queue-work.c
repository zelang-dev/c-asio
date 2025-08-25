#include "asio.h"

#define FIB_UNTIL 25

long fib_(long t) {
    if (t == 0 || t == 1)
        return 1;
    else
        return fib_(t-1) + fib_(t-2);
}

void_t fib(args_t req) {
	int n = req->integer;
	if (random() % 2)
        sleep(1);
    else
        sleep(3);
	long fib = fib_(n);
	fprintf(stderr, "%dth fibonacci is %lu"CLR_LN, n, fib);

	return $$(n, fib);
}

void after_fib(vectors_t req) {
	fprintf(stderr, "Done calculating %dth fibonacci, result: %d"CLR_LN,
		req[0].integer, req[1].integer);
}

int uv_main(int argc, char **argv) {
	arrays_t arr = arrays();
	int i;

	yield();
	for (i = 0; i < FIB_UNTIL; i++) {
		future req = queue_work(fib, 1, casting(i));
		$append(arr, req);
		queue_then(req, after_fib);
	}

	queue_wait(arr);

	return 0;
}
