#include "assertions.h"

/* converted from https://en.cppreference.com/w/cpp/thread/future.html */

void_t task(args_t req) {
	ASSERT_WORKER(($size(req) == 1));
	sleep(1);
	return $(casting(req->integer));
}

void_t task_after(vectors_t req) {
	ASSERT_WORKER(($size(req) == 1));
	ASSERT_WORKER((7 <= req->integer));
}

void_t task_after2(vectors_t req) {
	ASSERT_WORKER(($size(req) == 1));
	ASSERT_WORKER((9 == req->integer));
}

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) == 3));
    delay(args[0].u_int);
	ASSERT_WORKER(is_str_eq("uv_queue_work", args[1].char_ptr));
    return args[2].char_ptr;
}

TEST(queue_work) {
	arrays_t arr = arrays(), arr2 = arrays();
	rid_t res = go(worker_misc, 3, 2000, "uv_queue_work", "finish");

	future f1 = queue_work(task, 1, casting(7));
	$append(arr, f1);
	ASSERT_FALSE(result_is_ready(res));
	ASSERT_TRUE(is_future(f1));
	ASSERT_TRUE(queue_is_valid(f1));
	$append(arr2, queue_then(arr[0].object, (queue_cb)task_after));

	future f2 = queue_work(task, 1, casting(8));
	ASSERT_FALSE(result_is_ready(res));
	$append(arr, f2);
	ASSERT_TRUE(queue_is_valid(f2));
	$append(arr2, queue_then(f2, (queue_cb)task_after));

	future f3 = queue_work(task, 1, casting(9));
	ASSERT_TRUE(queue_is_valid(f3));
	promise *p = queue_then(f3, (queue_cb)task_after2);
	ASSERT_TRUE(is_promise(p));
	$append(arr, f3);
	$append(arr2, p);

	ASSERT_FALSE(result_is_ready(res));
	ASSERT_TRUE($size(arr) == 3);
	ASSERT_EQ(7, queue_get(arr2[0].object).integer);
	ASSERT_FALSE(queue_is_valid(f1));
	queue_wait(arr);
	ASSERT_TRUE($size(arr) == 0);
    ASSERT_TRUE(result_is_ready(res));

	ASSERT_FALSE(queue_is_valid(f2));
	ASSERT_FALSE(queue_is_valid(f3));

	ASSERT_EQ(8, queue_get(arr2[1].object).integer);
	ASSERT_EQ(9, queue_get(p).integer);

    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(queue_work);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}