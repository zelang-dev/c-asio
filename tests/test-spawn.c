#include "assertions.h"

static int output_count = 0;

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) == 3));
    sleepfor(args[0].u_int);
    ASSERT_WORKER(is_str_eq("uv_spawn", args[1].char_ptr));
    return args[2].char_ptr;
}

int _on_exit(int64_t exit_status, int term_signal) {
    ASSERT_EQ(0, exit_status);
    ASSERT_EQ(0, term_signal);
}

int _on_output(uv_stream_t *input, string buf, uv_stream_t *error) {
    output_count++;
    ASSERT_TRUE(is_str_in(buf, "This is stdout")
                || is_str_in(buf, "Sleeping...")
                || is_str_in(buf, "`test-dir` argument received"));
    ASSERT_FALSE(is_str_in(buf, "Exiting"));
}

TEST(spawn) {
    rid_t res = go(worker_misc, 3, 600, "uv_spawn", "finish");
    spawn_t child = spawn("./child", "test-dir",
                          spawn_opts(nullptr, nullptr, 0, 0, 0, 3,
                                     stdio_piperead(), stdio_pipewrite(), stdio_fd(2, UV_INHERIT_FD))
    );

    ASSERT_TRUE(is_process(child));
    ASSERT_EQ(0, spawn_atexit(child, (spawn_cb)_on_exit));
    ASSERT_EQ(0, spawn_handler(child, (spawn_handler_cb)_on_output));
    ASSERT_FALSE(result_is_ready(res));
    ASSERT_TRUE(spawn_pid(child) > 0);

    ASSERT_TRUE(is_spawning(child));
    while (is_spawning(child))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");
    ASSERT_EQ(3, output_count);

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(spawn);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}