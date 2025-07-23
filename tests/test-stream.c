#include "assertions.h"

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) == 3));
    delay(args[0].u_int);
    ASSERT_WORKER(is_str_in("stream_write, stream_read_once", args[1].char_ptr));
    return args[2].char_ptr;
}

TEST(stream_read) {
    rid_t res = go(worker_misc, 3, 1000, "stream_read_once", "finish");
    pipepair_t *pair = pipepair_create(false);
    ASSERT_TRUE(is_pipepair(pair));
    ASSERT_EQ(0, stream_write(pair->writer, "ABCDE"));
    ASSERT_FALSE(result_is_ready(res));
    ASSERT_STR("ABCDE", stream_read_once(pair->reader));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(stream_write) {
    rid_t res = go(worker_misc, 3, 600, "stream_write", "finish");
    tty_out_t *tty = tty_out();
    ASSERT_TRUE(is_tty(tty));
    ASSERT_EQ(0, stream_write(tty->writer, "hello world\n"));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res)) {
        yield();
    }

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(stream_read);
#ifndef _WIN32
    EXEC_TEST(stream_write);
#endif

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}