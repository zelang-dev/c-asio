#include "assertions.h"

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) == 2));
    sleepfor(args[0].u_int);
    ASSERT_WORKER(is_str_in("stream_write, stream_read", args[1].char_ptr));
    return args[1].char_ptr;
}

TEST(stream_read) {
    rid_t res = go(worker_misc, 2, 1000, "stream_read");
    pipepair_t *pair = pipepair_create(false);
    ASSERT_TRUE(is_pipepair(pair));
    ASSERT_EQ(0, stream_write(pair->writer, "ABCDE"));
    ASSERT_FALSE(result_is_ready(res));
    ASSERT_STR("ABCDE", stream_read_once(pair->reader));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "stream_read");

    return 0;
}

TEST(stream_write) {
    rid_t res = go(worker_misc, 2, 600, "stream_write");
    tty_out_t *tty = tty_out();
    ASSERT_TRUE(is_tty(tty));
    ASSERT_EQ(0, stream_write(tty->writer, "hello world\n"));
    ASSERT_FALSE(result_is_ready(res));
    while (!result_is_ready(res)) {
        yield();
    }

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "stream_write");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(stream_read);
    EXEC_TEST(stream_write);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}