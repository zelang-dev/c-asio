#include "assertions.h"

void_t worker_client(params_t args) {
    uv_stream_t *server = nullptr;
    ASSERT_WORKER(($size(args) == 3));

    delay(args[0].u_int);
    ASSERT_WORKER(is_str_eq("worker_client", args[1].char_ptr));

    ASSERT_WORKER(is_tls(server = stream_connect("https://127.0.0.1:8090")));
    ASSERT_WORKER(is_str_eq("world", stream_read_wait(server)));
    ASSERT_WORKER((stream_write(server, "hello") == 0));

    delay(args[0].u_int);
    return args[2].char_ptr;
}

void_t worker_connected(uv_stream_t *socket) {
    ASSERT_WORKER((stream_write(socket, "world") == 0));
    ASSERT_WORKER(is_str_eq("hello", stream_read_wait(socket)));

    return 0;
}

TEST(stream_listen) {
    uv_stream_t *client, *socket;
    rid_t res = go(worker_client, 3, 1000, "worker_client", "finish");

    ASSERT_TRUE(is_tls(socket = stream_bind("tls://0.0.0.0:8090", 0)));
    ASSERT_FALSE(is_tcp(socket));

    ASSERT_TRUE(is_tls(client = stream_listen(socket, 128)));
    ASSERT_FALSE(is_tcp(client));

    ASSERT_FALSE(result_is_ready(res));
    stream_handler((stream_cb)worker_connected, client);
    ASSERT_FALSE(result_is_ready(res));

    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(stream_listen);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}