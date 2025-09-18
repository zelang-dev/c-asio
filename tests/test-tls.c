#include "assertions.h"

void_t worker_client(params_t args) {
	uv_stream_t *server = nullptr;
	spawn_t child = nullptr;
	ASSERT_WORKER(($size(args) == 4));
	delay(args[0].u_int);

	ASSERT_WORKER(is_str_eq("tls_client", args[1].char_ptr));
	ASSERT_WORKER(is_empty(server = stream_secure("127.0.0.1", "localhost", 7000)));
	ASSERT_WORKER(is_process(child = spawn("./client",
		nullptr, spawn_opts(nullptr, nullptr, UV_PROCESS_DETACHED, 0, 0, 0))));

	ASSERT_WORKER((spawn_detach(child) == 0));
	delay(6000);

	return args[2].char_ptr;
}

void_t worker_connected(uv_stream_t *socket) {
    ASSERT_WORKER((stream_write(socket, "world") == 5));
    ASSERT_WORKER(is_str_eq("hello", stream_read(socket)));

    return 0;
}

TEST(stream_listen) {
    uv_stream_t *client, *socket;
	ASSERT_TRUE(is_tls(socket = stream_bind("tls://127.0.0.1:7000", 0)));
	ASSERT_FALSE(is_tcp(socket));

	rid_t res = go(worker_client, 4, 500, "tls_client", "finish", socket);
	ASSERT_FALSE(is_tls(client = stream_listen(socket, 128)));
    ASSERT_FALSE(is_tcp(client));

	if (is_tls(client)) {
		stream_handler((stream_cb)worker_connected, client);
	}

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