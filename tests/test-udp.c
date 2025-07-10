#include "assertions.h"

void_t worker_client(params_t args) {
    uv_udp_t *client = nullptr;
    udp_packet_t *packets = nullptr;
    ASSERT_WORKER(($size(args) == 3));

    sleepfor(args[0].u_int);
    ASSERT_WORKER(is_str_eq("worker_client", args[1].char_ptr));

    ASSERT_WORKER(is_udp(client = udp_bind("127.0.0.1:7777", 0)));
    sleepfor(100);
    ASSERT_WORKER((udp_send(client, "hello", "udp://0.0.0.0:9999") == 0));
    ASSERT_WORKER(is_udp_packet(packets = udp_recv(client)));
    ASSERT_WORKER(is_str_eq("world", udp_get_message(packets)));

    return args[2].char_ptr;
}

void_t worker_connected(udp_packet_t *client) {
    ASSERT_WORKER(is_str_eq("hello", udp_get_message(client)));
    ASSERT_WORKER((udp_send_packet(client, "world") == 0));

    return 0;
}

TEST(udp_listen) {
    uv_udp_t *server;
    udp_packet_t *client;
    rid_t res = go(worker_client, 3, 1000, "worker_client", "finish");

    ASSERT_TRUE(is_udp(server = udp_bind("0.0.0.0:9999", 0)));
    ASSERT_FALSE(is_udp_packet(server));

    ASSERT_TRUE(is_udp_packet(client = udp_listen(server)));
    ASSERT_FALSE(is_udp(client));

    ASSERT_FALSE(result_is_ready(res));
    udp_handler((packet_cb)worker_connected, client);
    ASSERT_FALSE(result_is_ready(res));

    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(udp_listen);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}