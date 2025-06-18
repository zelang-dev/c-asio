#include "uv_coro.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

void new_connection(uv_stream_t *socket) {
    string data = stream_read(socket);
    stream_write(socket, data);
}

int uv_main(int argc, char **argv) {
    uv_stream_t *client, *server;
    char addr[UV_MAXHOSTNAMESIZE] = nil;
    string_t is_secure = (argc > 0 && is_str_eq(argv[1], "-s"))
        ? "tls://0.0.0.0:%d"
        : "0.0.0.0:%d";

    if (snprintf(addr, sizeof(addr), is_secure, DEFAULT_PORT)) {
        server = stream_bind(addr, 0);
        while (server) {
            if (is_empty(client = stream_listen(server, DEFAULT_BACKLOG))) {
                fprintf(stderr, "Listen error %s\n", uv_strerror(coro_err_code()));
                break;
            }

            stream_handler(new_connection, client);
        }
    }

    return coro_err_code();
}
