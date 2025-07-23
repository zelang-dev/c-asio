#include "uv_coro.h"

int uv_main(int argc, char **argv) {
    string text = nullptr;
    fprintf(stderr, "irc.libera.chat is...\033[0K\n");
    dnsinfo_t *dns = get_addrinfo("irc.libera.chat", "6667",
                                  3, kv(ai_flags, AF_UNSPEC),
                                  kv(ai_socktype, SOCK_STREAM),
                                  kv(ai_protocol, IPPROTO_TCP));

    fprintf(stderr, "%s\033[0K\n", addrinfo_ip(dns));
    uv_stream_t *server = stream_connect_ex(UV_TCP, addrinfo_ip(dns), 6667);
    while (text = stream_read(server))
        fprintf(stderr, "\033[0K%s", text);

    return coro_err_code();
}
