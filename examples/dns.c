#include "asio.h"

int uv_main(int argc, char **argv) {
    string text = nullptr;
	cerr("irc.libera.chat is..."CLR_LN);
	dnsinfo_t *dns = get_addrinfo("irc.libera.chat", "6667", 3,
		kv(ai_flags, AF_UNSPEC),
		kv(ai_socktype, SOCK_STREAM),
		kv(ai_protocol, IPPROTO_TCP)
	);

	cerr("%s"CLR_LN, addrinfo_ip(dns));
	uv_stream_t *server = stream_connect_ex(UV_TCP, addrinfo_ip(dns), "irc.libera.chat", 6667);
    while (text = stream_read(server))
        cerr(CLR_LN"%s", text);

    return coro_err_code();
}
