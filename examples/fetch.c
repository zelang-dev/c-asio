#include "asio.h"

int uv_main(int argc, char **argv) {
	yield();
	if (argc <= 1) {
		cerr("Usage: fetch url"CLR_LN);
		return 1;
	}

	string data = nullptr;
	int chunks = 0;
	url_t *url = parse_url(argv[1]);
	if (!is_empty(url)) {
		dnsinfo_t *dns = get_addrinfo(url->host, url->scheme, 3,
			kv(ai_flags, AF_UNSPEC),
			kv(ai_socktype, SOCK_STREAM),
			kv(ai_protocol, IPPROTO_TCP)
		);

		use_ca_certificate("cert.pem");
		uv_stream_t *client = stream_secure(addrinfo_ip(dns), url->host, url->port);
		if (!is_empty(client) && stream_write(client, "GET /"CRLF)) {
			cout(CLR_LN);
			while (stream_peek(client) != UV_EOF) {
				if (!is_empty(data = stream_read(client)))
					cout("%s", data);
				else
					break;

				chunks++;
			}
		}
	}

	cout("\n\nReceived: %d chunks.\n", chunks);
	return coro_err_code();
}
