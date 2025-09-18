#include "asio.h"

int uv_main(int argc, char **argv) {
	yield();
	use_ca_certificate("cert.pem");
	uv_stream_t *client = stream_secure("127.0.0.1", asio_hostname(), 7000);
	if (is_tls(client)) {
		cerr("Connected!"CLR_LN);
		string data = stream_read(client);
		if (is_str_eq("world", data)) {
			if (stream_write(client, "hello") == 5) {
				cout("Secured transaction!"CLR_LN);
			}
		}
	}

	return coro_err_code();
}
