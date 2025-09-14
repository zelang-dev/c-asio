#include "asio.h"

#define READ_BUFFER (1024 * 8)
#define WRITE_BUFFER (1024 * 8)

enum {
	http_incomplete = 1 << 0,
	http_keepalive = 1 << 1,
	http_outgoing = 1 << 2,
};


static int tlserr(int const rc, struct tls *const secure) {
	if (0 == rc) return 0;
	RAII_ASSERT(-1 == rc);
#ifdef USE_DEBUG
	fprintf(stderr, "TLS error: %s\n", tls_error(secure));
	SSL_load_error_strings();
	char x[255 + 1];
	ERR_error_string_n(ERR_get_error(), x, sizeof(x));
	fprintf(stderr, "SSL error: %s\n", x);
#endif
	return UV_EPROTO;
}

static int tls_poll(uv_stream_t *const stream, int const event) {
	int rc;
	if (TLS_WANT_POLLIN == event) {
		rc = async_read(stream, nullptr, 0);
		if (UV_ENOBUFS == rc) rc = 0;
	} else if (TLS_WANT_POLLOUT == event) {
		// TODO: libuv provides NO WAY to wait until a stream is
		// writable! Even our zero-length write hack doesn't work.
		// uv_poll can't be used on uv's own stream fds.
		rc = delay(25) >= 0 ? 0 : RAII_ERR;
	} else {
		rc = event;
	}

	return rc;
}

int async_tls_accept(async_tls_t *const server, async_tls_t *const socket) {
	uv_os_fd_t fd;
	int event, rc;

	if (!server || !socket) return UV_EINVAL;
	rc = uv_tcp_init(asio_loop(), socket->stream);
	if (rc < 0) goto cleanup;
	rc = uv_accept((uv_stream_t *)server->stream, (uv_stream_t *)socket->stream);
	if (rc < 0) goto cleanup;
	if (server->secure) {
		rc = uv_fileno((uv_handle_t *)socket->stream, &fd);
		if (rc < 0) goto cleanup;
		rc = tlserr(tls_accept_socket(server->secure, &socket->secure, (int)fd), server->secure);
		if (rc < 0) goto cleanup;
		for (;;) {
			event = tls_handshake(socket->secure);
			if (0 == event) break;
			rc = tlserr(tls_poll(streamer(socket->stream), event), socket->secure);
			if (rc < 0) goto cleanup;
		}
	}

cleanup:
	if (rc < 0) async_tls_close(socket);
	return rc;
}

int async_tls_connect(char const *const host, async_tls_t *const socket) {
	int event, rc;
	uv_os_fd_t fd;

	if (!socket)
		return UV_EINVAL;

	socket->secure = tls_client();
	if (!socket->secure)
		rc = UV_ENOMEM;
	if (rc < 0) goto cleanup;

	rc = tls_configure(socket->secure, (struct tls_config *)socket->data);
	if (rc < 0)	goto cleanup;

	rc = uv_fileno((uv_handle_t *)socket->stream, &fd);
	if (rc < 0)	goto cleanup;

	rc = tlserr(tls_connect_socket(socket->secure, fd, host), socket->secure);
	if (rc < 0)	goto cleanup;

	for (;;) {
		if (!(event = tls_handshake(socket->secure)))
			break;

		rc = tlserr(tls_poll((uv_stream_t *)socket->stream, event), socket->secure);
		if (rc < 0)	goto cleanup;
	}

cleanup:
	if (rc < 0)
		async_tls_close(socket);

	return rc;
}

void async_tls_close(async_tls_t *const socket) {
	if (!socket)
		return;

	if (socket->err != UV_EOF && socket->secure)
		tls_close(socket->secure);

	tls_free(socket->secure);
	socket->secure = nullptr;
}

bool async_tls_is_secure(async_tls_t *const socket) {
	if (!socket) return false;
	return !!socket->secure;
}

string_t async_tls_error(async_tls_t *const socket) {
	if (!socket) return nullptr;
	if (!socket->secure) return nullptr;
	return tls_error(socket->secure);
}

string async_tls_read(async_tls_t *const socket) {
	string buf = calloc(1, READ_BUFFER + 1);
	size_t const max = READ_BUFFER;
	routine_t *co = coro_active();

	if (!buf)
		return coro_await_erred(co, UV_ENOMEM);

	if (!is_empty(socket->buf)) {
		free(socket->buf);
		socket->buf = nullptr;
	}

	yield();
	for (;;) {
		ssize_t x = tls_read(socket->secure, buf, max);
		if (x >= 0) {
			socket->buf = buf;
			return buf;
		}

		if (tlserr(tls_poll(streamer(socket->stream), (const int)x), socket->secure) < 0)
			return asio_abort(buf, x, co);
	}

	RAII_ASSERT(0);
	return coro_await_erred(co, UV_UNKNOWN); // Not reached
}

ssize_t async_tls_write(async_tls_t *const socket, unsigned char const *const buf, size_t const len) {
	for (;;) {
		ssize_t x = tls_write(socket->secure, buf, len);
		if (x >= 0) return x;
		int rc = tlserr(tls_poll(streamer(socket->stream), (const int)x), socket->secure);
		if (rc < 0) return rc;
	}
	RAII_ASSERT(0);
	return UV_UNKNOWN; // Not reached
}

static void tls_alloc_cb(uv_handle_t *const handle, size_t const suggested_size, uv_buf_t *const buf) {
	async_state *const state = handle_getasync_state(handle);
	buf->base = (char *)state->buf;
	buf->len = state->max;
}

static void tls_yield_cb(uv_stream_t *const stream, ssize_t const nread, uv_buf_t const *const buf) {
	async_state *const state = handle_getasync_state(stream);
	state->status = nread ? nread : UV_EAGAIN;
	uv_read_stop(stream);
	asio_switch(state->thread);
}

ssize_t async_read(uv_stream_t *const stream, unsigned char *const buf, size_t const max) {
	if (!stream) return UV_EINVAL;
	async_state *state = handle_getasync_state(stream);
	int rc;

	state->thread = coro_active();
	state->status = 0;
	state->buf = buf;
	state->max = max;

	do {
		rc = uv_read_start(stream, tls_alloc_cb, tls_yield_cb);
		if (rc < 0) return rc;
		rc = uv_run(asio_loop(), INTERRUPT_MODE);
		uv_read_stop(stream);
		if (rc < 0) return rc;
		rc = state->status;
	} while (UV_EAGAIN == rc);
	if (UV_EOF == rc) return 0;
	if (UV_ENOBUFS == rc && 0 == max) rc = 0;

	return rc;
}

int async_tls_flush(async_tls_t *const socket) {
	if (async_tls_is_secure(socket)) {
		if (http_keepalive & socket->flags) return 0;
		if (http_outgoing & socket->flags) return 0; // Don't close after sending request. Could use shutdown(2) here.
		tls_close(socket->secure);
		//tls_flush(socket->secure);
		socket->err = UV_EOF;
	}

	return 0;
}
