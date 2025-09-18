#include "asio.h"

#define READ_BUFFER (1024 * 8)
#define WRITE_BUFFER (1024 * 8)

enum {
	http_incomplete = 1 << 0,
	http_keepalive = 1 << 1,
	http_outgoing = 1 << 2,
};

static volatile bool tls_is_self_signed = false;
static int tlserr(int const rc, struct tls *const secure) {
	if (0 == rc) return 0;
	RAII_ASSERT(-1 == rc);
#ifdef USE_DEBUG
	cerr("TLS error: %s"CLR_LN, tls_error(secure));
	SSL_load_error_strings();
	char x[255 + 1];
	ERR_error_string_n(ERR_get_error(), x, sizeof(x));
	cerr("SSL error: %s"CLR_LN, x);
#endif
	return UV_EPROTO;
}

static void tls_alloc_cb(uv_handle_t *const handle, size_t const suggested_size, uv_buf_t *const buf) {
	async_state *const state = get_handle_tls_state(handle);
	buf->base = (char *)state->buf;
	buf->len = state->max;
}

static void tls_yield_cb(uv_stream_t *const stream, ssize_t const nread, uv_buf_t const *const buf) {
	async_state *const state = get_handle_tls_state(stream);
	state->status = nread ? nread : UV_EAGAIN;
	uv_read_stop(stream);
	asio_switch(state->thread);
}

static ssize_t async_read(async_tls_t *const socket, unsigned char *const buf, size_t const max) {
	if (!socket) return UV_EINVAL;
	async_state *state = get_handle_tls_state(socket->stream);
	bool is_client_only = socket->is_client && !socket->is_server;
	int rc;

	state->thread = coro_active();
	state->status = 0;
	state->buf = buf;
	state->max = max;
	if (is_client_only)
		coro_enqueue(coro_running());

	do {
		rc = uv_read_start(streamer(socket->stream), tls_alloc_cb, tls_yield_cb);
		if (rc < 0) return rc;
		if (socket->is_connecting)
			rc = uv_run(asio_loop(), INTERRUPT_MODE);
		else if (is_client_only)
			coro_suspend();
		else
			yield();

		uv_read_stop(streamer(socket->stream));
		if (rc < 0) return rc;
		rc = state->status;
	} while (UV_EAGAIN == rc);
	if (UV_EOF == rc) return 0;
	if (UV_ENOBUFS == rc && 0 == max) rc = 0;

	return rc;
}

static int tls_poll(async_tls_t *const socket, int const event) {
	int rc = event;
	if (TLS_WANT_POLLIN == event) {
		rc = async_read(socket, nullptr, 0);
		if (UV_ENOBUFS == rc) rc = 0;
	} else if (TLS_WANT_POLLOUT == event) {
		// TODO: libuv provides NO WAY to wait until a stream is
		// writable! Even our zero-length write hack doesn't work.
		// uv_poll can't be used on uv's own stream fds.
		rc = delay(25) >= 0 ? 0 : RAII_ERR;
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
			rc = tlserr(tls_poll(socket, event), socket->secure);
			if (rc < 0) goto cleanup;
		}
	}

cleanup:
	if (rc < 0)	async_tls_close(socket);
	return rc;
}

int async_tls_connect(char const *const host, async_tls_t *const socket) {
	int event = 0, rc = 0;
	uv_os_fd_t fd;

	if (!socket) return UV_EINVAL;
	socket->secure = tls_client();
	if (!socket->secure) rc = UV_ENOMEM;
	if (rc < 0) goto cleanup;

	if (tls_is_self_signed)
		tls_config_insecure_noverifycert((struct tls_config *)socket->data);
	else
		tls_config_verify((struct tls_config *)socket->data);

	rc = tls_configure(socket->secure, (struct tls_config *)socket->data);
	if (rc < 0)	goto cleanup;

	rc = uv_fileno((uv_handle_t *)socket->stream, &fd);
	if (rc < 0)	goto cleanup;
	rc = tlserr(tls_connect_socket(socket->secure, (int)fd, host), socket->secure);
	if (rc < 0)	goto cleanup;

	for (;;) {
		event = tls_handshake(socket->secure);
		if (0 == event) break;
		rc = tlserr(tls_poll(socket, event), socket->secure);
		if (rc < 0)	goto cleanup;
	}

cleanup:
	if (rc < 0) async_tls_close(socket);
	return rc;
}

bool is_tls_selfserver(void) {
	return tls_is_self_signed;
}

void tls_selfserver_set(void) {
	tls_is_self_signed = true;
}

void tls_selfserver_clear(void) {
	tls_is_self_signed = false;
}

void async_tls_close(async_tls_t *const socket) {
	if (!socket)
		return;

	if (is_type(socket, (raii_type)ASIO_ASYNC_TLS)) {
		socket->type = RAII_ERR;
		if (socket->err != UV_EOF && socket->secure)
			tls_close(socket->secure);

		tls_free(socket->secure);
		socket->secure = nullptr;
		if (!is_empty(socket->buf)) {
			RAII_FREE(socket->buf);
			socket->buf = nullptr;
		}
	}
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

	for (;;) {
		ssize_t x = tls_read(socket->secure, buf, max);
		if (x >= 0) {
			socket->buf = buf;
			return buf;
		}

		if (tlserr(tls_poll(socket, (int)x), socket->secure) < 0)
			return asio_abort(buf, x, co);
	}

	RAII_ASSERT(0);
	return coro_await_erred(co, UV_UNKNOWN); // Not reached
}

ssize_t async_tls_write(async_tls_t *const socket, unsigned char const *const buf, size_t const len) {
	for (;;) {
		ssize_t x = tls_write(socket->secure, buf, len);
		if (x >= 0) return x;
		int rc = tlserr(tls_poll(socket, (int)x), socket->secure);
		if (rc < 0) return rc;
	}
	RAII_ASSERT(0);
	return UV_UNKNOWN; // Not reached
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
