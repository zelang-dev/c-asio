#include "asio.h"

string http_get(string path, string type, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_GET, path, type, nullptr, numof, headers);
	va_end(headers);

	return req;
}

string http_post(string path, string data, string type, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_POST, path, type, data, numof, headers);
	va_end(headers);

	return req;
}

string http_delete(string path, string data, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_DELETE, path, nullptr, data, numof, headers);
	va_end(headers);

	return req;
}

string http_patch(string path, string data, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_PATCH, path, nullptr, data, numof, headers);
	va_end(headers);

	return req;
}

string http_options(string path, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_OPTIONS, path, nullptr, nullptr, numof, headers);
	va_end(headers);

	return req;
}

string http_head(string path, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_HEAD, path, nullptr, nullptr, numof, headers);
	va_end(headers);

	return req;
}

RAII_INLINE void http_this(uv_tls_t *socket) {
	if (is_type(socket, (raii_type)ASIO_ASYNC_TLS) && is_empty(coro_data()))
		coro_data_set(coro_active(), (void_t)socket);

	throw(logic_error);
}
