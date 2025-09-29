#include "asio.h"

string uv_http_get(string path, string type, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_GET, path, type, nullptr, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

string uv_http_post(string path, string data, string type, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_POST, path, type, data, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

string uv_http_delete(string path, string data, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_DELETE, path, nullptr, data, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

string uv_http_patch(string path, string data, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_PATCH, path, nullptr, data, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

string uv_http_options(string path, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_OPTIONS, path, nullptr, nullptr, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

string uv_http_head(string path, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_HEAD, path, nullptr, nullptr, numof, headers);
	va_end(headers);

	stream_write(this->stream, req);

	return req;
}

RAII_INLINE void uv_this(void_t *data, asio_types type) {
	if (is_type(socket, (raii_type)type) && is_empty(coro_data()))
		coro_data_set(coro_active(), (void_t)data);

	throw(logic_error);
}
