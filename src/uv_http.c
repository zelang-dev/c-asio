#include "asio.h"

/**
 * Make a GET request, will pause current task, and
 * continue other tasks until an response is received.
 *
 * @param path
 * @param type defaults to `text/html; charset=utf-8`, if empty
 * @param numof number of additional headers
 *
 *	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
 *
 * 	- `kv(header_types, "value")`
 *
 * 	- `or:` `kv_custom("key", "value")`
 */
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

/**
 * Make a POST request, will pause current task, and
 * continue other tasks until an response is received.
 *
 * @param path
 * @param data
 * @param type defaults to `text/html; charset=utf-8`, if empty
 * @param numof number of additional headers
 *
 *	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
 *
 * 	- `kv(header_types, "value")`
 *
 * 	- `or:` `kv_custom("key", "value")`
 */
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

/**
* Make a DELETE request, will pause current task, and
* continue other tasks until an response is received.
*
* @param path
* @param data
* @param type defaults to `text/html; charset=utf-8`, if empty
* @param numof number of additional headers
*
*	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* 	- `kv(header_types, "value")`
*
* 	- `or:` `kv_custom("key", "value")`
*/
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

/**
* Make a PATCH request, will pause current task, and
* continue other tasks until an response is received.
*
* @param path
* @param data
* @param numof number of additional headers
*
*	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* 	- `kv(header_types, "value")`
*
* 	- `or:` `kv_custom("key", "value")`
*/
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

/**
* Make a OPTIONS request, will pause current task, and
* continue other tasks until an response is received.
*
* @param path
* @param numof number of additional headers
*
*	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* 	- `kv(header_types, "value")`
*
* 	- `or:` `kv_custom("key", "value")`
*/
bool http_options(string path, u32 numof, ...) {
	uv_tls_t *this = (uv_tls_t *)coro_data();
	if (!is_type(this, (raii_type)ASIO_ASYNC_TLS))
		throw(logic_error);

	va_list headers;
	va_start(headers, numof);
	string req = http_request(this->http, HTTP_OPTIONS, path, nullptr, nullptr, numof, headers);
	va_end(headers);

	return req != nullptr;
}

/**
* Make a HEAD request, will pause current task, and
* continue other tasks until an response is received.
*
* @param path
* @param numof number of additional headers
*
*	- `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* 	- `kv(header_types, "value")`
*
* 	- `or:` `kv_custom("key", "value")`
*/
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

/**
 * Creates an `this` instance for `http_t`/`uv_tls_t`
 * on current `coroutine` ~connected~ `stream`.
 */
void http_this(uv_tls_t *socket) {
	if (is_type(socket, (raii_type)ASIO_ASYNC_TLS) && is_empty(coro_data()))
		coro_data_set(coro_active(), (void_t)socket);

	throw(logic_error);
}
