#ifndef _UV_HTTP_H
#define _UV_HTTP_H

#include "uv_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Make a GET request, will pause current task, and
 * continue other tasks until an response is received.
 *
 * WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
 *
 * @param path
 * @param type defaults to `text/html; charset=utf-8`, if empty
 * @param numof number of additional headers
 *
 * - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
 *
 * - `kv(header_types, "value")`
 *
 * - `or:` `kv_custom("key", "value")`
 */
C_API string uv_http_get(string path, string type, u32 numof, ...);

/**
 * Make a POST request, will pause current task, and
 * continue other tasks until an response is received.
 *
 * WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
 *
 * @param path
 * @param data
 * @param type defaults to `text/html; charset=utf-8`, if empty
 * @param numof number of additional headers
 *
 * - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
 *
 * - `kv(header_types, "value")`
 *
 * - `or:` `kv_custom("key", "value")`
 */
C_API string uv_http_post(string path, string data, string type, u32 numof, ...);

/**
* Make a DELETE request, will pause current task, and
* continue other tasks until an response is received.
*
* WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
*
* @param path
* @param data
* @param type defaults to `text/html; charset=utf-8`, if empty
* @param numof number of additional headers
*
* - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* - `kv(header_types, "value")`
*
* - `or:` `kv_custom("key", "value")`
*/
C_API string uv_http_delete(string path, string data, u32 numof, ...);

/**
* Make a PATCH request, will pause current task, and
* continue other tasks until an response is received.
*
* WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
*
* @param path
* @param data
* @param numof number of additional headers
*
* - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* - `kv(header_types, "value")`
*
* - `or:` `kv_custom("key", "value")`
*/
C_API string uv_http_patch(string path, string data, u32 numof, ...);

/**
* Make a OPTIONS request, will pause current task, and
* continue other tasks until an response is received.
*
* WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
*
* @param path
* @param numof number of additional headers
*
* - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* - `kv(header_types, "value")`
*
* - `or:` `kv_custom("key", "value")`
*/
C_API string uv_http_options(string path, u32 numof, ...);

/**
* Make a HEAD request, will pause current task, and
* continue other tasks until an response is received.
*
* WILL `panic` ~logic_error~, if current `coroutine` user_data ~field~, not `ASIO_TLS`.
*
* @param path
* @param numof number of additional headers
*
* - `using:` header_types = `head_by, head_cookie, head_secure, head_conn, head_bearer, head_auth_basic`
*
* - `kv(header_types, "value")`
*
* - `or:` `kv_custom("key", "value")`
*/
C_API string uv_http_head(string path, u32 numof, ...);

#ifdef __cplusplus
}
#endif

#endif /* _UV_HTTP_H */