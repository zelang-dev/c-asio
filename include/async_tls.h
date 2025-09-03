#ifndef _UV_TLS_H
#define _UV_TLS_H

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <stdbool.h>
#include <tls.h>
#include <uv.h>

// https://wiki.mozilla.org/Security/Server_Side_TLS
// https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS&oldid=1080944
// "Modern" compatibility ciphersuite
#define ASYNC_TLS_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

// According to SSL Labs, enabling TLS1.1 doesn't do any good...
// Not 100% sure about its status in IE11 though.
#define ASYNC_TLS_PROTOCOLS (TLS_PROTOCOL_TLSv1_2)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_config tls_config_t;
typedef struct tls tls_s;
typedef struct {
	uv_tcp_t *stream;
	tls_s *secure;
	void *data;
	char *buf;
} async_tls_t;

int async_tls_accept(async_tls_t *const server, async_tls_t *const socket);
int async_tls_connect(char const *const host, async_tls_t *const socket);
void async_tls_close(async_tls_t *const socket);
bool async_tls_is_secure(async_tls_t *const socket);
char const *async_tls_error(async_tls_t  *const socket);

char *async_tls_read(async_tls_t *const socket);
ssize_t async_tls_write(async_tls_t *const socket, unsigned char const *const buf, size_t const len);

ssize_t async_read(uv_stream_t *const stream, unsigned char *const buf, size_t const max);
int async_connect(uv_tcp_t *const stream, struct sockaddr const *const addr);

#ifdef __cplusplus
}
#endif

#endif /* _UV_TLS_H */