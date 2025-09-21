#ifndef _UV_TLS_H
#define _UV_TLS_H

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <rtypes.h>
#include <tls.h>
#include <uv.h>
#include <url_http.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_config tls_config_t;
typedef struct tls tls_s;
typedef struct uv_tls_s uv_tls_t;
typedef struct uv_tls_s {
	raii_type type;
	int err;
	bool is_client;
	bool is_server;
	bool is_connecting;
	unsigned flags;
	u32 retry;
	string buf;
	void_t data;
	http_t *http;
	uv_stream_t *stream;
	tls_s *secure;
} uv_tls_t;

#define TLS_EOF 0xa000126

C_API int uv_tls_accept(uv_tls_t *const server, uv_tls_t *const socket);
C_API int uv_tls_connect(char const *const host, uv_tls_t *const socket);
C_API void uv_tls_close(uv_tls_t *const socket);
C_API bool uv_tls_is_secure(uv_tls_t *const socket);
C_API char const *uv_tls_error(uv_tls_t  *const socket);

C_API char *uv_tls_read(uv_tls_t *const socket);
C_API ssize_t uv_tls_write(uv_tls_t *const socket, unsigned char const *const buf, size_t const len);

C_API int uv_tls_flush(uv_tls_t *const socket);
C_API int uv_tls_peek(uv_tls_t *const socket);

C_API bool is_tls_selfserver(void);
C_API void tls_selfserver_set(void);
C_API void tls_selfserver_clear(void);

#ifdef _WIN32
#define _BIO_MODE_R(flags) (((flags) & PKCS7_BINARY) ? "rb" : "r")
#define _BIO_MODE_W(flags) (((flags) & PKCS7_BINARY) ? "wb" : "w")
#else
#define _BIO_MODE_R(flags) "r"
#define _BIO_MODE_W(flags) "w"
#endif
/* OpenSSL Certificate */
typedef struct certificate_object ASIO_cert_t;

/* OpenSSL AsymmetricKey */
typedef struct pkey_object ASIO_pkey_t;

/* OpenSSL Certificate Signing Request */
typedef struct x509_request_object ASIO_req_t;

C_API bool is_pkey(void_t);
C_API bool is_cert_req(void_t);
C_API bool is_cert(void_t);

C_API string_t ca_cert_file(void);
C_API string_t cert_file(void);
C_API string_t pkey_file(void);
C_API string_t csr_file(void);

C_API void ASIO_ssl_error(void);
C_API void ASIO_ssl_init(void);

C_API ASIO_pkey_t *pkey_create(u32 num_pairs, ...);
C_API ASIO_req_t *csr_create(EVP_PKEY *pkey, u32 num_pairs, ...);
C_API ASIO_cert_t *x509_create(EVP_PKEY *pkey, u32 num_pairs, ...);

C_API X509 *csr_sign(ASIO_req_t *,
	ASIO_cert_t *,
	ASIO_pkey_t *,
	int days,
	int serial,
	arrays_t options);

C_API X509 *x509_get(string_t file_path);
C_API EVP_PKEY *pkey_get(string_t file_path);
C_API string x509_str(X509 *cert, bool show_details);

C_API bool pkey_x509_export(EVP_PKEY *pkey, string_t path_noext);
C_API bool csr_x509_export(X509_REQ *req, string_t path_noext);
C_API bool cert_x509_export(X509 *cert, string_t path_noext);
C_API bool x509_pkey_write(EVP_PKEY *pkey, X509 *x509);

C_API EVP_PKEY *rsa_pkey(int keylength);
C_API X509 *x509_self(EVP_PKEY *pkey, string_t country, string_t org, string_t domain);
C_API bool x509_self_export(EVP_PKEY *pkey, X509 *x509, string_t path_noext);

C_API void use_ca_certificate(string_t path);
C_API void use_certificate(string path, u32 ctx_pairs, ...);

#ifdef __cplusplus
}
#endif

#endif /* _UV_TLS_H */