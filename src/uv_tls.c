//%LICENSE////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2015 Devchandra M. Leishangthem (dlmeetei at gmail dot com)
//
// Distributed under the MIT License (See accompanying file LICENSE)
//
//////////////////////////////////////////////////////////////////////////
// See https://github.com/deleisha/evt-tls
//%///////////////////////////////////////////////////////////////////////////
#include "asio.h"
/*
 *All the asserts used in the code are possible targets for error
 * handling/error reporting
*/

evt_endpt_t evt_tls_get_role(const evt_tls_t *t) {
    RAII_ASSERT(t != NULL);
#if OPENSSL_VERSION_NUMBER < 0x10002000L
    return t->ssl->server ? ENDPT_IS_SERVER : ENDPT_IS_CLIENT;
#else
    return SSL_is_server(t->ssl) ? ENDPT_IS_SERVER : ENDPT_IS_CLIENT;
#endif
}

void evt_tls_set_role(evt_tls_t *t, evt_endpt_t role) {
    RAII_ASSERT(t != NULL && (role == ENDPT_IS_CLIENT || role == ENDPT_IS_SERVER));
    if (ENDPT_IS_SERVER == role) {
        SSL_set_accept_state(t->ssl);
    } else {
        SSL_set_connect_state(t->ssl);
    }
}

SSL_CTX *evt_get_SSL_CTX(const evt_ctx_t *ctx) {
    return ctx->ctx;
}

SSL *evt_get_ssl(const evt_tls_t *tls) {
    return tls->ssl;
}

static void tls_begin(void) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

evt_tls_t *evt_ctx_get_tls(evt_ctx_t *d_eng) {
    int r = 0;
    evt_tls_t *con = malloc(sizeof(evt_tls_t));
    if (!con) {
        return NULL;
    }
    memset(con, 0, sizeof * con);

    SSL *ssl = SSL_new(d_eng->ctx);
    if (!ssl) {
        free(con);
        return NULL;
    }
    con->ssl = ssl;

    //use default buf size for now.
    r = BIO_new_bio_pair(&(con->ssl_bio), 0, &(con->app_bio), 0);
    if (r != 1) {
        //order is important
        SSL_free(ssl);
        ssl = NULL;
        free(con);
        con = NULL;
        return NULL;
    }

    SSL_set_bio(con->ssl, con->ssl_bio, con->ssl_bio);

    QUEUE_INIT(&(con->q));
    QUEUE_INSERT_TAIL(&(d_eng->live_con), &(con->q));

    con->writer = d_eng->writer;
    con->reader = d_eng->reader;
    con->evt_ctx = d_eng;

    return con;
}

void evt_ctx_set_writer(evt_ctx_t *ctx, net_wrtr my_writer) {
    ctx->writer = my_writer;
    RAII_ASSERT(ctx->writer != NULL);
}

void evt_tls_set_writer(evt_tls_t *tls, net_wrtr my_writer) {
    tls->writer = my_writer;
    RAII_ASSERT(tls->writer != NULL);
}

void evt_ctx_set_reader(evt_ctx_t *ctx, net_rdr my_reader) {
    ctx->reader = my_reader;
    //RAII_ASSERT( ctx->reader != NULL);
}

void evt_tls_set_reader(evt_tls_t *tls, net_rdr my_reader) {
    tls->reader = my_reader;
    //RAII_ASSERT( ctx->reader != NULL);
}


void evt_ctx_set_nio(evt_ctx_t *ctx, net_rdr my_reader, net_wrtr my_writer) {
    ctx->reader = my_reader;
    //RAII_ASSERT( ctx->reader != NULL);

    ctx->writer = my_writer;
    RAII_ASSERT(ctx->writer != NULL);
}

int evt_ctx_set_crt_key(evt_ctx_t *tls, const char *crtf, const char *key) {
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);

    int r = SSL_CTX_use_certificate_file(tls->ctx, crtf, SSL_FILETYPE_PEM);
    if (r != 1) {
        return r;
    }
    tls->cert_set = 1;

    r = SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM);
    if (r != 1) {
        return r;
    }

    r = SSL_CTX_check_private_key(tls->ctx);
    if (r != 1) {
        return r;
    }
    tls->key_set = 1;
    return 1;
}

int evt_ctx_init(evt_ctx_t *tls) {
    tls_begin();

    //Currently we support only TLS, No DTLS
    //XXX SSLv23_method is deprecated change this,
    //Allow evt_ctx_init to take the method as input param,
    //allow others like dtls
    tls->ctx = SSL_CTX_new(SSLv23_method());
    if (!tls->ctx) {
        return -1;
    }

    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_3;
    SSL_CTX_set_options(tls->ctx, options);

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

    tls->type = UV_CTX;
    tls->data = NULL;
    tls->uv_args = NULL;
    tls->cert_set = 0;
    tls->key_set = 0;
    tls->ssl_err_ = 0;
    tls->writer = NULL;
    tls->reader = NULL;

    QUEUE_INIT(&(tls->live_con));
    return 0;
}

int evt_ctx_init_ex(evt_ctx_t *tls, const char *crtf, const char *key) {
    int r = 0;
    r = evt_ctx_init(tls);
    RAII_ASSERT(0 == r);
    return evt_ctx_set_crt_key(tls, crtf, key);
}

int evt_ctx_is_crtf_set(evt_ctx_t *t) {
    return t->cert_set;
}

int evt_ctx_is_key_set(evt_ctx_t *t) {
    return t->key_set;
}

static int evt__send_pending(evt_tls_t *conn) {
    RAII_ASSERT(conn != NULL);
    int pending = BIO_pending(conn->app_bio);
    if (!(pending > 0))
        return 0;

    void *buf = calloc(1, pending);
    RAII_ASSERT(buf != NULL && "Memory alloc failed");
    if (!buf) return 0;

    int p = BIO_read(conn->app_bio, buf, pending);
    RAII_ASSERT(p == pending);

    RAII_ASSERT(conn->writer != NULL && "You need to set network writer first");
    p = conn->writer(conn, buf, p);
    free(buf);
    return p;
}

static int evt__tls__op(evt_tls_t *conn, enum tls_op_type op, void *buf, int sz) {
    int r = 0;
    int bytes = 0;
    char tbuf[16 * 1024] = {0};

    switch (op) {
        case EVT_TLS_OP_HANDSHAKE:
            {
                r = SSL_do_handshake(conn->ssl);
                bytes = evt__send_pending(conn);
                RAII_ASSERT(bytes >= 0);
                if (1 == r || 0 == r) {
                    RAII_ASSERT(conn->hshake_cb != NULL);
                    conn->hshake_cb(conn, r);
                }
                break;
            }

        case EVT_TLS_OP_READ:
            {
                r = SSL_read(conn->ssl, tbuf, sizeof(tbuf));
                if (r == 0) goto handle_shutdown;

                if (r > 0) {
                    if (conn->read_cb) {
                        conn->read_cb(conn, tbuf, r);
                    }
                } else {
                    //write pending data, if nothing is pending, we assume
                    //that SSL_read failed and triger the read_cb
                    bytes = evt__send_pending(conn);
                    if (bytes == 0 && conn->read_cb) {
                        conn->read_cb(conn, tbuf, r);
                    }
                }
                break;
            }

        case EVT_TLS_OP_WRITE:
            {
                RAII_ASSERT(sz > 0 && "number of bytes to write should be positive");
                r = SSL_write(conn->ssl, buf, sz);
                if (0 == r) goto handle_shutdown;
                bytes = evt__send_pending(conn);
                if (r > 0 && conn->write_cb) {
                    conn->write_cb(conn, r);
                }
                break;
            }

            /* we initiate shutdown process, send the close_notify but we are not
             * sure if peer will sent their close_notify hence fire the callback
             * if the peer replied, it will be processed in SSL_read returning 0
             * and jump to handle_shutdown
             *
             * No check for SSL_shutdown done as it may be possible that user
             * called close upon receive of EOF.
             * TODO: Find a elegant way later
             * */

        case EVT_TLS_OP_SHUTDOWN:
            {
                r = SSL_shutdown(conn->ssl);
                bytes = evt__send_pending(conn);
                if (conn->close_cb) {
                    conn->close_cb(conn, r);
                }
                break;
            }

        default:
            RAII_ASSERT(0 && "Unsupported operation");
            break;
    }
    return r;

handle_shutdown:
    r = SSL_shutdown(conn->ssl);
    //it might be possible that peer send close_notify and close the network
    //hence, no check if sending is complete
    bytes = evt__send_pending(conn);
    if ((1 == r) && conn->close_cb) {
        conn->close_cb(conn, r);
    }
    return r;
}

int evt_tls_is_handshake_over(const evt_tls_t *evt) {
    return SSL_is_init_finished(evt->ssl);
}

int evt_tls_feed_data(evt_tls_t *c, void *data, int sz) {
    int offset = 0;
    int rv = 0;
    int i = 0;
    RAII_ASSERT(data != NULL && "invalid argument passed");
    RAII_ASSERT(sz > 0 && "Size of data should be positive");
    for (offset = 0; offset < sz; offset += i) {
        //handle error condition
        i = BIO_write(c->app_bio, data, sz - offset);

        //if handshake is not complete, do it again
        if (evt_tls_is_handshake_over(c)) {
            rv = evt__tls__op(c, EVT_TLS_OP_READ, NULL, 0);
        } else {
            rv = evt__tls__op(c, EVT_TLS_OP_HANDSHAKE, NULL, 0);
        }
    }
    return rv;
}

int evt_tls_connect(evt_tls_t *con, evt_handshake_cb cb) {
    con->hshake_cb = cb;
    SSL_set_connect_state(con->ssl);
    return evt__tls__op(con, EVT_TLS_OP_HANDSHAKE, NULL, 0);
}

int evt_tls_accept(evt_tls_t *tls, evt_handshake_cb cb) {
    RAII_ASSERT(tls != NULL);
    SSL_set_accept_state(tls->ssl);
    tls->hshake_cb = cb;

    //RAII_ASSERT( tls->reader != NULL && "You need to set network reader first");
    //char edata[16*1024] = {0};
    //tls->reader(tls, edata, sizeof(edata));
    return 0;
}

int evt_tls_write(evt_tls_t *c, void *msg, int str_len, evt_write_cb on_write) {
    c->write_cb = on_write;
    return evt__tls__op(c, EVT_TLS_OP_WRITE, msg, str_len);
}

// read only register the callback to be made
int evt_tls_read(evt_tls_t *c, evt_read_cb on_read) {
    RAII_ASSERT(c != NULL);
    c->read_cb = on_read;
    return 0;
}

int evt_tls_close(evt_tls_t *tls, evt_close_cb cb) {
    RAII_ASSERT(tls != NULL);
    tls->close_cb = cb;
    return evt__tls__op(tls, EVT_TLS_OP_SHUTDOWN, NULL, 0);
}

//need impl
int evt_tls_force_close(evt_tls_t *tls, evt_close_cb cb);



int evt_tls_free(evt_tls_t *tls) {
    BIO_free(tls->app_bio);
    tls->app_bio = NULL;

    SSL_free(tls->ssl);
    tls->ssl = NULL;

    QUEUE_REMOVE(&(tls->q));
    QUEUE_INIT(&(tls->q));

    free(tls);
    tls = NULL;
    return 0;
}

void evt_ctx_free(evt_ctx_t *ctx) {
    QUEUE *qh;
    evt_tls_t *tls = NULL;
    RAII_ASSERT(ctx != NULL);

    //clean all pending connections
    QUEUE_FOREACH(qh, &ctx->live_con) {
        tls = QUEUE_DATA(qh, evt_tls_t, q);
        evt__tls__op(tls, EVT_TLS_OP_SHUTDOWN, NULL, 0);
    }

    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;

    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    //SSL_COMP_free_compression_methods();
    CRYPTO_cleanup_all_ex_data();
}


// adapted from Openssl's s23_srvr.c code
int evt_is_tls_stream(const char *bfr, const int nrd) {
    int is_tls = 0;
    RAII_ASSERT(nrd >= 11);
    if ((bfr[0] & 0x80) && (bfr[2] == 1)) // SSL2_MT_CLIENT_HELLO
    {
        // SSLv2
        is_tls = 1;
    }
    if ((bfr[0] == 0x16) && (bfr[1] == 0x03) && (bfr[5] == 1) &&
        ((bfr[3] == 0 && bfr[4] < 5) || (bfr[9] == bfr[1]))
        ) {
        //SSLv3 and above
        is_tls = 1;
    }
    return is_tls;
}

static void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    memset(buf->base, 0, size);
    buf->len = (unsigned long)size;
    RAII_ASSERT(buf->base != NULL && "Memory allocation failed");
}

int uv_tls_writer(evt_tls_t *t, void *bfr, int sz) {
    int rv = 0;
    uv_buf_t b;
    b.base = bfr;
    b.len = sz;
    uv_tls_t *uvt = t->data;
    if(uv_is_writable((uv_stream_t*)(uvt->tcp_hdl)) ) {
        rv = uv_try_write((uv_stream_t*)(uvt->tcp_hdl), &b, 1);
    }
    return rv;
}

//int uv_tls_init(uv_loop_t *loop, evt_ctx_t *ctx, uv_tls_t *endpt)
//the tcp handle being passed should have been initialized or does not required
//to be initialized as uv_tls_init will not call uv_tcp_init
int uv_tls_init(evt_ctx_t *ctx, uv_tcp_t *tcp, uv_tls_t *endpt)
{
    int r = 0;
    memset( endpt, 0, sizeof *endpt);

    //r = uv_tcp_init(loop, &(endpt->tcp_hdl));

    evt_tls_t *t = evt_ctx_get_tls(ctx);

    //Replace the NULL with a meaningful error later
    RAII_ASSERT( t != NULL );

    t->data = endpt;
    tcp->data = endpt;

    endpt->tcp_hdl    = tcp;
    endpt->tls        = t;
    endpt->tls_rd_cb  = NULL;
    endpt->tls_cls_cb = NULL;
    endpt->tls_hsk_cb = NULL;
    endpt->tls_wr_cb  = NULL;
    endpt->type = UV_TLS;
    return r;
}

void on_tcp_eof(uv_handle_t *handle)
{
    uv_tls_t *utls = (uv_tls_t*)handle->data;
    evt_tls_free(utls->tls);
    free(handle);
}

void on_tcp_read(uv_stream_t *stream, ssize_t nrd, const uv_buf_t *data)
{
    uv_tls_t *parent = (uv_tls_t*)stream->data;

    RAII_ASSERT( parent != NULL);
    if ( nrd <= 0 ) {
        if( nrd == UV_EOF) {
            if ( evt_tls_is_handshake_over(parent->tls) ) {
                uv_tls_close(parent, (uv_tls_close_cb)free);
            }
            else {
                //if handshake is not over, simply tear down without close_notify
                uv_close((uv_handle_t*)stream, on_tcp_eof);
            }
        }
        free(data->base);
        return;
    }
    evt_tls_feed_data(parent->tls, data->base, (int)nrd);
    free(data->base);
}

static void on_hd_complete( evt_tls_t *t, int status)
{
    uv_tls_t *ut = (uv_tls_t*)t->data;
    RAII_ASSERT( ut != NULL && ut->tls_hsk_cb != NULL);
    ut->tls_hsk_cb(ut, status -1);
}


int uv_tls_accept(uv_tls_t *t, uv_handshake_cb cb)
{
    int rv = 0;
    RAII_ASSERT( t != NULL);
    t->tls_hsk_cb = cb;
    evt_tls_t *tls = t->tls;
    rv = evt_tls_accept(tls, on_hd_complete);
    uv_read_start((uv_stream_t*)(t->tcp_hdl), alloc_cb, on_tcp_read);
    return rv;
}

static void evt_on_rd(evt_tls_t *t, char *bfr, int sz)
{
    uv_buf_t data;
    uv_tls_t *tls = (uv_tls_t*)t->data;

    data.base = bfr;
    data.len = sz;

    RAII_ASSERT(tls->tls_rd_cb != NULL);
    tls->tls_rd_cb(tls, sz, &data);
}

void my_uclose_cb(uv_handle_t *handle)
{
    uv_tls_t *utls = (uv_tls_t*)handle->data;
    RAII_ASSERT( utls->tls_cls_cb != NULL);
    evt_tls_free(utls->tls);
    utls->tls_cls_cb(utls);
    free(handle);
}

void on_close(evt_tls_t *tls, int status)
{
    uv_tls_t *ut = (uv_tls_t*)tls->data;
    RAII_ASSERT( ut->tls_cls_cb != NULL);

    if ( !uv_is_closing((uv_handle_t*)(ut->tcp_hdl)))
        uv_close( (uv_handle_t*)(ut->tcp_hdl), my_uclose_cb);
}

int uv_tls_close(uv_tls_t *strm,  uv_tls_close_cb cb)
{
    strm->tls_cls_cb = cb;

    return evt_tls_close(strm->tls, on_close);
}

int uv_tls_read(uv_tls_t *tls, uv_tls_read_cb cb)
{
    uv_tls_t *ptr = (uv_tls_t*)tls;
    ptr->tls_rd_cb = cb;
    return evt_tls_read(ptr->tls, evt_on_rd);
}

static void on_hshake(evt_tls_t *etls, int status)
{
    RAII_ASSERT(etls != NULL);
    uv_tls_t *ut = (uv_tls_t*)etls->data;
    RAII_ASSERT(ut != NULL && ut->tls_hsk_cb != NULL);
    ut->tls_hsk_cb(ut, status - 1);
}

int uv_tls_connect(uv_tls_t *t, uv_handshake_cb cb)
{
    RAII_ASSERT( t != NULL);
    t->tls_hsk_cb = cb;
    evt_tls_t *evt = t->tls;
    RAII_ASSERT( evt != NULL);

    evt_tls_connect(evt, on_hshake);
    return uv_read_start((uv_stream_t*)(t->tcp_hdl), alloc_cb, on_tcp_read);
}

void on_evt_write(evt_tls_t *tls, int status) {
    RAII_ASSERT( tls != NULL);
    uv_tls_t *ut = (uv_tls_t*)tls->data;
    RAII_ASSERT( ut != NULL && ut->tls_wr_cb != NULL);
    ut->tls_wr_cb(ut, status);
}

int uv_tls_write(uv_tls_t *stream, uv_buf_t *buf, uv_tls_write_cb cb)
{
    RAII_ASSERT( stream != NULL);
    stream->tls_wr_cb = cb;
    evt_tls_t *evt = stream->tls;
    RAII_ASSERT( evt != NULL);

    return evt_tls_write(evt, buf->base, buf->len, on_evt_write);
}
