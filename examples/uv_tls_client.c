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

void echo_read(uv_tls_t *strm, ssize_t nrd, const uv_buf_t *bfr)
{
    if ( nrd <= 0 ) return;
    fprintf( stdout, "%s\n", bfr->base);

    uv_tls_close(strm, (uv_tls_close_cb)free);
}

void on_write(uv_tls_t *utls, int status)
{
    assert(utls->tcp_hdl->data == utls);
    if (status == -1) {
	fprintf(stderr, "error on_write");
	return;
    }

    uv_tls_read(utls, echo_read);
}

void on_tls_handshake(uv_tls_t *tls, int status)
{
    assert(tls->tcp_hdl->data == tls);
    uv_buf_t dcrypted;
    dcrypted.base = "Hello from evt-tls";
    dcrypted.len = (unsigned long)strlen(dcrypted.base);

    if ( 0 == status ) // TLS connection not failed
    {
        uv_tls_write(tls, &dcrypted, on_write);
    }
    else {
	uv_tls_close(tls, (uv_tls_close_cb)free);
    }
}

void on_connect(uv_connect_t *req, int status)
{
    // TCP connection error check
    if( status ) {
        return;
    }

    evt_ctx_t *ctx = req->data;
    uv_tcp_t *tcp = (uv_tcp_t*)req->handle;

    //free on uv_tls_close
    uv_tls_t *sclient = malloc(sizeof(*sclient));
    if( uv_tls_init(ctx, tcp, sclient) < 0 ) {
        free(sclient);
        return;
    }
    assert(tcp->data == sclient);
    uv_tls_connect(sclient, on_tls_handshake);
}

int uv_main(int argc, char **argv) {
	yield();
	uv_loop_t *loop = asio_loop();
    //free on uv_close_cb via uv_tls_close call
    uv_tcp_t *client = malloc(sizeof *client);
    uv_tcp_init(loop, client);
    int port = 7000;

    evt_ctx_t ctx;

	evt_ctx_init_ex(&ctx, cert_file(), pkey_file());
    evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);

    struct sockaddr_in conn_addr;
    uv_ip4_addr("127.0.0.1", port, &conn_addr);

    uv_connect_t req;
    req.data = &ctx;
    uv_tcp_connect(&req, client,(const struct sockaddr*)&conn_addr, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);
	evt_ctx_free(&ctx);

	return 0;
}
