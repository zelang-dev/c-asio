//%LICENSE////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2015 Devchandra M. Leishangthem (dlmeetei at gmail dot com)
//
// Distributed under the MIT License (See accompanying file LICENSE)
//
//////////////////////////////////////////////////////////////////////////
//
//%///////////////////////////////////////////////////////////////////////////

#include <string.h>
#include <stdint.h>
#include <signal.h>
#include "evt_tls.h"
#include <rpmalloc.h>

void on_write(uv_tls_t *tls, int status) {
    uv_tls_close(tls, (uv_tls_close_cb)free);
}

void uv_rd_cb( uv_tls_t *strm, ssize_t nrd, const uv_buf_t *bfr) {
    if ( nrd <= 0 )
    {
        return;
    }
    uv_tls_write(strm, (uv_buf_t *)bfr, on_write);
}

void on_uv_handshake(uv_tls_t *ut, int status) {
    if ( 0 == status )
        uv_tls_read(ut, uv_rd_cb);
    else
        uv_tls_close(ut, (uv_tls_close_cb)free);
}

void on_connect_cb(uv_stream_t *server, int status) {
    if( status ) return;
    uv_tcp_t *tcp = malloc(sizeof(*tcp)); //freed on uv_close callback
    uv_tcp_init(uv_default_loop(), tcp);
    if (uv_accept(server, (uv_stream_t*)tcp)) {
        return;
    }

    uv_tls_t *sclient = malloc(sizeof(*sclient)); //freed on uv_close callback
    if( uv_tls_init((evt_ctx_t*)server->data, tcp, sclient) < 0 ) {
        free(sclient);
        return;
    }
    uv_tls_accept(sclient, on_uv_handshake);
}

#ifndef HOSTNAME
#define HOSTNAME "localhost"
#endif
int main() {
    uv_replace_allocator(rp_malloc, rp_realloc, rp_calloc, rpfree);
    uv_loop_t *loop = uv_default_loop();
    int port = 9010, r = 0;
    evt_ctx_t ctx;
    struct sockaddr_in bind_local;

    char name[256];
    char crt[256];
    char key[256];
    size_t len = sizeof(name);

    uv_os_gethostname(name, &len);
    r = snprintf(crt, sizeof(crt), "%s.crt", name);
    if (r == 0)
        puts("Invalid hostname");

    r = snprintf(key, sizeof(crt), "%s.key", name);
    if (r == 0)
        puts("Invalid hostname");

    evt_ctx_init_ex(&ctx, crt, key);
    evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);

    uv_tcp_t listener_local;
    uv_tcp_init(loop, &listener_local);
    listener_local.data = &ctx;
    uv_ip4_addr("127.0.0.1", port, &bind_local);
    if ((r = uv_tcp_bind(&listener_local, (struct sockaddr*)&bind_local, 0)))
        fprintf( stderr, "bind: %s\n", uv_strerror(r));

    if ((r = uv_listen((uv_stream_t*)&listener_local, 1024, on_connect_cb)))
        fprintf( stderr, "listen: %s\n", uv_strerror(r));
    printf("Listening on %d\n", port);
    uv_run(loop, UV_RUN_DEFAULT);
    evt_ctx_free(&ctx);

    return 0;
}
