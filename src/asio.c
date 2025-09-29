#include "asio.h"

struct uv_args_s {
    asio_types type;
    raii_type bind_type;
    bool is_path;
    bool is_request;
    bool is_freeable;
    bool is_server;
    bool is_generator;
    bool is_once;
    volatile bool is_working;
    uv_fs_type fs_type;
    uv_req_type req_type;
    uv_handle_type handle_type;

    /* total number of args in set */
    size_t n_args;

    /* allocated array of arguments */
    arrays_t args;
    routine_t *context;

    string buffer;
    uv_buf_t bufs;
    uv_fs_t fs_req;
    uv_work_t work_req;
    uv_write_t write_req;
    uv_connect_t connect_req;
    uv_shutdown_t shutdown_req;
    uv_getaddrinfo_t addinfo_req;
    udp_packet_t *packet_req;
	tls_config_t *ctx;
	tls_state state[1];
	uv_tls_t tls[1];
	uv_stat_t stat[1];
    uv_statfs_t statfs[1];
    scandir_t dir[1];
    dnsinfo_t dns[1];
};

struct udp_packet_s {
    asio_types type;
    unsigned int flags;
    bool message_set;
    ssize_t nread;
    string_t message;
    uv_udp_t *handle;
    uv_args_t *args;
    sockaddr_t addr[1];
    uv_udp_send_t udp_req[1];
};

struct spawn_s {
    asio_types type;
    rid_t id;
    bool is_detach;
    routine_t *context;
    spawn_options_t *handle;
    uv_process_t process[1];
};

static char asio_powered_by[SCRAPE_SIZE] = nil;
static char asio_host[UV_MAXHOSTNAMESIZE] = nil;
static uv_fs_poll_t *fs_poll_create(void);
static uv_fs_event_t *fs_event_create(void);
static uv_tcp_t *tls_tcp_create(void_t extra);
static void_t fs_init(params_t);
static void_t uv_init(params_t);
static template uv_start(uv_args_t *uv_args, int type, size_t n_args, bool is_request);
static string stream_get(uv_stream_t *handle);
static udp_packet_t *udp_get(uv_udp_t *handle);
static void udp_packet_free(udp_packet_t *handle);
static void dummy_free(void_t ptr) {}

static RAII_INLINE uv_args_t *uv_server_data(void) {
    return (uv_args_t *)interrupt_data();
}

static RAII_INLINE void uv_log_error(int err) {
    cerr("Error: %s"CLR_LN"\r", uv_strerror(err));
}

static void_t asio_sockaddr(const char *host, int port, struct sockaddr_in6 *addr6, struct sockaddr_in *addr) {
    void_t addr_set = nullptr;
    int r = RAII_ERR;
    if (is_str_in(host, ":") && !(r = uv_ip6_addr(host, port, (struct sockaddr_in6 *)addr6))) {
        addr_set = addr6;
    } else if (is_str_in(host, ".") && !(r = uv_ip4_addr(host, port, (struct sockaddr_in *)addr))) {
        addr_set = addr;
    }

    if (r)
        return asio_abort(nullptr, r, coro_active());

    return addr_set;
}

static void uv_arguments_free(uv_args_t *self) {
    if (is_defined(self)) {
		if (!self->is_freeable) {
			array_delete(self->args);
			memset(self, RAII_ERR, sizeof(raii_type));
			RAII_FREE(self);
        }
    }
}

static uv_args_t *uv_arguments(int count, bool auto_free) {
    uv_args_t *uv_args = nullptr;
    arrays_t params = nullptr;
    if (auto_free) {
        uv_args = (uv_args_t *)calloc_local(1, sizeof(uv_args_t));
        params = arrays();
    } else {
        uv_args = (uv_args_t *)try_calloc(1, sizeof(uv_args_t));
        params = array_of(get_scope(), 0);
    }

    uv_args->n_args = count;
    uv_args->args = params;
    uv_args->is_freeable = auto_free;
    uv_args->is_server = false;
    uv_args->is_generator = false;
    uv_args->is_once = false;
    uv_args->is_working = false;
    uv_args->bind_type = RAII_NO_INSTANCE;
    uv_args->type = ASIO_ARGS;
    return uv_args;
}

static void fs_remove_pipe(uv_args_t *uv) {
    if (uv->bind_type == RAII_SCHEME_PIPE
        && !uv_fs_unlink(asio_loop(), &uv->fs_req, (string_t)uv->args[2].object, nullptr)) {
        uv_fs_req_cleanup(&uv->fs_req);
    }
}

static void uv_close_deferred(void_t handle) {
    if (is_pipe_stdin(handle)) {
        uv_close(handler(((pipe_in_t *)handle)->input), nullptr);
    } else if (is_pipe_stdout(handle)) {
        uv_close(handler(((pipe_out_t *)handle)->output), nullptr);
    } else if (is_pipe_file(handle)) {
        uv_close(handler(((pipe_file_t *)handle)->file), nullptr);
    } else if (is_tty_in(handle)) {
        uv_close(handler(((tty_in_t *)handle)->input), nullptr);
    } else if (is_tty_out(handle)) {
        uv_close(handler(((tty_out_t *)handle)->output), nullptr);
    } else if (is_tty_err(handle)) {
        uv_close(handler(((tty_err_t *)handle)->err), nullptr);
    } else if (is_pipepair(handle)) {
        pipepair_t *pair = (pipepair_t *)handle;
        uv_close(handler(pair->input), nullptr);
        uv_close(handler(pair->output), nullptr);
    } else if (is_socketpair(handle)) {
        socketpair_t *pair = (socketpair_t *)handle;
        uv_close(handler(pair->reader), nullptr);
        uv_close(handler(pair->writer), nullptr);
    } else {
        uv_close(handler(handle), nullptr);
    }

    RAII_FREE(handle);
}

static void _close_cb(uv_handle_t *handle) {
    if (!handle)
        return;

    memset(handle, 0, sizeof(uv_handle_t));
    RAII_FREE(handle);
}

static void uv_close_free(void_t handle) {
    uv_handle_t *h = handler(handle);
    if (!h || UV_UNKNOWN_HANDLE == h->type)
        return;

    if (!uv_is_closing(h))
        uv_close(h, _close_cb);
}

static void asio_closer(uv_args_t *uv) {
    if (uv->req_type == UV_GETNAMEINFO) {
        RAII_FREE(uv->args[0].object);
    } else if (uv->req_type == UV_GETADDRINFO) {
        uv_freeaddrinfo((addrinfo_t *)uv->args[0].object);
    } else {
        uv_close_free(uv->args[0].object);
    }

    uv_arguments_free(uv);
}

static void timer_cb(uv_timer_t *handle) {
    uv_args_t *uv = (uv_args_t *)uv_handle_get_data(handler(handle));
    uint64_t old = uv->args[2].max_size;
    routine_t *co = uv->context;
    uv_timer_stop(handle);
    coro_await_finish(co, nullptr, (uv_hrtime() - old), true);
}

static void fs_event_cleanup(uv_args_t *uv_args, routine_t *co, int status) {
    arrays_t arr = interrupt_array();
    i32 i, inset = interrupt_code();
    if (arr && inset) {
        for (i = 0; i < $size(arr); i = i + 3) {
            if ((uv_fs_type)arr[i].integer == uv_args->fs_type && (uv_args_t *)arr[i + 1].object == uv_args) {
                arr[i].integer = RAII_ERR;
                inset--;
                break;
            }
        }

        if (!inset) {
            array_delete(arr);
            interrupt_array_set(nullptr);
        }

        interrupt_code_set(inset);
    }

    asio_abort(nullptr, status, co);
    asio_closer(uv_args);
    coro_await_exit(co, nullptr, 0, false);
}

static void fs_event_cb(uv_fs_event_t *handle, string_t filename, int events, int status) {
    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    routine_t *co = (routine_t *)uv_args->context, *coro = coro_active();
    event_cb watchfunc = (event_cb)uv_args->args[2].func;
    void_t data = nullptr;
    uv_this_t this = nil;
    this.diff = sizeof(this.charaters) - 1;
    this.handle = handler(handle);

    if (status < 0) {
        uv_fs_event_stop(handle);
        fs_event_cleanup(uv_args, co, status);
    } else if ((events & UV_RENAME) || (events & UV_CHANGE)) {
        data = get_coro_data(coro);
        this.data = data;
        // Does not handle error if path is longer than 1023.
        uv_fs_event_getpath(handle, this.charaters, (size_t *)&this.diff);
        coro_data_set(coro, &this);
        watchfunc(filename, events, status);
        if (data == this.data)
            coro_data_set(coro, data);
    }
}

static RAII_INLINE void_t coro_fs_event(params_t args) {
    i32 num_args_set = interrupt_code();
    coro_name("fs_event #%d", coro_active_id());
    interrupt_code_set(++num_args_set);
    if (!interrupt_array()) {
        interrupt_array_set(array_of(coro_scope(), 3, UV_FS_EVENT, args->object, coro_active()));
    } else {
        $append_signed(interrupt_array(), UV_FS_EVENT);
        $append(interrupt_array(), args->object);
        $append(interrupt_array(), coro_active());
    }

    return uv_start((uv_args_t *)args->object, UV_FS_EVENT, 3, false).object;
}

static void fs_poll_cb(uv_fs_poll_t *handle, int status, const uv_stat_t *prev, const uv_stat_t *curr) {
    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    routine_t *co = (routine_t *)uv_args->context, *coro = coro_active();
    poll_cb pollerfunc = (poll_cb)uv_args->args[2].func;
    void_t data = nullptr;
    uv_this_t this = nil;
    this.diff = sizeof(this.charaters) - 1;
    this.handle = handler(handle);

    if (status < 0) {
        uv_fs_poll_stop(handle);
        fs_event_cleanup(uv_args, co, status);
    } else {
        data = get_coro_data(coro);
        this.data = data;
        // Does not handle error if path is longer than 1023.
        uv_fs_poll_getpath(handle, this.charaters, (size_t *)&this.diff);
        coro_data_set(coro, &this);
        pollerfunc(status, prev, curr);
        if (data == this.data)
            coro_data_set(coro, data);
    }
}

static RAII_INLINE void_t coro_fs_poll(params_t args) {
    i32 num_poll_set = interrupt_code();
    coro_name("fs_poll #%d", coro_active_id());
    interrupt_code_set(++num_poll_set);
    if (!interrupt_array()) {
        interrupt_array_set(array_of(coro_scope(), 3, UV_FS_POLL, args->object, coro_active()));
    } else {
        $append_signed(interrupt_array(), UV_FS_POLL);
        $append(interrupt_array(), args->object);
        $append(interrupt_array(), coro_active());
    }

    return uv_start((uv_args_t *)args->object, UV_FS_POLL, 4, false).object;
}

static template fs_start(uv_args_t *uv_args, uv_fs_type fs_type, size_t n_args, bool is_path) {
    uv_args->fs_type = fs_type;
    uv_args->n_args = n_args;
    uv_args->is_path = is_path;

    return coro_await(fs_init, 1, uv_args);
}

static template uv_start(uv_args_t *uv_args, int type, size_t n_args, bool is_request) {
    if (uv_args->is_request = is_request)
        uv_args->req_type = type;
    else
        uv_args->handle_type = type;

    uv_args->n_args = n_args;
    return coro_await(uv_init, 1, uv_args);
}

static void uv_catch_error(uv_args_t *uv) {
    routine_t *co = uv->context;
    string_t text = err_message();
    if (!is_empty((void_t)text) && raii_is_caught(get_coro_scope(co), text)) {
        coro_halt_set(co);
        coro_await_erred(co, get_coro_err(co));
	}

	if (uv->bind_type == UV_TLS)
		uv_tls_close(uv->tls);

	if (!uv->is_freeable)
        uv_arguments_free(uv);

    interrupt_data_set(nullptr);
}

static void connect_cb(uv_connect_t *client, int status) {
	uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(client));
	routine_t *co = uv->context;

    if (status < 0)
        uv_log_error(status);
    else
        uv_handle_set_data(handler(uv->args[0].object), (void_t)uv);

    coro_await_finish(co, nullptr, status, true);
}

static void on_connect(uv_connect_t *req, int status) {
	uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
	uv_tls_t *socket = uv->tls;

	if (status == 0) {
		socket->stream = req->handle;
		socket->data = (void_t)uv->ctx;
		socket->buf = nullptr;
		socket->is_client = true;
		socket->is_server = false;
		socket->is_connecting = true;
		socket->type = ASIO_TLS;
		status = uv_tls_connect((string_t)uv->args[3].char_ptr, socket);
		socket->is_connecting = false;
	}

	connect_cb(req, status);
}

static void connection_cb(uv_stream_t *server, int status) {
	uv_args_t *client_args, *uv = uv_handle_get_data(handler(server));
    routine_t *co = uv->context;
    uv_loop_t *uvLoop = asio_loop();
    void_t handle = nullptr;
    int result = status;

	if (status == 0) {
		if (uv->bind_type == UV_TLS) {
			handle = RAII_CALLOC(1, sizeof(uv_tcp_t));
			result = UV_ENOMEM;
			if (!is_empty(handle)) {
				client_args = uv_arguments(1, false);
				client_args->bind_type = UV_TLS;
				client_args->tls->stream = streamer(handle);
				client_args->tls->data = nullptr;
				client_args->tls->buf = nullptr;
				client_args->tls->err = 0;
				uv_handle_set_data(handler(client_args->tls->stream), (void_t)client_args);
				client_args->tls->is_client = true;
				client_args->tls->is_server= true;
				client_args->tls->is_connecting = true;
				client_args->tls->type = ASIO_TLS;
				result = uv_tls_accept(uv->tls, client_args->tls);
				client_args->tls->is_connecting = false;
				if (result) {
					uv_tls_close(client_args->tls);
					uv_close(handler(handle), nullptr);
					uv_arguments_free(client_args);
				}
			}

        } else if (uv->bind_type == RAII_SCHEME_TCP) {
            handle = RAII_CALLOC(1, sizeof(uv_tcp_t));
			result = uv_tcp_init(uvLoop, (uv_tcp_t *)handle);
        } else if (uv->bind_type == RAII_SCHEME_PIPE) {
            handle = RAII_CALLOC(1, sizeof(uv_pipe_t));
			result = uv_pipe_init(uvLoop, (uv_pipe_t *)handle, 0);
        }

		if (!result && (uv->bind_type != UV_TLS)) {
			if (!(result = uv_accept(server, streamer(handle))))
                uv_handle_set_data(handler(handle), (void_t)uv);
        }
    }

	if (result) {
		uv_log_error(result);
        if (!is_empty(handle))
            RAII_FREE(handle);

		coro_err_set(co, result);
    }

	coro_await_finish(co, ((result == 0) ? streamer(handle) : nullptr), result, false);
}

static void getnameinfo_cb(uv_getnameinfo_t *req, int status, string_t hostname, string_t service) {
    uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = uv->context;
    nameinfo_t *info = uv->dns->info;

    uv->args[0].object = req;
    if (status < 0) {
        info->type = RAII_ERR;
        asio_abort(nullptr, status, co);
        asio_closer(uv);
    } else {
        info->service = service;
        info->host = hostname;
        info->type = ASIO_NAME;
        raii_deferred(get_coro_scope(get_coro_context(co)), (func_t)asio_closer, uv);
    }

    coro_await_finish(co, info, status, false);
}

static void getaddrinfo_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = uv->context;
    addrinfo_t *next = nullptr;
    dnsinfo_t *dns = uv->dns;
    int count = 0;

    uv->args[0].object = res;
    if (status < 0) {
        dns->addr = nullptr;
        dns->type = RAII_ERR;
        asio_abort(nullptr, status, co);
        asio_closer(uv);
    } else {
        for (next = res->ai_next; next != nullptr; next = next->ai_next)
            count++;

        dns->addr = res;
        dns->count = count;
        dns->type = ASIO_DNS;
        addrinfo_next(dns);
        raii_deferred(get_coro_scope(get_coro_context(co)), (func_t)asio_closer, uv);
    }

    coro_await_finish(co, dns, status, false);
}

static void shutdown_cb(uv_shutdown_t *req, int status) {
    uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = uv->context;

    if (status < 0) {
        uv_log_error(status);
    }

    coro_await_finish(co, nullptr, status, true);
    RAII_FREE(req);
}

static void write_cb(uv_write_t *req, int status) {
    uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = uv->context;

    if (status < 0) {
        uv_log_error(status);
    }

    coro_await_finish(co, nullptr, status, true);
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = try_calloc(1, suggested_size + 1);
    buf->len = (unsigned int)suggested_size;
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    uv_args_t *uv = (uv_args_t *)uv_handle_get_data(handler(stream));
    routine_t *co = uv->context;

    if (nread < 0) {
        if (nread != UV_EOF)
            uv_log_error(nread);

        uv_read_stop(stream);
    } else if (nread > 0) {
        coro_await_finish(co, buf->base, nread, false);
        RAII_FREE(buf->base);
    }
}

static void udp_send_cb(uv_udp_send_t *req, int status) {
    uv_args_t *uv = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = uv->context;
    uv->args[0].object = req;
    if (status < 0) {
        uv_log_error(status);
    }

    coro_await_finish(co, nullptr, status, true);
}

static RAII_INLINE void fs_cleanup(uv_fs_t *req) {
    uv_args_t *args = (uv_args_t *)uv_req_get_data(requester(req));
    uv_fs_req_cleanup(req);
    uv_arguments_free(args);
}

static void fs_cb(uv_fs_t *req) {
    ssize_t result = uv_fs_get_result(req);
    uv_args_t *fs = (uv_args_t *)uv_req_get_data(requester(req));
    routine_t *co = fs->context;
    void_t fs_ptr, data = nullptr;
    uv_fs_type fs_type = UV_FS_CUSTOM;
    bool override = false;

	if (result < 0 && fs->fs_type != UV_FS_ACCESS) {
		asio_abort(nullptr, result, co);
    } else {
        fs_ptr = uv_fs_get_ptr(req);
        fs_type = uv_fs_get_type(req);

        switch (fs_type) {
            case UV_FS_CLOSE:
            case UV_FS_SYMLINK:
            case UV_FS_LINK:
            case UV_FS_CHMOD:
            case UV_FS_RENAME:
            case UV_FS_UNLINK:
            case UV_FS_RMDIR:
            case UV_FS_MKDIR:
            case UV_FS_CHOWN:
            case UV_FS_UTIME:
            case UV_FS_FUTIME:
            case UV_FS_FCHMOD:
            case UV_FS_FCHOWN:
            case UV_FS_FTRUNCATE:
            case UV_FS_FDATASYNC:
            case UV_FS_FSYNC:
            case UV_FS_OPEN:
            case UV_FS_MKSTEMP:
            case UV_FS_WRITE:
            case UV_FS_SENDFILE:
            case UV_FS_ACCESS:
            case UV_FS_COPYFILE:
                break;
            case UV_FS_SCANDIR:
                override = true;
                scandir_t *dirents = fs->dir;
                dirents->started = false;
                dirents->count = result;
                dirents->req = req;
                data = dirents;
                break;
            case UV_FS_STATFS:
                override = true;
                memcpy(fs->statfs, fs_ptr, sizeof(fs->statfs));
                data = fs->statfs;
                break;
            case UV_FS_LSTAT:
            case UV_FS_STAT:
            case UV_FS_FSTAT:
                override = true;
                memcpy(fs->stat, uv_fs_get_statbuf(req), sizeof(fs->stat));
                data = fs->stat;
                break;
            case UV_FS_MKDTEMP:
                override = true;
                data = (void_t)req->path;
                break;
            case UV_FS_READLINK:
            case UV_FS_REALPATH:
                override = true;
                data = fs_ptr;
                break;
            case UV_FS_READ:
                override = true;
                data = fs->buffer;
                break;
            case UV_FS_UNKNOWN:
            case UV_FS_CUSTOM:
            default:
                cerr("type: %d not supported."CLR_LN, fs_type);
                break;
        }
    }

    coro_await_finish(co, data, result, !override);
    if (fs_type != UV_FS_SCANDIR) {
        if (fs_type == UV_FS_READ)
			RAII_FREE(fs->bufs.base);

		fs_cleanup(req);
    }
}

static void_t fs_init(params_t uv_args) {
    uv_loop_t *uvLoop = asio_loop();
    uv_args_t *fs = uv_args->object;
    uv_fs_t *req = &fs->fs_req;
    arrays_t args = fs->args;
    routine_t *co = coro_active();
    int result = UV_ENOENT;

    if (fs->is_path) {
        string_t path = args[0].char_ptr;
        switch (fs->fs_type) {
            case UV_FS_OPEN:
                result = uv_fs_open(uvLoop, req, path, args[1].integer, args[2].integer, fs_cb);
                break;
            case UV_FS_UNLINK:
                result = uv_fs_unlink(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_MKDIR:
                result = uv_fs_mkdir(uvLoop, req, path, args[1].integer, fs_cb);
                break;
            case UV_FS_RMDIR:
                result = uv_fs_rmdir(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_RENAME:
                result = uv_fs_rename(uvLoop, req, path, args[1].char_ptr, fs_cb);
                break;
            case UV_FS_ACCESS:
                result = uv_fs_access(uvLoop, req, path, args[1].integer, fs_cb);
                break;
            case UV_FS_COPYFILE:
                result = uv_fs_copyfile(uvLoop, req, path, args[1].char_ptr, args[2].integer, fs_cb);
                break;
            case UV_FS_CHMOD:
                result = uv_fs_chmod(uvLoop, req, path, args[1].integer, fs_cb);
                break;
            case UV_FS_UTIME:
                result = uv_fs_utime(uvLoop, req, path, args[1].precision, args[2].precision, fs_cb);
                break;
            case UV_FS_CHOWN:
                result = uv_fs_chown(uvLoop, req, path, (uv_uid_t)args[1].uchar, (uv_uid_t)args[2].uchar, fs_cb);
                break;
            case UV_FS_LINK:
                result = uv_fs_link(uvLoop, req, path, (string_t)args[1].char_ptr, fs_cb);
                break;
            case UV_FS_SYMLINK:
                result = uv_fs_symlink(uvLoop, req, path, (string_t)args[1].char_ptr, args[2].integer, fs_cb);
                break;
            case UV_FS_LSTAT:
                result = uv_fs_lstat(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_STAT:
                result = uv_fs_stat(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_STATFS:
                result = uv_fs_statfs(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_SCANDIR:
                result = uv_fs_scandir(uvLoop, req, path, args[1].integer, fs_cb);
                break;
            case UV_FS_MKDTEMP:
                result = uv_fs_mkdtemp(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_MKSTEMP:
                result = uv_fs_mkstemp(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_READLINK:
                result = uv_fs_readlink(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_REALPATH:
                result = uv_fs_realpath(uvLoop, req, path, fs_cb);
                break;
            case UV_FS_UNKNOWN:
            case UV_FS_CUSTOM:
            default:
                cerr("type: %d not supported."CLR_LN, fs->fs_type);
                break;
        }
    } else {
        uv_file fd = args[0].integer;
        switch (fs->fs_type) {
            case UV_FS_FSTAT:
                result = uv_fs_fstat(uvLoop, req, fd, fs_cb);
                break;
            case UV_FS_SENDFILE:
                result = uv_fs_sendfile(uvLoop, req, fd, args[1].integer, args[2].long_long, args[3].max_size, fs_cb);
                break;
            case UV_FS_CLOSE:
                result = uv_fs_close(uvLoop, req, fd, fs_cb);
                break;
            case UV_FS_FSYNC:
                result = uv_fs_fsync(uvLoop, req, fd, fs_cb);
                break;
            case UV_FS_FDATASYNC:
                result = uv_fs_fdatasync(uvLoop, req, fd, fs_cb);
                break;
            case UV_FS_FTRUNCATE:
                result = uv_fs_ftruncate(uvLoop, req, fd, args[1].long_long, fs_cb);
                break;
            case UV_FS_FCHMOD:
                result = uv_fs_fchmod(uvLoop, req, fd, args[1].integer, fs_cb);
                break;
            case UV_FS_FUTIME:
                result = uv_fs_futime(uvLoop, req, fd, args[1].precision, args[2].precision, fs_cb);
                break;
            case UV_FS_FCHOWN:
                result = uv_fs_fchown(uvLoop, req, fd, (uv_uid_t)args[1].uchar, (uv_uid_t)args[2].uchar, fs_cb);
                break;
            case UV_FS_READ:
                result = uv_fs_read(uvLoop, req, fd, &fs->bufs, 1, args[1].long_long, fs_cb);
                break;
            case UV_FS_WRITE:
                result = uv_fs_write(uvLoop, req, fd, &fs->bufs, 1, args[1].long_long, fs_cb);
                break;
            case UV_FS_UNKNOWN:
            case UV_FS_CUSTOM:
            default:
                cerr("type; %d not supported."CLR_LN, fs->fs_type);
                break;
        }
    }

    if (result) {
        return asio_abort(nullptr, result, co);
    }

    fs->context = co;
    uv_req_set_data(requester(req), (void_t)fs);
    return 0;
}

static void_t uv_init(params_t uv_args) {
    uv_args_t *uv = uv_args->object;
    arrays_t args = uv->args;
    int length, r, result = UV_EBADF;
    uv_handle_t *stream = args[0].object;
    char name[SCRAPE_SIZE * 2] = nil;
    routine_t *co = uv->context;
    uv->context = coro_active();
    if (uv->is_request) {
        uv_req_t *req;
        switch (uv->req_type) {
            case UV_WRITE:
                req = (uv_req_t *)&uv->write_req;
                result = uv_write((uv_write_t *)req, streamer(stream), &uv->bufs, 1, write_cb);
                break;
            case UV_CONNECT:
                req = (uv_req_t *)&uv->connect_req;
                switch (uv->bind_type) {
                    case RAII_SCHEME_PIPE:
                        uv->handle_type = UV_NAMED_PIPE;
                        uv_pipe_connect((uv_connect_t *)req, (uv_pipe_t *)stream, (string_t)args[1].char_ptr, connect_cb);
                        result = 0;
                        break;
					case UV_TLS:
						result = uv_tcp_connect((uv_connect_t *)req, (uv_tcp_t *)stream, (sockaddr_t *)args[1].object, on_connect);
                        break;
                    default:
                        uv->handle_type = UV_TCP;
                        result = uv_tcp_connect((uv_connect_t *)req, (uv_tcp_t *)stream, (sockaddr_t *)args[1].object, connect_cb);
                        break;
                }
                break;
            case UV_UDP_SEND:
                req = args[0].object;
                result = uv_udp_send((uv_udp_send_t *)req, (uv_udp_t *)args[1].object,
                                     &uv->bufs, 1, (sockaddr_t *)args[2].object, udp_send_cb);
                break;
            case UV_SHUTDOWN:
                req = (uv_req_t *)&uv->shutdown_req;
                if (result = uv_shutdown((uv_shutdown_t *)req, streamer(stream), shutdown_cb))
                    RAII_FREE(req);
                break;
            case UV_WORK:
                break;
            case UV_GETADDRINFO:
                req = (uv_req_t *)&uv->addinfo_req;
                result = uv_getaddrinfo(asio_loop(), (uv_getaddrinfo_t *)req,
                                        getaddrinfo_cb, args[0].char_ptr, args[1].char_ptr,
                                        (uv->n_args > 2 ? (const addrinfo_t *)args[2].object : nullptr));
                if (result) {
                    uv_arguments_free(uv);
                }
                break;
            case UV_GETNAMEINFO:
                req = try_calloc(1, sizeof(uv_getnameinfo_t));
                result = uv_getnameinfo(asio_loop(), (uv_getnameinfo_t *)req,
                                        getnameinfo_cb, (sockaddr_t *)args[0].object,
                                        args[1].integer);
                if (result) {
                    uv->args[0].object = req;
                    asio_closer(uv);
                }
                break;
            case UV_RANDOM:
                break;
            case UV_UNKNOWN_REQ:
            default:
                cerr("type; %d not supported."CLR_LN, uv->req_type);
                break;
        }

		if (!result)
            uv_req_set_data(req, (void_t)uv);
    } else {
        if (uv->bind_type != UV_TLS)
            uv_handle_set_data(stream, (void_t)uv);

        switch (uv->handle_type) {
            case UV_FS_EVENT:
                result = uv_fs_event_start((uv_fs_event_t *)stream, fs_event_cb, args[1].char_ptr, UV_FS_EVENT_RECURSIVE);
                break;
            case UV_FS_POLL:
                result = uv_fs_poll_start((uv_fs_poll_t *)stream, fs_poll_cb, args[1].char_ptr, args[3].integer);
                break;
            case UV_CHECK:
            case UV_IDLE:
            case UV_NAMED_PIPE:
            case UV_POLL:
            case UV_PREPARE:
                break;
            case UV_HANDLE_TYPE_MAX:
				if (!(result = uv_listen(streamer(stream), args[1].integer, connection_cb))) {
                    length = (int)sizeof(uv->dns->name);
                    switch (uv->bind_type) {
                        case RAII_SCHEME_PIPE:
                            length = (int)sizeof(name);
                            r = uv_pipe_getsockname((const uv_pipe_t *)args[0].object, name, (size_t *)&length);
                            if (!is_equal(name, args[2].object)
                                && (r = snprintf(name, sizeof(name), "%s", args[2].char_ptr)))
                                r = 0;
                            break;
                        default:
                            r = uv_tcp_getsockname((const uv_tcp_t *)stream, uv->dns->name, &length);
                            break;
                    }

                    if (!r && uv->bind_type != RAII_SCHEME_PIPE) {
                        if (is_str_in(args[3].char_ptr, ":")) {
                            uv_ip6_name((const struct sockaddr_in6 *)uv->dns->name, uv->dns->ip, sizeof uv->dns->ip);
                        } else if (is_str_in(args[3].char_ptr, ".")) {
                            uv_ip4_name((const struct sockaddr_in *)uv->dns->name, uv->dns->ip, sizeof uv->dns->ip);
                        }
                    }

                    fprintf(stdout, "Listening to %s:%d for%s connections, %s."CLR_LN,
                            (uv->bind_type == RAII_SCHEME_PIPE ? name : uv->dns->ip),
                            args[4].integer,
                            (uv->bind_type == UV_TLS ? " secure" : ""),
                            http_std_date(0)
                    );

                    if (is_empty(uv_server_data()))
                        interrupt_data_set(uv);
                }
                break;
            case UV_STREAM:
				result = uv_read_start((uv_stream_t *)stream, alloc_cb, read_cb);
                break;
            case UV_TIMER:
                defer((func_t)asio_closer, uv);
                result = uv_timer_start((uv_timer_t *)args[0].object, timer_cb, args[1].ulong_long, 0);
                break;
            case UV_HANDLE:
            case UV_PROCESS:
            case UV_TCP:
            case UV_TTY:
            case UV_UDP:
            case UV_SIGNAL:
            case UV_FILE:
                break;
            case UV_UNKNOWN_HANDLE:
            default:
                cerr("type; %d not supported."CLR_LN, uv->handle_type);
                break;
        }
    }

	if (result) {
		uv_log_error(result);
		if (is_coroutine(uv->context))
			coro_await_canceled(uv->context, result);
    }

    return 0;
}

uv_file fs_open(string_t path, int flags, int mode) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_signed(uv_args->args, flags);
    $append_signed(uv_args->args, mode);

    return (uv_file)fs_start(uv_args, UV_FS_OPEN, 3, true).integer;
}

int fs_unlink(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return fs_start(uv_args, UV_FS_UNLINK, 1, true).integer;
}

int fs_mkdir(string_t path, int mode) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_signed(uv_args->args, (mode ? mode : 0755));

    return fs_start(uv_args, UV_FS_MKDIR, 2, true).integer;
}

int fs_rmdir(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return fs_start(uv_args, UV_FS_RMDIR, 1, true).integer;
}

int fs_rename(string_t path, string_t new_path) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_string(uv_args->args, new_path);

    return fs_start(uv_args, UV_FS_RENAME, 2, true).integer;
}

int fs_link(string_t path, string_t new_path) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_string(uv_args->args, new_path);

    return fs_start(uv_args, UV_FS_LINK, 2, true).integer;
}

scandir_t *fs_scandir(string_t path, int flags) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_signed(uv_args->args, flags);

    return (scandir_t *)fs_start(uv_args, UV_FS_SCANDIR, 2, true).object;
}

uv_dirent_t *fs_scandir_next(scandir_t *dir) {
    if (!dir->started) {
        dir->started = true;
        defer((func_t)fs_cleanup, dir->req);
    }

    if (UV_EOF != uv_fs_scandir_next(dir->req, dir->item))
        return dir->item;

    return nullptr;
}

uv_stat_t *fs_fstat(uv_file fd) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append(uv_args->args, casting(fd));

    return (uv_stat_t *)fs_start(uv_args, UV_FS_FSTAT, 1, false).object;
}

int fs_fsync(uv_file fd) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append(uv_args->args, casting(fd));

    return fs_start(uv_args, UV_FS_FSYNC, 1, false).integer;
}

int fs_fdatasync(uv_file fd) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append(uv_args->args, casting(fd));

    return fs_start(uv_args, UV_FS_FDATASYNC, 1, false).integer;
}

int fs_ftruncate(uv_file fd, int64_t offset) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append(uv_args->args, casting(fd));
    $append_signed(uv_args->args, offset);

    return fs_start(uv_args, UV_FS_FTRUNCATE, 2, false).integer;
}

int fs_fchmod(uv_file fd, int mode) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append(uv_args->args, casting(fd));
    $append_signed(uv_args->args, mode);

    return fs_start(uv_args, UV_FS_FCHMOD, 2, false).integer;
}

int fs_fchown(uv_file fd, uv_uid_t uid, uv_gid_t gid) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append(uv_args->args, casting(fd));
    $append_char(uv_args->args, uid);
    $append_char(uv_args->args, gid);

    return fs_start(uv_args, UV_FS_FCHOWN, 3, false).integer;
}

int fs_futime(uv_file fd, double atime, double mtime) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append(uv_args->args, casting(fd));
    $append_double(uv_args->args, atime);
    $append_double(uv_args->args, mtime);

    return fs_start(uv_args, UV_FS_FUTIME, 3, false).integer;
}

int fs_chmod(string_t path, int mode) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_signed(uv_args->args, mode);

    return fs_start(uv_args, UV_FS_CHMOD, 2, true).integer;
}

int fs_utime(string_t path, double atime, double mtime) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_double(uv_args->args, atime);
    $append_double(uv_args->args, mtime);

    return fs_start(uv_args, UV_FS_UTIME, 3, false).integer;
}

int fs_lutime(string_t path, double atime, double mtime) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_double(uv_args->args, atime);
    $append_double(uv_args->args, mtime);

    return fs_start(uv_args, UV_FS_LUTIME, 3, false).integer;
}

int fs_chown(string_t path, uv_uid_t uid, uv_gid_t gid) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_char(uv_args->args, uid);
    $append_char(uv_args->args, gid);

    return fs_start(uv_args, UV_FS_CHOWN, 3, false).integer;
}

int fs_lchown(string_t path, uv_uid_t uid, uv_gid_t gid) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_char(uv_args->args, uid);
    $append_char(uv_args->args, gid);

    return fs_start(uv_args, UV_FS_LCHOWN, 3, false).integer;
}

int fs_sendfile(uv_file out_fd, uv_file in_fd, int64_t in_offset, size_t length) {
    uv_args_t *uv_args = uv_arguments(4, false);
    $append(uv_args->args, casting(out_fd));
    $append(uv_args->args, casting(in_fd));
    $append_signed(uv_args->args, in_offset);
    $append_unsigned(uv_args->args, length);

    return fs_start(uv_args, UV_FS_SENDFILE, 4, false).integer;
}

int fs_access(string_t path, int mode) {
    uv_args_t *uv_args = uv_arguments(2, false);
    $append_string(uv_args->args, path);
    $append_signed(uv_args->args, mode);

    return fs_start(uv_args, UV_FS_ACCESS, 2, true).integer;
}

int fs_copyfile(string_t path, string_t new_path, int flags) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_string(uv_args->args, new_path);
    $append_signed(uv_args->args, flags);

    return fs_start(uv_args, UV_FS_COPYFILE, 3, true).integer;
}

int fs_symlink(string_t path, string_t new_path, int flags) {
    uv_args_t *uv_args = uv_arguments(3, false);
    $append_string(uv_args->args, path);
    $append_string(uv_args->args, new_path);
    $append_signed(uv_args->args, flags);

    return fs_start(uv_args, UV_FS_SYMLINK, 3, true).integer;
}

string fs_readlink(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return fs_start(uv_args, UV_FS_READLINK, 1, true).char_ptr;
}

string fs_realpath(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return fs_start(uv_args, UV_FS_REALPATH, 1, true).char_ptr;
}

uv_stat_t *fs_stat(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return (uv_stat_t *)fs_start(uv_args, UV_FS_STAT, 1, true).object;
}

uv_stat_t *fs_lstat(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return (uv_stat_t *)fs_start(uv_args, UV_FS_LSTAT, 1, true).object;
}

uv_statfs_t *fs_statfs(string_t path) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, path);

    return (uv_statfs_t *)fs_start(uv_args, UV_FS_STATFS, 1, true).object;
}

uv_file fs_mkstemp(string tpl) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, tpl);

    return (uv_file)fs_start(uv_args, UV_FS_MKSTEMP, 1, true).integer;
}

string fs_mkdtemp(string tpl) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append_string(uv_args->args, tpl);

    return fs_start(uv_args, UV_FS_MKDTEMP, 1, true).char_ptr;
}

RAII_INLINE bool file_exists(string_t path) {
    return fs_access(path, F_OK) == 0;
}

RAII_INLINE size_t file_size(string_t path) {
    uv_stat_t *stat = fs_stat(path);
    if (!is_empty(stat))
        return (size_t)stat->st_size;

    return 0;
}

RAII_INLINE bool fs_touch(string_t filepath) {
	return fs_writefile(filepath, "") == 0;
}

string fs_read(uv_file fd, int64_t offset) {
    uv_stat_t *stat = fs_fstat(fd);
    uv_args_t *uv_args = uv_arguments(2, false);
    size_t sz = (size_t)stat->st_size;

    uv_args->buffer = try_calloc(1, sz + 1);
    uv_args->bufs = uv_buf_init(uv_args->buffer, (unsigned int)sz);
    $append(uv_args->args, casting(fd));
    $append_signed(uv_args->args, offset);

    return fs_start(uv_args, UV_FS_READ, 2, false).char_ptr;
}

int fs_write(uv_file fd, string_t text, int64_t offset) {
    size_t size = simd_strlen(text);
    uv_args_t *uv_args = uv_arguments(2, false);

    uv_args->bufs = uv_buf_init((string)text, (unsigned int)size);
    $append(uv_args->args, casting(fd));
    $append_signed(uv_args->args, offset);

    return fs_start(uv_args, UV_FS_WRITE, 2, false).integer;
}

int fs_close(uv_file fd) {
    uv_args_t *uv_args = uv_arguments(1, false);
    $append(uv_args->args, casting(fd));

    return fs_start(uv_args, UV_FS_CLOSE, 1, false).integer;
}

string fs_readfile(string_t path) {
    uv_file fd = fs_open(path, O_RDONLY, 0);
    if (fd > 0) {
        string file = fs_read(fd, -1);
        fs_close(fd);

        return file;
    }

    return nullptr;
}

int fs_writefile(string_t path, string_t text) {
	int status = 0;
	uv_file fd = fs_open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd > 0) {
        if ((status = (int)simd_strlen(text)) > 0)
            status = fs_write(fd, text, -1);

        if (!fs_close(fd))
            return status;
    }

    return coro_err_code();
}

RAII_INLINE string_t fs_poll_path(void) {
    return fs_watch_path();
}

RAII_INLINE bool fs_poll_stop(void) {
    void_t data = get_coro_data(coro_active());
    bool status = false;
    if (!is_empty(data)) {
        uv_this_t *this = (uv_this_t *)data;
        uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(this->handle);
        status = uv_fs_poll_stop((uv_fs_poll_t *)this->handle);
        coro_data_set(coro_active(), this->data);
        fs_event_cleanup(uv_args, uv_args->context, (status == 0 ? UV_ECANCELED : status));
    }

    return status == 0;
}

void fs_poll(string_t path, poll_cb pollfunc, int interval) {
    uv_fs_poll_t *poll = fs_poll_create();
    if (is_empty(poll))
        raii_panic("Initialization failed: `fs_poll_create`");

    uv_args_t *uv_args = uv_arguments(4, false);
    $append(uv_args->args, poll);
    $append_string(uv_args->args, path);
    $append_func(uv_args->args, pollfunc);
    $append_signed(uv_args->args, interval);
    coro_launch(coro_fs_poll, 1, uv_args);
}

RAII_INLINE string_t fs_watch_path(void) {
    void_t data = coro_data();
    if (is_empty(data))
        return "";

    uv_this_t *this = (uv_this_t *)data;
    return (string_t)this->charaters;
}

RAII_INLINE bool fs_watch_stop(void) {
    void_t data = coro_data();
    bool status = false;
    if (!is_empty(data)) {
        uv_this_t *this = (uv_this_t *)data;
        uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(this->handle);
        status = uv_fs_event_stop((uv_fs_event_t *)this->handle);
        coro_data_set(coro_active(), this->data);
        fs_event_cleanup(uv_args, uv_args->context, (status == 0 ? UV_ECANCELED : status));
    }

    return status == 0;
}

void fs_watch(string_t path, event_cb watchfunc) {
    uv_fs_event_t *event = fs_event_create();
    if (is_empty(event))
        raii_panic("Initialization failed: `fs_event_create`");

    uv_args_t *uv_args = uv_arguments(3, false);
    $append(uv_args->args, event);
    $append_string(uv_args->args, path);
    $append_func(uv_args->args, watchfunc);
    coro_launch(coro_fs_event, 1, uv_args);
}

dnsinfo_t *get_addrinfo(string_t address, string_t service, u32 numhints_pair, ...) {
    uv_args_t *uv_args = uv_arguments(3, false);
    ai_hints_types k;
    int hint, i, count = 2;
    va_list ap;
    addrinfo_t *hints = nullptr;
    $append_string(uv_args->args, address);
    $append_string(uv_args->args, service);
    if (numhints_pair > 0) {
        hints = uv_args->dns->original;
        va_start(ap, numhints_pair);
        for (i = 0; i < (int)numhints_pair; i++) {
            k = va_arg(ap, ai_hints_types);
            hint = va_arg(ap, int);
            switch (k) {
                case ai_family: hints->ai_family = hint; break;
                case ai_socktype: hints->ai_socktype = hint; break;
                case ai_protocol: hints->ai_protocol = hint; break;
                case ai_flags: hints->ai_flags = hint; break;
            }
        }
        va_end(ap);
        $append(uv_args->args, hints);
        count++;
    }

    return (dnsinfo_t *)uv_start(uv_args, UV_GETADDRINFO, count, true).object;
}

RAII_INLINE string_t addrinfo_ip(dnsinfo_t *dns) {
    if (is_addrinfo(dns))
        return (string_t)(dns->is_ip6 ? dns->ip6_addr : dns->ip_addr);

    return nullptr;
}

addrinfo_t *addrinfo_next(dnsinfo_t *dns) {
    if (is_addrinfo(dns) && !is_empty(dns->addr)) {
        addrinfo_t *dir = dns->addr;
        int ip = RAII_ERR;
        *dns->original = *dns->addr;
        if (dir->ai_canonname)
            dns->ip_name = dir->ai_canonname;

        if (dir->ai_family == AF_INET) {
            dns->is_ip6 = false;
            if (is_zero(ip = uv_ip4_name((const struct sockaddr_in *)dir->ai_addr, dns->ip, INET_ADDRSTRLEN)))
                dns->ip_addr = dns->ip;
        } else if (dir->ai_family == AF_INET6) {
            dns->is_ip6 = true;
            if (is_zero(ip = uv_ip6_name((const struct sockaddr_in6 *)dir->ai_addr, dns->ip, INET6_ADDRSTRLEN)))
                dns->ip6_addr = dns->ip;
        }

        if (ip) {
            uv_log_error(ip);
            return nullptr;
        }

        dns->addr = dir->ai_next;
        return dns->addr;
    }

    return nullptr;
}

nameinfo_t *get_nameinfo(string_t addr, int port, int flags) {
    uv_args_t *uv_args = uv_arguments(2, false);
    void_t addr_set = asio_sockaddr(addr, port, uv_args->dns->in6, uv_args->dns->in4);

    if (addr_set) {
        $append(uv_args->args, addr_set);
        $append_signed(uv_args->args, flags);
        return (nameinfo_t *)uv_start(uv_args, UV_GETNAMEINFO, 2, true).object;
    } else {
        uv_arguments_free(uv_args);
        return nullptr;
    }
}

static void queue_after_wrapper(uv_work_t *req, int status) {
	uv_args_t *uv_args = (uv_args_t *)uv_req_get_data(requester(req));
	future fut = (future)uv_args->args[1].object;
	if (!status && $size(uv_args->args) > 2) {
		queue_cb after_work = (queue_cb)uv_args->args[2].func;
		after_work((vectors_t)fut->value->result->value.object);
	}

	queue_delete(fut);
	uv_args->is_working = false;
}

static void queue_work_wrapper(uv_work_t *req) {
	uv_args_t *uv_args = (uv_args_t *)uv_req_get_data(requester(req));
	args_t args = (args_t)uv_args->args[0].object;
	future f = (future)uv_args->args[1].object;

	/* Wait for start signal */
	while (!atomic_flag_load_explicit(&f->started, memory_order_relaxed))
		;

	guarding(f, args);
}

static void_t queue_work_ex(params_t args) {
	uv_args_t *uv_args = args->object;
	future f = (future)uv_args->args[1].object;
	coro_name("queue_work #%d", coro_active_id());
	defer((func_t)uv_arguments_free, uv_args);
	defer((func_t)promise_close, f->value);
	int r = uv_queue_work(asio_loop(), &uv_args->work_req, queue_work_wrapper, queue_after_wrapper);
	if (r) {
		promise_set(f->value, nullptr);
		queue_after_wrapper(&uv_args->work_req, r);
		return asio_abort(nullptr, r, coro_active());
	}

	uv_args->is_working = true;
	yield();
	while (uv_args->is_working)
		coro_yield_info();

	yield();
	return nullptr;
}

void queue_delete(future f) {
	if (is_future(f)) {
		f->type = RAII_ERR;
		if (!is_empty(f->scope))
			raii_deferred_free(f->scope);

		RAII_FREE(f);
	}
}

void queue_wait(arrays_t work) {
	yield();
	while ($size(work) > 0) {
		foreach(worker in work) {
			if (!queue_is_valid(worker.object)) {
				$erase(work, iworker);
			}
		}
		iworker = 0;
		yield();
	}
}

RAII_INLINE bool queue_is_valid(future f) {
	return is_future(f) && is_defined(f->scope->arena)
		&& ((uv_args_t *)f->scope->arena)->is_working;
}

future queue_work(thrd_func_t fn, size_t num_args, ...) {
	uv_args_t *uv_args = uv_arguments(2, false);
	va_list ap;

	va_start(ap, num_args);
	args_t args = args_ex(num_args, ap);
	va_end(ap);

	promise *p = promise_create(get_scope());
	future f = future_create(fn);
	f->value = p;
	f->scope = vector_scope(args);
	f->scope->arena = (void_t)uv_args;
	$append(uv_args->args, args);
	$append(uv_args->args, f);
	uv_req_set_data(requester(&uv_args->work_req), (void_t)uv_args);
	coro_launch(queue_work_ex, 1, uv_args);
	return f;
}

template_t queue_get(void_t queue) {
	promise *p = nullptr;
	future f = nullptr;
	if (is_future(queue) || is_promise(queue)) {
		if (is_future(queue)) {
			f = (future)queue;
			if (is_promise(f->value)) {
				p = (promise *)f->value;
				atomic_flag_test_and_set(&f->started);
			}
		} else if (is_promise(queue)) {
			p = (promise *)queue;
		}

		if (!is_empty(p)) {
			while (!atomic_flag_load(&p->done))
				coro_yield_info();

			return p->result->value;
		}
	}

	throw(logic_error);
}

RAII_INLINE promise *queue_then(future work, queue_cb callback) {
	uv_args_t *uv_args = (uv_args_t *)work->scope->arena;
	$append_func(uv_args->args, callback);
	atomic_flag_test_and_set(&work->started);

	return work->value;
}

static void_t stream_client(params_t args) {
    uv_stream_t *client = (uv_stream_t *)args[0].object;
    stream_cb handlerFunc = (stream_cb)args[1].func;
	uv_args_t *uv = (uv_args_t *)uv_handle_get_data(handler(client));
	uv_tls_t *tls = uv->tls;
	bool is_tls = false;

	if (uv->bind_type == UV_TLS) {
		is_tls = true;
		defer((func_t)uv_arguments_free, uv);
		defer(uv_close_deferred, client);
		defer((func_t)uv_tls_close, tls);
	} else {
        uv_handle_set_data(handler(client), nullptr);
        defer(uv_close_free, client);
    }

	handlerFunc(client);
	return 0;
}

RAII_INLINE void stream_handler(stream_cb connected, uv_stream_t *client) {
    launch((func_t)stream_client, 2, client, connected);
}

int stream_write(uv_stream_t *handle, string_t data) {
    if (is_empty(handle))
        return RAII_ERR;

    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
	if (is_defined(uv_args)) {
		if ((!uv_is_writable(handle) || uv_is_closing(handler(handle))))
			return UV_EBADF;

		uv_args->args[0].object = handle;
	} else {
		uv_args = uv_arguments(1, true);
		uv_args->tls->stream = handle;
        $append(uv_args->args, handle);
        uv_handle_set_data(handler(handle), (void_t)uv_args);
    }

    size_t size = simd_strlen(data);
    uv_args->bufs = uv_buf_init((string)data, (unsigned int)size);

	if (uv_args->bind_type == UV_TLS)
		return uv_tls_write(uv_args->tls, uv_args->bufs.base, uv_args->bufs.len);

	return uv_start(uv_args, UV_WRITE, 1, true).integer;
}

RAII_INLINE string stream_read_wait(uv_stream_t *handle) {
    if (is_empty(handle))
        return nullptr;

    uv_args_t *uv_args = nullptr;
    void_t check = uv_handle_get_data(handler(handle));
    if (is_empty(check)) {
		uv_args = uv_arguments(1, true);
		uv_args->tls->stream = handle;
        $append(uv_args->args, handle);
        uv_handle_set_data(handler(handle), (void_t)uv_args);
    } else {
        uv_args = (uv_args_t *)check;
        uv_args->args[0].object = handle;
    }

    return uv_start(uv_args, UV_STREAM, 1, false).char_ptr;
}

RAII_INLINE string stream_read_once(uv_stream_t *handle) {
    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    if (!is_defined(uv_args))
        throw(logic_error);

    uv_args->is_once = true;
    return stream_get(handle);
}

RAII_INLINE string stream_read(uv_stream_t *handle) {
    return stream_get(handle);
}

static void read_generator_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    uv_args_t *uv = (uv_args_t *)uv_handle_get_data(handler(stream));
    routine_t *co = uv->context;

    if (nread < 0) {
        if (nread != UV_EOF)
            uv_log_error(nread);

        uv_read_stop(stream);
        if (buf->base)
            RAII_FREE(buf->base);

        coro_await_erred(co, nread);
        coro_await_exit(co, nullptr, nread, false);
    } else if (nread > 0) {
        uv->bufs.base = buf->base;
        uv->bufs.len = buf->len;
        coro_await_yield(co, buf->base, nread, false, true);
        RAII_FREE(buf->base);
        uv->bufs.base = nullptr;
        if (uv->is_once)
            coro_await_exit(co, nullptr, nread, false);
    }
}

static void_t stream_yield(params_t args) {
    uv_args_t *uv = args->object;
    uv_handle_t *stream = uv->args[0].object;
    routine_t *co = coro_active();
    int result = 0;
    uv->context = co;

    if (!uv->is_freeable)
        defer((func_t)uv_arguments_free, uv);
    uv_handle_set_data(stream, (void_t)uv);

    if (result = uv_read_start(streamer(stream), alloc_cb, read_generator_cb)) {
        return asio_abort(nullptr, result, co);
    }

    yield();
    while (!coro_terminated(co)) {
        if (!is_empty(uv->bufs.base) && uv->bufs.len > 0)
            yielding(uv->bufs.base);
        else
            coro_yield_info();
    }

    uv_read_stop(streamer(stream));
    return 0;
}

RAII_INLINE tls_state *get_handle_tls_state(void_t handle) {
	return ((uv_args_t *)uv_handle_get_data(handler(handle)))->state;
}

RAII_INLINE uv_tls_t *get_handle_tls_socket(void_t handle) {
	return ((uv_args_t *)uv_handle_get_data(handler(handle)))->tls;
}

RAII_INLINE bool stream_canceled(uv_stream_t *handle) {
	uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
	if (is_defined(uv_args)) {
		coro_halt_set(uv_args->context);
		return true;
	}

	return false;
}

static string stream_get(uv_stream_t *handle) {
    if (is_empty(handle))
        return nullptr;

    generator_t gen = nullptr;
    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
	if (is_defined(uv_args) && uv_args->is_generator) {
		uv_args->args[0].object = handle;
		gen = get_coro_generator(uv_args->context);
    } else {
		if (is_defined(uv_args)) {
			uv_args->args[0].object = handle;
			if (uv_args->bind_type == UV_TLS)
				return uv_tls_read(uv_args->tls);
        } else if (is_empty(uv_args)) {
			uv_args = uv_arguments(1, false);
			uv_args->tls->stream = handle;
            uv_args->bind_type = RAII_NO_INSTANCE;
            $append(uv_args->args, handle);
        } else if (is_undefined(uv_args)) {
            return nullptr;
        }

		uv_args->is_generator = true;
		gen = generator(stream_yield, 1, uv_args);
		uv_handle_set_data(handler(handle), (void_t)uv_args);
    }

    return yield_for(gen).char_ptr;
}

sockaddr_t *sockaddr(string_t host, int port) {
	uv_args_t *uv_args = uv_arguments(0, true);
	return (sockaddr_t *)asio_sockaddr(host, port, uv_args->dns->in6, uv_args->dns->in4);
}

int stream_shutdown(uv_stream_t *handle) {
    if (is_empty(handle))
        return coro_err_code();

    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    if (is_defined(uv_args)) {
        uv_args->args[0].object = handle;
    } else {
		uv_args = uv_arguments(1, true);
		uv_args->tls->stream = handle;
        $append(uv_args->args, handle);
        uv_handle_set_data(handler(handle), (void_t)uv_args);
    }

    return uv_start(uv_args, UV_SHUTDOWN, 1, true).integer;
}

uv_stream_t *stream_connect(string_t address) {
    if (is_empty((void_t)address))
        return nullptr;

    url_t *url = parse_url((string_t)(is_str_in(address, "://")
                                      ? address
                                      : str_concat(2, "tcp://", address)));
    if (is_empty(url))
        return nullptr;

	return stream_connect_ex(url->type, (string_t)url->host, (string_t)url->host, (url->port == 0 ? 80 : url->port));
}

RAII_INLINE uv_stream_t *stream_secure(string_t address, string_t name, int port) {
	return stream_connect_ex(UV_TLS, address, name, (port == 0 ? 443 : port));
}

uv_stream_t *stream_connect_ex(uv_handle_type scheme, string_t address, string_t name, int port) {
    uv_args_t *uv_args = uv_arguments(4, true);
    void_t addr_set = nullptr;
    void_t handle = nullptr;

    if (scheme == RAII_SCHEME_PIPE || scheme == UV_NAMED_PIPE)
        addr_set = str_concat(2, SYS_PIPE, address);
    else
        addr_set = asio_sockaddr(address, port,
                                    (struct sockaddr_in6 *)uv_args->dns->in6,
                                    (struct sockaddr_in *)uv_args->dns->in4);

    if (!addr_set)
        return addr_set;

    switch (scheme) {
        case UV_NAMED_PIPE:
        case RAII_SCHEME_PIPE:
            uv_args->bind_type = RAII_SCHEME_PIPE;
            handle = pipe_create(false);
            break;
		case UV_TLS:
			coro_name("tls_client #%d", coro_active_id());
			uv_args->bind_type = UV_TLS;
			uv_args->ctx = tls_config_new();
			if (uv_args->ctx) {
				defer((func_t)tls_config_free, uv_args->ctx);
				if (tls_config_set_ca_file(uv_args->ctx, ca_cert_file()) < 0
					|| tls_config_set_keypair_file(uv_args->ctx, cert_file(), pkey_file()) < 0) {
					cerr("failed to set connect: %s\n", tls_config_error(uv_args->ctx));
					return nullptr;
				}

				handle = tcp_create();
				uv_handle_set_data(handler(handle), (void_t)uv_args);
			} else {
				cerr("failed to connect: `tls_config_new`\n");
				return nullptr;
			}
            break;
        case UV_TCP:
		case RAII_SCHEME_TCP:
        default:
            uv_args->bind_type = RAII_SCHEME_TCP;
            handle = tcp_create();
            break;
    }

    $append(uv_args->args, handle);
    $append(uv_args->args, addr_set);
    $append_string(uv_args->args, address);
    $append_string(uv_args->args, name);
    if (uv_start(uv_args, UV_CONNECT, 4, true).integer < 0)
		return nullptr;

	if (uv_args->bind_type == UV_TLS)
		defer((func_t)uv_tls_close, uv_args->tls);
	else
		uv_args->tls->stream = streamer(handle);

	return streamer(handle);
}

uv_stream_t *stream_listen(uv_stream_t *stream, int backlog) {
    if (is_empty(stream))
        return nullptr;

    uv_args_t *uv_args = nullptr;
    void_t check = uv_handle_get_data(handler(stream));
    if (is_defined(check))
		uv_args = (uv_args_t *)check;
	else
		return nullptr;

	if (uv_args->bind_type == UV_TLS)
		coro_name("tls_server #%d", coro_active_id());

	uv_args->args[0].object = stream;
    uv_args->args[1].integer = backlog;

    return (uv_stream_t *)uv_start(uv_args, UV_HANDLE_TYPE_MAX, 5, false).object;
}

RAII_INLINE int stream_flush(uv_stream_t *stream) {
	return uv_tls_flush(((uv_args_t *)uv_handle_get_data(handler(stream)))->tls);
}

RAII_INLINE int stream_peek(uv_stream_t *stream) {
	return uv_tls_peek(((uv_args_t *)uv_handle_get_data(handler(stream)))->tls);
}

uv_stream_t *stream_bind(string_t address, int flags) {
    if (is_empty((void_t)address))
        return nullptr;

    url_t *url = parse_url((string_t)(is_str_in(address, "://")
                                      ? address
                                      : str_concat(2, "tcp://", address)));
    if (is_empty(url))
        return nullptr;

    return stream_bind_ex(url->type, (string_t)url->host, url->port, flags);
}

uv_stream_t *stream_bind_ex(uv_handle_type scheme, string_t address, int port, int flags) {
    void_t addr_set = nullptr, handle;
    int r = 0;
	uv_args_t *uv_args = uv_arguments(5, false);

	defer_recover((func_t)uv_catch_error, uv_args);
    if (scheme == RAII_SCHEME_PIPE)
        addr_set = str_concat(2, SYS_PIPE, address);
    else
        addr_set = asio_sockaddr(address, port, uv_args->dns->in6, uv_args->dns->in4);

    if (!addr_set)
        return addr_set;

    switch (scheme) {
        case UV_NAMED_PIPE:
        case RAII_SCHEME_PIPE:
            handle = pipe_create(false);
            r = uv_pipe_bind(handle, (string_t)addr_set);
            if (!r)
                defer((func_t)fs_remove_pipe, uv_args);
            break;
		case UV_TLS:
			uv_args->ctx = tls_config_new();
			if (uv_args->ctx) {
				defer((func_t)tls_config_free, uv_args->ctx);
				if (tls_config_set_keypair_file(uv_args->ctx, cert_file(), pkey_file()) < 0) {
					cerr("failed to set bind: %s\n", tls_config_error(uv_args->ctx));
					return nullptr;
				}

				uv_args->tls->secure = tls_server();
				if (uv_args->tls->secure) {
					if (tls_configure(uv_args->tls->secure, uv_args->ctx) < 0) {
						cerr("failed to configure bind: %s", tls_error(uv_args->tls->secure));
						return nullptr;
					}
				} else {
					cerr("failed to bind: `tls_server`\n");
					return nullptr;
				}

				handle = tcp_create();
				uv_args->tls->data = uv_args->ctx;
				uv_args->tls->buf = nullptr;
				uv_args->tls->is_server = true;
				uv_args->tls->is_client = false;
				uv_args->tls->is_connecting = false;
				uv_args->tls->type = ASIO_TLS;
				r = uv_tcp_bind(handle, (sockaddr_t *)addr_set, flags);
			} else {
				cerr("failed to bind: `tls_config_new`\n");
				return nullptr;
			}
            break;
        case UV_TCP:
		case RAII_SCHEME_TCP:
        default:
            handle = tcp_create();
            r = uv_tcp_bind(handle, (sockaddr_t *)addr_set, flags);
            break;
    }

    if (r) {
        return asio_abort(nullptr, r, coro_active());
    }

    $append(uv_args->args, handle);
    $append_signed(uv_args->args, flags);
    $append(uv_args->args, addr_set);
    $append_string(uv_args->args, address);
    $append_signed(uv_args->args, port);

	uv_args->bind_type = scheme;
	uv_args->tls->stream = streamer(handle);
	uv_handle_set_data(handler(handle), (void_t)uv_args);

    return streamer(handle);
}

uv_udp_t *udp_bind(string_t address, unsigned int flags) {
    void_t addr_set, handle;
    int r = RAII_ERR;
    if (is_empty((void_t)address))
        return nullptr;

    url_t *url = parse_url((string_t)(is_str_in(address, "://")
                                      ? address
                                      : str_concat(2, "udp://", address)));
    if (is_empty(url))
        return nullptr;

    uv_args_t *uv_args = uv_arguments(5, false);
    if (!(addr_set = asio_sockaddr(url->host, url->port, uv_args->dns->in6, uv_args->dns->in4))) {
        return addr_set;
    }

    handle = udp_create();
    if (r = uv_udp_bind(handle, (sockaddr_t *)addr_set, flags)) {
        return asio_abort(nullptr, r, coro_active());
    }

    $append(uv_args->args, handle);
    $append_unsigned(uv_args->args, flags);
    $append(uv_args->args, addr_set);
    $append_string(uv_args->args, url->host);
    $append_signed(uv_args->args, url->port);
    uv_args->bind_type = RAII_SCHEME_UDP;
    uv_handle_set_data(handler(handle), (void_t)uv_args);

    return handle;
}

uv_udp_t *udp_broadcast(string_t broadcast) {
    uv_udp_t *handle = udp_bind(broadcast, 0);
    int r = uv_udp_set_broadcast(handle, 1);
    if (r) {
        return asio_abort(nullptr, r, coro_active());
    }

    return handle;
}

static void udp_generator_cb(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
                             const struct sockaddr *addr, unsigned int flags) {
    uv_args_t *uv = (uv_args_t *)uv_handle_get_data(handler(req));
    routine_t *co = uv->context, *coro = get_coro_context(co);
    int count = $size(uv->args);

    if (nread < 0) {
        uv_udp_recv_stop(req);
        uv_log_error(nread);
        if (uv->is_server && buf->base)
            RAII_FREE(buf->base);

        coro_await_exit(co, nullptr, nread, true);
    } else if (nread == 0) {
        uv->packet_req = nullptr;
        if (is_empty(coro) || co == coro) {
            coro_context_set(co, coro_running());
            coro_await_exit(co, nullptr, nread, false);
        }
    } else {
        if (uv->is_server) {
            uv->packet_req = try_calloc(1, sizeof(udp_packet_t));
        } else if (count == 2) {
            uv->packet_req = calloc_full(get_coro_scope(co), 1, sizeof(udp_packet_t), (func_t)udp_packet_free);
            uv->args[1].object = req;
            $append(uv->args, addr);
            $append(uv->args, uv->packet_req);
            uv->args[0].object = uv->packet_req->udp_req;
        } else if (count == 5) {
            uv->packet_req = (udp_packet_t *)uv->args[4].object;
        } else {
            uv->packet_req = (udp_packet_t *)uv->args[3].object;
        }

        memcpy((void_t)uv->packet_req->addr, addr, sizeof(uv->packet_req->addr));
        uv->packet_req->flags = flags;
        uv->packet_req->message_set = true;
        uv->packet_req->message = (string_t)buf->base;
        uv->packet_req->nread = nread;
        uv->packet_req->handle = req;
        uv->packet_req->args = (uv->is_server) ? nullptr : uv;
        uv->packet_req->type = ASIO_UDP;
        coro_context_set(co, co);
        coro_await_upgrade(co, uv->packet_req, nread, false, false, true);
    }
}

static void_t udp_yield(params_t args) {;
    uv_args_t *uv = args->object;
    int port, length, result = $size(uv->args) == 2 ? 0 : 1;
    uv_udp_t *handle = uv->args[result].object;
    routine_t *co = coro_active();
    string ip = nullptr;
    uv->context = co;
    uv->packet_req = nullptr;

    if (!uv->is_freeable)
        defer((func_t)uv_arguments_free, uv);
    uv_handle_set_data(handler(handle), (void_t)uv);

    if (result = uv_udp_recv_start(handle, alloc_cb, udp_generator_cb)) {
        return asio_abort(nullptr, result, co);
    }

    if (uv->is_server && !(result = uv_udp_getsockname((const uv_udp_t *)handle, uv->dns->name, &length))) {
        if (is_str_in(uv->args[3].char_ptr, ":")) {
            uv_ip6_name((const struct sockaddr_in6 *)uv->dns->name, uv->dns->ip, sizeof uv->dns->ip);
        } else if (is_str_in(uv->args[3].char_ptr, ".")) {
            uv_ip4_name((const struct sockaddr_in *)uv->dns->name, uv->dns->ip, sizeof uv->dns->ip);
        }

        port = uv->args[4].integer;
        ip = uv->dns->ip;
        fprintf(stdout, "Listening to UDP %s:%d for connections, %s."CLR_LN, ip, port, http_std_date(0));
        if (is_empty(uv_server_data()))
            interrupt_data_set(uv);
    }

    while (!coro_terminated(co)) {
        if (is_empty(uv->packet_req)) {
            yield();
        } else {
            yielding(uv->packet_req);
            if (uv->is_server && ip) {
                fprintf(stdout, "Listening to UDP %s:%d for connections, %s."CLR_LN, ip, port, http_std_date(0));
            }
        }
    }

    uv_udp_recv_stop(handle);
    return 0;
}

static udp_packet_t *udp_get(uv_udp_t *handle) {
    if (is_empty(handle))
        return nullptr;

    bool has_args = false;
    generator_t gen = nullptr;
    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    if (is_defined(uv_args) && uv_args->is_generator) {
        uv_args->args[1].object = handle;
        uv_args->packet_req = nullptr;
        gen = get_coro_generator(uv_args->context);
        coro_context_set(uv_args->context, coro_active());
    } else {
        if (is_defined(uv_args)) {
            uv_args->args[1].object = handle;
        } else if (is_empty(uv_args)) {
            has_args = true;
            uv_args = uv_arguments(2, false);
            $append(uv_args->args, handle);
        } else if (is_undefined(uv_args)) {
            return nullptr;
        }

        uv_args->is_generator = true;
        gen = generator(udp_yield, 1, uv_args);
        if (has_args)
            $append(uv_args->args, gen);
    }

    uv_handle_set_data(handler(handle), (void_t)uv_args);
    return (udp_packet_t *)yield_for(gen).object;
}

RAII_INLINE udp_packet_t *udp_recv(uv_udp_t *handle) {
    return udp_get(handle);
}

RAII_INLINE udp_packet_t *udp_listen(uv_udp_t *handle) {
    if (!is_udp(handle))
        return nullptr;

    ((uv_args_t *)uv_handle_get_data(handler(handle)))->is_server = true;
    return udp_get(handle);
}

static void udp_packet_free(udp_packet_t *handle) {
    if (is_udp_packet(handle)) {
        memset((void_t)handle, RAII_ERR, sizeof(asio_types));
        RAII_FREE((void_t)handle);
    }
}

RAII_INLINE string_t udp_get_message(udp_packet_t *udpp) {
    if (udpp->message && udpp->message_set) {
        udpp->message_set = false;
        defer(RAII_FREE, (void_t)udpp->message);
    }

    return udpp->message;
}

RAII_INLINE unsigned int udp_get_flags(udp_packet_t *udpp) {
    return udpp->flags;
}

static void_t udp_client(params_t args) {
    udp_packet_t *client = (udp_packet_t *)args[0].object;
    packet_cb handlerFunc = (packet_cb)args[1].func;

    if (is_empty(client->args))
        defer((func_t)udp_packet_free, client);

    handlerFunc(client);

    return 0;
}

RAII_INLINE void udp_handler(packet_cb connected, udp_packet_t *client) {
    launch((func_t)udp_client, 2, client, connected);
}

int udp_send(uv_udp_t *handle, string_t message, string_t addr) {
    udp_packet_t *packet = nullptr;
    void_t addr_set;
    string_t host = nullptr;
    bool is_args_set = false;
    int r = RAII_ERR;
    if (is_empty((void_t)addr) || is_empty((void_t)message) || is_empty(handle))
        return r;

    url_t *url = parse_url((string_t)(is_str_in(addr, "://")
                                      ? addr
                                      : str_concat(2, "udp://", addr)));
    if (is_empty(url))
        return r;

    uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(handle));
    if (is_empty(uv_args)) {
        is_args_set = true;
        uv_args = uv_arguments(4, false);
        uv_handle_set_data(handler(handle), (void_t)uv_args);
    } else if ($size(uv_args->args) == 5) {
        $pop(uv_args->args);
        uv_args->args[3].object = calloc_local(1, sizeof(udp_packet_t));
    }

    addr_set = asio_sockaddr((string_t)url->host, url->port,
                                (struct sockaddr_in6 *)uv_args->dns->in6,
                                (struct sockaddr_in *)uv_args->dns->in4);

    if (!(r = coro_err_code())) {
        size_t size = simd_strlen(message);
        uv_args->bufs = uv_buf_init((string)message, (unsigned int)size);
        if (is_args_set) {
            packet = calloc_full(coro_scope(), 1, sizeof(udp_packet_t), (func_t)udp_packet_free);
            packet->message_set = false;
            $append(uv_args->args, packet->udp_req);
            $append(uv_args->args, handle);
            $append(uv_args->args, addr_set);
            $append(uv_args->args, packet);
        } else {
            packet = (udp_packet_t *)uv_args->args[3].object;
            packet->message_set = false;
            uv_args->args[0].object = packet->udp_req;
            uv_args->args[1].object = handle;
            uv_args->args[2].object = addr_set;
        }

        if (!(r = uv_start(uv_args, UV_UDP_SEND, 4, true).integer)) {
            memcpy((void_t)packet->addr, addr_set, sizeof(packet->addr));
            packet->flags = handle->flags;
            packet->message = uv_args->buffer;
            packet->nread = size;
            packet->handle = handle;
            packet->args = uv_args;
            packet->type = ASIO_UDP;
        }
    } else {
        uv_log_error(r);
    }

    return r;
}

RAII_INLINE int udp_send_packet(udp_packet_t *connected, string_t message) {
    if (!is_udp_packet(connected))
        return RAII_ERR;

    size_t size = simd_strlen(message);
    uv_args_t *uv_args = nullptr;
    if (is_defined(connected->args)) {
        uv_args = connected->args;
        uv_args->args[0].object = connected->udp_req;
        uv_args->args[1].object = connected->handle;
        uv_args->args[2].object = (void_t)connected->addr;
        uv_args->args[3].object = connected;
    } else {
        if (is_undefined(connected->args))
            return RAII_ERR;

        uv_args = uv_arguments(4, true);
        $append(uv_args->args, connected->udp_req);
        $append(uv_args->args, connected->handle);
        $append(uv_args->args, connected->addr);
        $append(uv_args->args, connected);
        connected->args = uv_args;
    }

    uv_args->buffer = (string)message;
    uv_args->bufs = uv_buf_init(uv_args->buffer, (unsigned int)size);

    return uv_start(uv_args, UV_UDP_SEND, 4, true).integer;
}

static uv_fs_event_t *fs_event_create(void) {
    uv_fs_event_t *event = try_calloc(1, sizeof(uv_fs_event_t));
    int r = uv_fs_event_init(asio_loop(), event);
    if (r) {
        return asio_abort(event, r, coro_active());
    }

    return event;
}

static uv_fs_poll_t *fs_poll_create(void) {
    uv_fs_poll_t *poll = try_calloc(1, sizeof(uv_fs_poll_t));
    int r = uv_fs_poll_init(asio_loop(), poll);
    if (r) {
        return asio_abort(poll, r, coro_active());
    }

    return poll;
}

static uv_timer_t *time_create(void) {
    uv_timer_t *timer = (uv_timer_t *)try_calloc(1, sizeof(uv_timer_t));
    int r = uv_timer_init(asio_loop(), timer);
    if (r) {
        return asio_abort(timer, r, coro_active());
    }

    return timer;
}

uv_udp_t *udp_create(void) {
    uv_udp_t *udp = (uv_udp_t *)try_calloc(1, sizeof(uv_udp_t));
    int r = uv_udp_init(asio_loop(), udp);
    if (r) {
        return asio_abort(udp, r, coro_active());
    }

    defer(uv_close_deferred, udp);
    return udp;
}

uv_pipe_t *pipe_create_ex(bool is_ipc, bool autofree) {
    uv_pipe_t *pipe = (uv_pipe_t *)try_calloc(1, sizeof(uv_pipe_t));
    int r = uv_pipe_init(asio_loop(), pipe, (int)is_ipc);
    if (r) {
        return asio_abort(pipe, r, coro_active());
    }

    if (autofree)
        defer(uv_close_deferred, pipe);

    return pipe;
}

RAII_INLINE uv_pipe_t *pipe_create(bool is_ipc) {
    return pipe_create_ex(is_ipc, true);
}

pipe_file_t *pipe_file(uv_file fd, bool is_ipc) {
    pipe_file_t *pipe = (pipe_file_t *)try_calloc(1, sizeof(pipe_file_t));
    pipe->fd = fd;
    int r = uv_pipe_init(asio_loop(), pipe->file, is_ipc);
    if (r || (r = uv_pipe_open(pipe->file, pipe->fd))) {
        return asio_abort(pipe, r, coro_active());
    }

    defer(uv_close_deferred, pipe);
    pipe->type = ASIO_PIPE_FD;
    return pipe;
}

pipe_in_t *pipe_stdin(bool is_ipc) {
    pipe_in_t *pipe = (pipe_in_t *)try_calloc(1, sizeof(pipe_in_t));
    pipe->fd = STDIN_FILENO;
    int r = uv_pipe_init(asio_loop(), pipe->input, is_ipc);
    if (r || (r = uv_pipe_open(pipe->input, pipe->fd))) {
        return asio_abort(pipe, r, coro_active());
    }

    defer(uv_close_deferred, pipe);
    pipe->type = ASIO_PIPE_0;
    return pipe;
}

pipe_out_t *pipe_stdout(bool is_ipc) {
    pipe_out_t *pipe = (pipe_out_t *)try_calloc(1, sizeof(pipe_out_t));
    pipe->fd = STDOUT_FILENO;
    int r = uv_pipe_init(asio_loop(), pipe->output, is_ipc);
    if (r || (r = uv_pipe_open(pipe->output, pipe->fd))) {
        return asio_abort(pipe, r, coro_active());
    }

    defer(uv_close_deferred, pipe);
    pipe->type = ASIO_PIPE_1;
    return pipe;
}

pipepair_t *pipepair_create(bool is_ipc) {
    routine_t *co = coro_active();
    pipepair_t *pair = (pipepair_t *)try_calloc(1, sizeof(pipepair_t));
    int r = uv_pipe(pair->fd, UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE);
    if (r) {
        return asio_abort(pair, r, co);
    }

    if ((r = uv_pipe_init(asio_loop(), pair->input, (int)is_ipc))
        || (r = uv_pipe_init(asio_loop(), pair->output, (int)is_ipc))) {
        return asio_abort(pair, r, co);
    }

    if ((r = uv_pipe_open(pair->input, pair->fd[0]))
        || (r = uv_pipe_open(pair->output, pair->fd[1]))) {
        return asio_abort(pair, r, co);
    }

    uv_args_t *uv_args = uv_arguments(1, true);
    uv_args_t *uv_args2 = uv_arguments(1, true);
    $append(uv_args->args, pair->reader);
	$append(uv_args2->args, pair->writer);
	uv_args->tls->stream = pair->reader;
    uv_handle_set_data(handler(pair->reader), (void_t)uv_args);
    uv_handle_set_data(handler(pair->writer), (void_t)uv_args2);
    defer(uv_close_deferred, pair);
    pair->type = ASIO_PIPE;
    return pair;
}

socketpair_t *socketpair_create(int type, int protocol) {
    routine_t *co = coro_active();
    socketpair_t *pair = (socketpair_t *)try_calloc(1, sizeof(socketpair_t));
    int r = uv_socketpair(type, protocol, pair->fds, UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE);
    if (r) {
        return asio_abort(pair, r, co);
    }

    if ((r = uv_tcp_init(asio_loop(), pair->writer))
        || (r = uv_tcp_init(asio_loop(), pair->reader))) {
        return asio_abort(pair, r, co);
    }

    if ((r = uv_tcp_open(pair->reader, pair->fds[0]))
        || (r = uv_tcp_open(pair->writer, pair->fds[1]))) {
        return asio_abort(pair, r, co);
    }

    defer(uv_close_deferred, pair);
    pair->type = ASIO_SOCKET;
    return pair;
}

uv_tcp_t *tcp_create(void) {
    uv_tcp_t *tcp = (uv_tcp_t *)try_calloc(1, sizeof(uv_tcp_t));
    int r = uv_tcp_init(asio_loop(), tcp);
    if (r) {
        return asio_abort(tcp, r, coro_active());
    }

    defer(uv_close_deferred, tcp);
    return tcp;
}

tty_in_t *tty_in(void) {
    tty_in_t *tty = (tty_in_t *)try_calloc(1, sizeof(tty_in_t));
    tty->fd = STDIN_FILENO;
    int r = uv_tty_init(asio_loop(), tty->input, tty->fd, 1);
    if (r) {
        return asio_abort(tty, r, coro_active());
    }

	uv_args_t *uv_args = uv_arguments(1, true);
	uv_args->tls->stream = tty->reader;
    $append(uv_args->args, tty->reader);
    uv_handle_set_data(handler(tty->reader), (void_t)uv_args);
    defer(uv_close_deferred, tty);
    tty->type = ASIO_TTY_0;
    return tty;
}

tty_out_t *tty_out(void) {
    tty_out_t *tty = (tty_out_t *)try_calloc(1, sizeof(tty_out_t));
    tty->fd = STDOUT_FILENO;
    int r = uv_tty_init(asio_loop(), tty->output, tty->fd, 0);
    if (r) {
        return asio_abort(tty, r, coro_active());
    }

    uv_args_t *uv_args = uv_arguments(1, true);
    $append(uv_args->args, tty->writer);
    uv_handle_set_data(handler(tty->writer), (void_t)uv_args);
    defer(uv_close_deferred, tty);
    tty->type = ASIO_TTY_1;
    return tty;
}

tty_err_t *tty_err(void) {
    tty_err_t *tty = (tty_err_t *)try_calloc(1, sizeof(tty_err_t));
    tty->fd = STDERR_FILENO;
    int r = uv_tty_init(asio_loop(), tty->err, tty->fd, 0);
    if (r) {
        return asio_abort(tty, r, coro_active());
    }

    uv_args_t *uv_args = uv_arguments(1, true);
    $append(uv_args->args, tty->erred);
    uv_handle_set_data(handler(tty->erred), (void_t)uv_args);
    defer(uv_close_deferred, tty);
    tty->type = ASIO_TTY_2;
    return tty;
}

static uv_tcp_t *tls_tcp_create(void_t extra) {
    uv_tcp_t *tcp = (uv_tcp_t *)calloc_full(coro_scope(), 1, sizeof(uv_tcp_t), uv_close_free);
    tcp->data = extra;
    int r = uv_tcp_init(asio_loop(), tcp);
    if (r) {
        return asio_abort(nullptr, r, coro_active());
    }

    return tcp;
}

static RAII_INLINE uv_stream_t *ipc_in(spawn_t _in) {
    return _in->handle->stdio[0].data.stream;
}

static RAII_INLINE uv_stream_t *ipc_out(spawn_t out) {
    return out->handle->stdio[1].data.stream;
}

static RAII_INLINE uv_stream_t *ipc_duplex(spawn_t err) {
    return err->handle->stdio[2].data.stream;
}

static void spawn_free(spawn_t child) {
    uv_handle_t *handle = handler(&child->process);
    uv_stream_t *stream = nullptr;
    int i;

    for (i = 0; i < child->handle->stdio_count; i++) {
        if (!is_empty(stream = child->handle->stdio[i].data.stream)
			&& (size_t)child->handle->stdio[i].data.fd > 0x20000000)
            uv_close_free(stream);
    }

    if (uv_is_active(handle) || !uv_is_closing(handle))
        uv_close(handle, nullptr);

    RAII_FREE(child->handle);
    child->type = RAII_ERR;
    RAII_FREE(child);
}

static void spawn_exit_cb(uv_process_t *handle, int64_t exit_status, int term_signal) {
    spawn_t child = (spawn_t)uv_handle_get_data(handler(handle));
    routine_t *co = (routine_t *)child->handle->data;

    if (!is_empty(child->handle->exiting_cb)) {
        coro_data_set(co, (void_t)child->handle->exiting_cb);
        coro_err_set(co, exit_status);
    }

    coro_await_exit(co, casting(term_signal), term_signal, true);
}

static void_t stdio_handler(params_t uv_args) {
    uv_args_t *uv = uv_args->object;
    spawn_t child = uv->args[0].object;
    spawn_handler_cb std = (spawn_handler_cb)uv->args[1].func;
    uv_stream_t *io_in = uv->args[2].object;
    uv_stream_t *io_out = uv->args[3].object;
    uv_stream_t *io_duplex = uv->args[4].object;
    string data = nullptr;
    uv_arguments_free(uv);

    while ((data = stream_get(io_out)) && !coro_terminated(child->context)) {
        std(io_in, data, io_duplex);
    }

    uv_read_stop(io_out);
    return nullptr;
}

static void_t spawning(params_t uv_args) {
    uv_args_t *uv = uv_args->object;
    spawn_t child = uv->args[0].object;
    spawn_cb exiting_cb;
    routine_t *co = coro_active();

    uv_handle_set_data(handler(child->process), (void_t)child);
    coro_err_set(co, uv_spawn(asio_loop(), child->process, child->handle->options));
    defer((func_t)spawn_free, child);
    if (!is_empty(child->handle->data))
        RAII_FREE(child->handle->data);

    child->handle->data = (void_t)co;
    RAII_FREE(uv->args[1].object);
    uv_arguments_free(uv);

	if (!get_coro_err(co)) {
		if (child->is_detach) {
			while (!coro_terminated(child->context)) {
				coro_info(co, 1);
				yield();
			}
		} else {
			while (!coro_terminated(co)) {
				coro_info(co, 1);
				yield();
			}
		}

		if (!is_empty(get_coro_data(co))) {
            exiting_cb = (spawn_cb)get_coro_data(co);
            exiting_cb(get_coro_err(co), get_coro_result(co)->integer);
        }
    } else {
        cerr("Process launch failed with: %s"CLR_LN, uv_strerror(get_coro_err(co)));
    }

    raii_deferred_free(get_coro_scope(co));
    yield();
    unreachable;
    return asio_abort(nullptr, get_coro_err(co), co);
}

RAII_INLINE uv_stdio_container_t *stdio_fd(int fd, int flags) {
    uv_stdio_container_t *stdio = try_calloc(1, sizeof(uv_stdio_container_t));
    stdio->flags = flags;
    stdio->data.fd = fd;

    return stdio;
}

RAII_INLINE uv_stdio_container_t *stdio_stream(void_t handle, int flags) {
    uv_stdio_container_t *stdio = try_calloc(1, sizeof(uv_stdio_container_t));
    stdio->flags = flags;
    stdio->data.stream = (uv_stream_t *)handle;

    return stdio;
}

RAII_INLINE uv_stdio_container_t *stdio_pipeduplex(void) {
    return stdio_stream(pipe_create_ex(use_ipc, false), UV_CREATE_PIPE | UV_READABLE_PIPE | UV_WRITABLE_PIPE);
}

RAII_INLINE uv_stdio_container_t *stdio_piperead(void) {
    return stdio_stream(pipe_create_ex(use_ipc, false), UV_CREATE_PIPE | UV_READABLE_PIPE);
}

RAII_INLINE uv_stdio_container_t *stdio_pipewrite(void) {
    return stdio_stream(pipe_create_ex(use_ipc, false), UV_CREATE_PIPE | UV_WRITABLE_PIPE);
}

spawn_options_t *spawn_opts(string env, string_t cwd, int flags, uv_uid_t uid, uv_gid_t gid, int no_of_stdio, ...) {
    spawn_options_t *handle = try_calloc(1, sizeof(spawn_options_t));
    uv_stdio_container_t *p;
    va_list argp;
    int i;

    handle->data = !is_empty(env) ? str_split_ex(nullptr, env, ";", nullptr) : nullptr;
    handle->exiting_cb = nullptr;
    handle->options->env = handle->data;
    handle->options->cwd = cwd;
    handle->options->flags = flags;
    handle->options->exit_cb = (flags == UV_PROCESS_DETACHED) ? nullptr : spawn_exit_cb;
    handle->stdio_count = no_of_stdio;

#ifdef _WIN32
    handle->options->uid = 0;
    handle->options->gid = 0;
#else
    handle->options->uid = uid;
    handle->options->gid = gid;
#endif

    if (no_of_stdio > 0) {
        va_start(argp, no_of_stdio);
        for (i = 0; i < no_of_stdio; i++) {
            p = va_arg(argp, uv_stdio_container_t *);
            memcpy(&handle->stdio[i], p, sizeof(uv_stdio_container_t));
            RAII_FREE(p);
        }
        va_end(argp);
    }

    handle->options->stdio = (uv_stdio_container_t *)handle->stdio;
    handle->options->stdio_count = handle->stdio_count;

    return handle;
}

spawn_t spawn(string_t command, string_t args, spawn_options_t *handle) {
    spawn_t process = try_calloc(1, sizeof(_spawn_t));
    int has_args = 3;

    if (is_empty(handle)) {
        handle = spawn_opts(nullptr, nullptr, 0, 0, 0, 3,
                            stdio_fd(0, UV_IGNORE),
                            stdio_fd(1, UV_IGNORE),
                            stdio_fd(2, UV_INHERIT_FD));
    }

    handle->options->file = command;
    if (is_empty((void_t)args))
        has_args = 2;

    string command_arg = str_cat_ex(nullptr, has_args, command, ",", args);
    string *command_args = str_split_ex(nullptr, command_arg, ",", nullptr);
    RAII_FREE(command_arg);
    handle->options->args = command_args;

    process->handle = handle;
    process->is_detach = false;
    process->type = ASIO_SPAWN;
    uv_args_t *uv_args = uv_arguments(2, false);

    $append(uv_args->args, process);
    $append(uv_args->args, command_args);
    coro_mark();
    process->id = go(spawning, 1, uv_args);
    process->context = coro_unmark(process->id, "Process");

    return process;
}

RAII_INLINE int spawn_signal(spawn_t handle, int sig) {
    return uv_process_kill(handle->process, sig);
}

int spawn_detach(spawn_t child) {
	if (is_process(child)) {
		if ((child->handle->options->flags == UV_PROCESS_DETACHED) && !child->is_detach) {
			child->is_detach = true;
			child->handle->exiting_cb = nullptr;
			coro_detached(child->context);
			uv_unref(handler(child->process));
			child->context = coro_active();
		}

		while (is_empty(child->handle->data))
			yield();

		return get_coro_err((routine_t *)child->handle->data);
	}

	return coro_err_code();
}

RAII_INLINE int spawn_atexit(spawn_t child, spawn_cb exit_func) {
    child->handle->exiting_cb = exit_func;
    yield();

	return get_coro_err((routine_t *)child->handle->data);
}

RAII_INLINE bool is_spawning(spawn_t child) {
    return is_process(child) && result_is_ready(child->id) == false;
}

int spawn_handler(spawn_t child, spawn_handler_cb std_func) {
    uv_args_t *uv_args = uv_arguments(5, false);

    $append(uv_args->args, child);
    $append_func(uv_args->args, std_func);
    $append(uv_args->args, ipc_in(child));
    $append(uv_args->args, ipc_out(child));
    $append(uv_args->args, ipc_duplex(child));
    go(stdio_handler, 1, uv_args);

    return get_coro_err((routine_t *)child->handle->data);
}

RAII_INLINE uv_pid_t spawn_pid(spawn_t child) {
	return uv_process_get_pid(child->process);
}

RAII_INLINE bool is_undefined(void_t self) {
    return self && !is_defined(self);
}

RAII_INLINE bool is_defined(void_t self) {
    return is_type(self, (raii_type)ASIO_ARGS);
}

RAII_INLINE bool is_process(void_t self) {
    return is_type(self, (raii_type)ASIO_SPAWN);
}

RAII_INLINE bool is_pipepair(void_t self) {
    return is_type(self, (raii_type)ASIO_PIPE);
}

RAII_INLINE bool is_socketpair(void_t self) {
    return is_type(self, (raii_type)ASIO_SOCKET);
}

RAII_INLINE bool is_pipe_stdin(void_t self) {
    return is_type(self, (raii_type)ASIO_PIPE_0);
}

RAII_INLINE bool is_pipe_stdout(void_t self) {
    return is_type(self, (raii_type)ASIO_PIPE_1);
}

RAII_INLINE bool is_pipe_file(void_t self) {
    return is_type(self, (raii_type)ASIO_PIPE_FD);
}

RAII_INLINE bool is_tty_in(void_t self) {
    return is_type(self, (raii_type)ASIO_TTY_0);
}

RAII_INLINE bool is_tty_out(void_t self) {
    return is_type(self, (raii_type)ASIO_TTY_1);
}

RAII_INLINE bool is_tty_err(void_t self) {
    return is_type(self, (raii_type)ASIO_TTY_2);
}

RAII_INLINE bool is_tty(void_t self) {
    return is_tty_out(self) || is_tty_in(self) || is_tty_err(self);
}

RAII_INLINE bool is_pipe(void_t self) {
    if (!self)
        return false;

    void_t check = uv_handle_get_data(handler(self));
    return is_defined(check) && ((uv_args_t *)check)->bind_type == RAII_SCHEME_PIPE;
}

RAII_INLINE bool is_tcp(void_t self) {
    if (!self)
        return false;

    void_t check = uv_handle_get_data(handler(self));
    return is_defined(check) && ((uv_args_t *)check)->bind_type == RAII_SCHEME_TCP;
}

RAII_INLINE bool is_tls(uv_stream_t *self) {
    if (!self)
		return false;

	uv_args_t *uv_args = (uv_args_t *)uv_handle_get_data(handler(self));
	return is_defined(uv_args) && uv_args->bind_type == UV_TLS;
}

RAII_INLINE bool is_udp(void_t self) {
    if (!self || is_udp_packet(self))
        return false;

    void_t check = uv_handle_get_data(handler(self));
    return is_defined(check) && ((uv_args_t *)check)->bind_type == RAII_SCHEME_UDP;
}

RAII_INLINE bool is_udp_packet(void_t self) {
    return is_type(self, (raii_type)ASIO_UDP);
}

RAII_INLINE bool is_nameinfo(void_t self) {
    return is_type(self, (raii_type)ASIO_NAME);
}

RAII_INLINE bool is_addrinfo(void_t self) {
    return is_type(self, (raii_type)ASIO_DNS);
}

string_t asio_uname(void) {
    if (is_str_empty((string_t)asio_powered_by)) {
        char scrape[SCRAPE_SIZE];
        uv_utsname_t buffer[1];
        uv_os_uname(buffer);
        string_t powered_by = str_cat_ex(nullptr, 7,
                                         simd_itoa(thrd_cpu_count(), scrape), " Cores, ",
                                         buffer->sysname, " ",
                                         buffer->machine, " ",
                                         buffer->release);

        str_copy(asio_powered_by, powered_by, SCRAPE_SIZE);
        RAII_FREE((void_t)powered_by);
    }

    return (string_t)asio_powered_by;
}

string_t asio_hostname(void) {
	if (is_str_empty((string_t)asio_host)) {
        size_t len = sizeof(asio_host);
        uv_os_gethostname(asio_host, &len);
    }

    return (string_t)asio_host;
}

RAII_INLINE uv_loop_t *asio_loop(void) {
    if (!is_empty(interrupt_handle()))
        return (uv_loop_t *)interrupt_handle();

    return uv_default_loop();
}

void_t asio_abort(void_t handle, int err, routine_t *co) {
	if (!is_empty(handle))
		RAII_FREE(handle);

	uv_log_error(err);
	return coro_await_erred(co, err);
}

RAII_INLINE void asio_switch(routine_t *co) {
	if (!is_empty(co))
		coro_await_yield(co, nullptr, 0, false, false);
}

static void asio_free(routine_t *coro, routine_t *co, uv_args_t *uv_args) {
    hash_free(get_coro_waitgroup(coro));
    raii_deferred_free(get_coro_scope(coro));
    RAII_FREE(coro);

    hash_free(get_coro_waitgroup(co));
    raii_deferred_free(get_coro_scope(co));
    RAII_FREE(co);

    uv_arguments_free(uv_args);
}

static void asio_shutdown(void_t t) {
    routine_t *c = nullptr, *co = (routine_t *)t;
    waitgroup_t wg = nullptr;
    if (!is_empty(co)
        && !is_empty(c = get_coro_context(co))
        && !is_empty(wg = get_coro_waitgroup(c))
        && is_type(wg, RAII_HASH)) {
        hash_free(wg);
    }

    if (is_empty(t)) {
        uv_loop_t *loop = interrupt_handle();
        i32 num_of = interrupt_code();
        bool has_code = false;
        if (num_of) {
            has_code = true;
            uv_handle_type fs_type;
            uv_args_t *uv_args;
            routine_t *coro, *co;
            do {
                num_of--;
                fs_type = (uv_handle_type)$shift(interrupt_array()).integer;
                uv_args = $shift(interrupt_array()).object;
                co = $shift(interrupt_array()).object;
                if (fs_type == UV_FS_EVENT) {
                    coro = uv_args->context;
                    uv_fs_event_stop(uv_args->args[0].object);
                    asio_free(coro, co, uv_args);
                } else if (fs_type == UV_FS_POLL) {
                    coro = uv_args->context;
                    uv_fs_poll_stop(uv_args->args[0].object);
                    asio_free(coro, co, uv_args);
                }
            } while (num_of);

            array_delete(interrupt_array());
            interrupt_array_set(nullptr);
            interrupt_code_set(num_of);
        }

        if (loop) {
            if (uv_loop_alive(loop) || has_code) {
                uv_walk(loop, (uv_walk_cb)uv_close_free, nullptr);
                uv_run(loop, UV_RUN_DEFAULT);
            }

            uv_loop_close(loop);
            RAII_FREE((void_t)loop);
            interrupt_handle_set(nullptr);
        }
    }
}

static void uv_create_loop(void) {
    uv_loop_t *handle = try_calloc(1, sizeof(uv_loop_t));
    int r = 0;
    if (r = uv_loop_init(handle)) {
        uv_log_error(r);
        handle = nullptr;
    }

    interrupt_handle_set(handle);
}

u32 delay(u32 ms) {
    uv_timer_t *timer = time_create();
    if (is_empty(timer))
        return RAII_ERR;

    uv_args_t *uv_args = uv_arguments(3, false);
    $append(uv_args->args, timer);
    $append_unsigned(uv_args->args, ms);
    $append_unsigned(uv_args->args, uv_hrtime());
    coro_flag_set(coro_active());
    return uv_start(uv_args, UV_TIMER, 3, false).u_int;
}

main(int argc, char **argv) {
	uv_replace_allocator(rp_malloc, rp_realloc, rp_calloc, rpfree);
	RAII_INFO("%s, %s\n\n", asio_uname(), asio_hostname());
	coro_interrupt_setup((call_interrupter_t)uv_run, uv_create_loop, asio_shutdown);
	coro_stacksize_set(Kb(64));
	ASIO_ssl_init();
	CRYPTO_set_mem_functions(
		(void_t(*)(long unsigned int, string_t, int))rp_malloc,
		(void_t(*)(void_t, long unsigned int, string_t, int))rp_realloc,
		(void(*)(void_t, string_t, int))rpfree);

	return coro_start((coro_sys_func)uv_main, argc, argv, 0);
}
