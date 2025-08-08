#ifndef _ASIO_H
#define _ASIO_H

#define INTERRUPT_MODE UV_RUN_NOWAIT
#ifndef CERTIFICATE
    #define CERTIFICATE "localhost"
#endif

#include "evt_tls.h"
#include "url_http.h"
#include "reflection.h"

#ifdef _WIN32
#define INVALID_FD -EBADF
#define use_ipc false
#else
#define INVALID_FD -EBADF
#define use_ipc true
#endif

/* Cast ~libuv~ `obj` to `uv_stream_t` ptr. */
#define streamer(obj) ((uv_stream_t *)obj)

/* Cast ~libuv~ `obj` to `uv_handle_t` ptr. */
#define handler(obj) ((uv_handle_t *)obj)

/* Cast ~libuv~ `obj` to `uv_req_t` ptr. */
#define requester(obj) ((uv_req_t *)obj)
#define CLR_LN  "\033[0K\n"

#if defined(_MSC_VER)
    #define S_IRUSR S_IREAD  /* read, user */
    #define S_IWUSR S_IWRITE /* write, user */
    #define S_IXUSR 0 /* execute, user */
    #define S_IRGRP 0 /* read, group */
    #define S_IWGRP 0 /* write, group */
    #define S_IXGRP 0 /* execute, group */
    #define S_IROTH 0 /* read, others */
    #define S_IWOTH 0 /* write, others */
    #define S_IXOTH 0 /* execute, others */
    #define S_IRWXU 0
    #define S_IRWXG 0
    #define S_IRWXO 0
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    ai_family = RAII_COUNTER + 1,
    ai_socktype,
    ai_protocol,
    ai_flags
} ai_hints_types;

typedef enum {
    ASIO_DNS = ai_flags + 1,
    ASIO_NAME,
    ASIO_PIPE,
    ASIO_TCP,
    ASIO_UDP,
    ASIO_SPAWN,
    ASIO_SOCKET,
    ASIO_PIPE_0,
    ASIO_PIPE_1,
    ASIO_PIPE_FD,
    ASIO_TTY_0,
    ASIO_TTY_1,
    ASIO_TTY_2,
    ASIO_SSL_CERT,
    ASIO_SSL_REQ,
    ASIO_SSL_PKEY,
    ASIO_THIS,
    ASIO_ARGS = ASIO_THIS + UV_HANDLE_TYPE_MAX
} asio_types;

/* X509v3 distinguished names and extensions */
typedef enum {
    /* country */
    dn_c = ASIO_ARGS + 1,
    /* state */
    dn_st,
    /* locality */
    dn_l,
    /* organisation */
    dn_o,
    /* organizational unit */
    dn_ou,
    /* common name */
    dn_cn,
    /* Subject Alternative Name */
    ext_san = dn_cn + NID_subject_alt_name,
    /* Issuer Alternative Name */
    ext_ian = dn_cn + NID_issuer_alt_name,
    /* Key Usage */
    ext_ku = dn_cn + NID_key_usage,
    /* Netscape Cert Type */
    ext_nct = dn_cn + NID_netscape_cert_type,
    /* sha256 With RSA Encryption */
    rsa_sha256 = ext_nct + NID_sha256WithRSAEncryption,
    /* sha384 With RSA Encryption */
    rsa_sha384 = ext_nct + NID_sha384WithRSAEncryption,
    /* sha512 With RSA Encryption */
    rsa_sha512 = ext_nct + NID_sha512WithRSAEncryption,
    /* sha224 With RSA Encryption */
    rsa_sha224 = ext_nct + NID_sha224WithRSAEncryption,
    /* sha512_224 With RSA Encryption */
    rsa_sha512_224 = ext_nct + NID_sha512_224WithRSAEncryption,
    /* sha251_256 With RSA Encryption */
    rsa_sha512_256 = ext_nct + NID_sha512_256WithRSAEncryption,
    pkey_type,
    pkey_bits
} csr_types;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t reader[1];
        uv_pipe_t input[1];
    };
} pipe_in_t;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t writer[1];
        uv_pipe_t output[1];
    };
} pipe_out_t;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t handle[1];
        uv_pipe_t file[1];
    };
} pipe_file_t;

typedef struct {
    asio_types type;
    uv_file fd[2];
    union {
        uv_stream_t writer[1];
        uv_pipe_t output[1];
    };
    union {
        uv_stream_t reader[1];
        uv_pipe_t input[1];
    };
} pipepair_t;

typedef struct {
    asio_types type;
    uv_os_sock_t fds[2];
    uv_tcp_t writer[1];
    uv_tcp_t reader[1];
} socketpair_t;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t reader[1];
        uv_tty_t input[1];
    };
} tty_in_t;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t writer[1];
        uv_tty_t output[1];
    };
} tty_out_t;

typedef struct {
    asio_types type;
    uv_file fd;
    union {
        uv_stream_t erred[1];
        uv_tty_t err[1];
    };
} tty_err_t;

typedef struct udp_packet_s udp_packet_t;
typedef struct addrinfo addrinfo_t;
typedef const struct sockaddr sockaddr_t;
typedef struct sockaddr_in sock_in_t;
typedef struct sockaddr_in6 sock_in6_t;
typedef void (*event_cb)(string_t filename, int events, int status);
typedef void (*poll_cb)(int status, const uv_stat_t *prev, const uv_stat_t *curr);
typedef void (*stream_cb)(uv_stream_t *);
typedef void (*packet_cb)(udp_packet_t *);
typedef void (*spawn_cb)(int64_t status, int signal);
typedef void (*spawn_handler_cb)(uv_stream_t *input, string output, uv_stream_t *duplex);

typedef struct {
    asio_types type;
    void *data;
    int stdio_count;
    spawn_cb exiting_cb;
    uv_stdio_container_t stdio[3];
    uv_process_options_t options[1];
} spawn_options_t;

typedef struct spawn_s _spawn_t;
typedef _spawn_t *spawn_t;
typedef struct nameinfo_s {
    asio_types type;
    string_t host;
    string_t service;
} nameinfo_t;

typedef struct scandir_s {
    bool started;
    size_t count;
    uv_fs_t *req;
    uv_dirent_t item[1];
} scandir_t;

typedef struct dnsinfo_s {
    asio_types type;
    bool is_ip6;
    size_t count;
    string ip_addr, ip6_addr, ip_name;
    addrinfo_t *addr, original[1];
    nameinfo_t info[1];
    struct sockaddr name[1];
    struct sockaddr_in in4[1];
    struct sockaddr_in6 in6[1];
    char ip[INET6_ADDRSTRLEN + 1];
} dnsinfo_t;

typedef struct uv_args_s uv_args_t;
typedef struct {
    asio_types type;
    void_t data;
    ptrdiff_t diff;
    uv_handle_t *handle;
    uv_req_t *req;
    uv_args_t *args;
    char charaters[PATH_MAX];
} uv_this_t;

/**
*@param stdio fd
* -The convention stdio[0] points to `fd 0` for stdin, `fd 1` is used for stdout, and `fd 2` is stderr.
* -Note: On Windows file descriptors greater than 2 are available to the child process only if
*the child processes uses the MSVCRT runtime.
*
*@param flag specify how stdio `uv_stdio_flags` should be transmitted to the child process.
* -`UV_IGNORE`
* -`UV_CREATE_PIPE`
* -`UV_INHERIT_FD`
* -`UV_INHERIT_STREAM`
* -`UV_READABLE_PIPE`
* -`UV_WRITABLE_PIPE`
* -`UV_NONBLOCK_PIPE`
* -`UV_OVERLAPPED_PIPE`
*/
C_API uv_stdio_container_t *stdio_fd(int fd, int flags);

/**
*@param stdio streams
* -The convention stdio[0] points to `fd 0` for stdin, `fd 1` is used for stdout, and `fd 2` is stderr.
* -Note: On Windows file descriptors greater than 2 are available to the child process only if
*the child processes uses the MSVCRT runtime.
*
*@param flag specify how stdio `uv_stdio_flags` should be transmitted to the child process.
* -`UV_IGNORE`
* -`UV_CREATE_PIPE`
* -`UV_INHERIT_FD`
* -`UV_INHERIT_STREAM`
* -`UV_READABLE_PIPE`
* -`UV_WRITABLE_PIPE`
* -`UV_NONBLOCK_PIPE`
* -`UV_OVERLAPPED_PIPE`
*/
C_API uv_stdio_container_t *stdio_stream(void_t handle, int flags);

/*
Stdio container `pipe` ~pointer~ with `uv_stdio_flags` transmitted to the child process.
* -`UV_CREATE_PIPE`
* -`UV_READABLE_PIPE`
* -`UV_WRITABLE_PIPE`
*/
C_API uv_stdio_container_t *stdio_pipeduplex(void);

/*
Stdio container `pipe` ~pointer~ with `uv_stdio_flags` transmitted to the child process.
* -`UV_CREATE_PIPE`
* -`UV_READABLE_PIPE`
*/
C_API uv_stdio_container_t *stdio_piperead(void);

/*
Stdio container `pipe` ~pointer~ with `uv_stdio_flags` transmitted to the child process.
* -`UV_CREATE_PIPE`
* -`UV_WRITABLE_PIPE`
*/
C_API uv_stdio_container_t *stdio_pipewrite(void);

/**
 * @param env Environment for the new process. Key=value, separated with semicolon like:
 * `"Key1=Value1;Key2=Value2;Key3=Value3"`. If `NULL` the parents environment is used.
 *
 * @param cwd Current working directory for the subprocess.
 * @param flags  Various process flags that control how `uv_spawn()` behaves:
 * - On Windows this uses CreateProcess which concatenates the arguments into a string this can
 * cause some strange errors. See the UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS flag on uv_process_flags.
 * - `UV_PROCESS_SETUID`
 * - `UV_PROCESS_SETGID`
 * - `UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS`
 * - `UV_PROCESS_DETACHED`
 * - `UV_PROCESS_WINDOWS_HIDE`
 * - `UV_PROCESS_WINDOWS_HIDE_CONSOLE`
 * - `UV_PROCESS_WINDOWS_HIDE_GUI`
 *
 * @param uid options
 * @param gid options
 * Can change the child process’ user/group id. This happens only when the appropriate bits are set in the flags fields.
 * - Note:  This is not supported on Windows, uv_spawn() will fail and set the error to UV_ENOTSUP.
 *
 * @param no_of_stdio Number of `uv_stdio_container_t` for each stream or file descriptors to be passed to a child process. Use `stdio_stream()` or `stdio_fd()` functions to create.
 */
C_API spawn_options_t *spawn_opts(string env, string_t cwd, int flags, uv_uid_t uid, uv_gid_t gid, int no_of_stdio, ...);

/**
 * Initializes the process handle and starts the process.
 * If the process is successfully spawned, this function will return `spawn_t`
 * handle. Otherwise, the negative error code corresponding to the reason it couldn’t
 * spawn is returned.
 *
 * Possible reasons for failing to spawn would include (but not be limited to) the
 * file to execute not existing, not having permissions to use the setuid or setgid
 * specified, or not having enough memory to allocate for the new process.
 *
 * @param command Program to be executed.
 * @param args Command line arguments, separate with comma like: `"arg1,arg2,arg3,..."`
 * @param options Use `spawn_opts()` function to produce `uv_stdio_container_t` and `uv_process_options_t` options.
 * If `NULL` defaults `stderr` of subprocess to parent.
 */
C_API spawn_t spawn(string_t command, string_t args, spawn_options_t *options);
C_API int spawn_atexit(spawn_t, spawn_cb exit_func);
C_API bool is_spawning(spawn_t);
C_API int spawn_handler(spawn_t child, spawn_handler_cb std_func);
C_API int spawn_pid(spawn_t);
C_API int spawn_signal(spawn_t, int sig);
C_API int spawn_detach(spawn_t);

C_API string fs_readfile(string_t path);
C_API int fs_writefile(string_t path, string_t text);

C_API uv_file fs_open(string_t path, int flags, int mode);
C_API int fs_close(uv_file fd);
C_API uv_stat_t *fs_fstat(uv_file fd);
C_API string fs_read(uv_file fd, int64_t offset);
C_API int fs_write(uv_file fd, string_t text, int64_t offset);
C_API int fs_fsync(uv_file fd);
C_API int fs_fdatasync(uv_file fd);
C_API int fs_ftruncate(uv_file fd, int64_t offset);
C_API int fs_fchmod(uv_file fd, int mode);
C_API int fs_fchown(uv_file fd, uv_uid_t uid, uv_gid_t gid);
C_API int fs_futime(uv_file fd, double atime, double mtime);
C_API int fs_sendfile(uv_file out_fd, uv_file in_fd, int64_t in_offset, size_t length);

C_API int fs_unlink(string_t path);
C_API int fs_mkdir(string_t path, int mode);
C_API int fs_rmdir(string_t path);
C_API int fs_rename(string_t path, string_t new_path);
C_API int fs_link(string_t path, string_t new_path);
C_API int fs_access(string_t path, int mode);
C_API int fs_copyfile(string_t path, string_t new_path, int flags);
C_API int fs_symlink(string_t path, string_t new_path, int flags);
C_API string fs_readlink(string_t path);
C_API string fs_realpath(string_t path);
C_API uv_stat_t *fs_stat(string_t path);
C_API scandir_t *fs_scandir(string_t path, int flags);
C_API uv_dirent_t *fs_scandir_next(scandir_t *dir);

C_API bool file_exists(string_t path);
C_API size_t file_size(string_t path);

C_API int fs_chmod(string_t path, int mode);
C_API int fs_utime(string_t path, double atime, double mtime);
C_API int fs_lutime(string_t path, double atime, double mtime);
C_API int fs_chown(string_t path, uv_uid_t uid, uv_gid_t gid);
C_API int fs_lchown(string_t path, uv_uid_t uid, uv_gid_t gid);

C_API uv_stat_t *fs_lstat(string_t path);
C_API uv_statfs_t *fs_statfs(string_t path);
C_API uv_file fs_mkstemp(string tpl);
C_API string fs_mkdtemp(string tpl);

C_API void fs_poll(string_t path, poll_cb pollfunc, int interval);
C_API string_t fs_poll_path(void);
C_API bool fs_poll_stop(void);

C_API void fs_watch(string_t, event_cb watchfunc);
C_API string_t fs_watch_path(void);
C_API bool fs_watch_stop(void);

C_API dnsinfo_t *get_addrinfo(string_t address, string_t service, u32 numhints_pair, ...);
C_API addrinfo_t *addrinfo_next(dnsinfo_t *);
C_API string_t addrinfo_ip(dnsinfo_t *);
C_API nameinfo_t *get_nameinfo(string_t addr, int port, int flags);

C_API uv_pipe_t *pipe_create_ex(bool is_ipc, bool autofree);
C_API uv_pipe_t *pipe_create(bool is_ipc);
C_API uv_tcp_t *tcp_create(void);

C_API pipepair_t *pipepair_create(bool is_ipc);
C_API socketpair_t *socketpair_create(int type, int protocol);

C_API pipe_in_t *pipe_stdin(bool is_ipc);
C_API pipe_out_t *pipe_stdout(bool is_ipc);
C_API pipe_file_t *pipe_file(uv_file fd, bool is_ipc);

C_API tty_in_t *tty_in(void);
C_API tty_out_t *tty_out(void);
C_API tty_err_t *tty_err(void);

C_API string stream_read(uv_stream_t *);
C_API string stream_read_once(uv_stream_t *);
C_API string stream_read_wait(uv_stream_t *);
C_API int stream_write(uv_stream_t *, string_t text);
C_API int stream_shutdown(uv_stream_t *);

/*
* Parse `address` separating `scheme`, `host`, and `port`.
*
* - Pause/loop current `coroutine` until connection to `address`.
* - The returned `stream` handle `type` depends on `scheme` part of `address`.
*
* NOTE: Combines `uv_pipe_connect`, `uv_tcp_connect`, `uv_ip4_addr`, `uv_ip6_addr`. */
C_API uv_stream_t *stream_connect(string_t address);
C_API uv_stream_t *stream_connect_ex(uv_handle_type scheme, string_t address, int port);

/*
* Starts listing for `new` incoming connections on the given `stream` handle.
*
* - Pause/loop current `coroutine` until accepted connection.
* - The returned ~client~ handle `type` depends on `scheme` part of `stream_bind` call.
* - This new ~stream~ MUST CALL `stream_handler` for processing.
*
* NOTE: Combines `uv_listen` and `uv_accept`. */
C_API uv_stream_t *stream_listen(uv_stream_t *, int backlog);

/*
* Parse `address` separating `scheme`, `host`, and `port`.
*
* - The returned `stream` handle `type` depends on `scheme` part of `address`.
*
* NOTE: Combines `uv_pipe_bind`, `uv_tcp_bind`, `uv_ip4_addr`, `uv_ip6_addr`. */
C_API uv_stream_t *stream_bind(string_t address, int flags);
C_API uv_stream_t *stream_bind_ex(uv_handle_type scheme, string_t address, int port, int flags);

/* Creates and launch new coroutine to handle `connected` client `handle`. */
C_API void stream_handler(stream_cb connected, uv_stream_t *client);

C_API uv_udp_t *udp_create(void);
C_API uv_udp_t *udp_bind(string_t address, unsigned int flags);
C_API uv_udp_t *udp_broadcast(string_t broadcast);
C_API udp_packet_t *udp_listen(uv_udp_t *);
C_API void udp_handler(packet_cb connected, udp_packet_t *);

C_API string_t udp_get_message(udp_packet_t *);
C_API unsigned int udp_get_flags(udp_packet_t *);

C_API int udp_send(uv_udp_t *handle, string_t message, string_t addr);
C_API udp_packet_t *udp_recv(uv_udp_t *);
C_API int udp_send_packet(udp_packet_t *, string_t);

#define UV_TLS                  RAII_SCHEME_TLS
#define UV_CTX                  ASIO_ARGS + RAII_NAN

#define foreach_in_dir(X, S)    uv_dirent_t *(X) = nil; \
    for(X = fs_scandir_next((scandir_t *)S); X != nullptr; X = fs_scandir_next((scandir_t *)S))
#define foreach_scandir(...)    foreach_xp(foreach_in_dir, (__VA_ARGS__))

#define foreach_in_info(X, S)   addrinfo_t *(X) = nil; \
    for (X = ((dnsinfo_t *)S)->original; X != nullptr; X = addrinfo_next((dnsinfo_t *)S))
#define foreach_addrinfo(...)   foreach_xp(foreach_in_info, (__VA_ARGS__))

C_API uv_loop_t *asio_loop(void);

/* For displaying Cpu core count, library version, and OS system info from `uv_os_uname()`. */
C_API string_t asio_uname(void);
C_API string_t asio_hostname(void);

C_API bool is_undefined(void_t);
C_API bool is_defined(void_t);
C_API bool is_tls(uv_stream_t *);
C_API bool is_pipe(void_t);
C_API bool is_tty(void_t);
C_API bool is_udp(void_t);
C_API bool is_tcp(void_t);
C_API bool is_process(void_t);
C_API bool is_udp_packet(void_t);
C_API bool is_socketpair(void_t);
C_API bool is_pipepair(void_t);
C_API bool is_pipe_stdin(void_t);
C_API bool is_pipe_stdout(void_t);
C_API bool is_pipe_file(void_t);
C_API bool is_tty_in(void_t);
C_API bool is_tty_out(void_t);
C_API bool is_tty_err(void_t);
C_API bool is_addrinfo(void_t);
C_API bool is_nameinfo(void_t);
C_API bool is_ssl_cert(void_t);
C_API bool is_ssl_req(void_t);
C_API bool is_ssl_pkey(void_t);

/* This library provides its own ~main~,
which call this function as an coroutine! */
C_API int uv_main(int, char **);
C_API u32 delay(u32 ms);

#ifdef _WIN32
#define _BIO_MODE_R(flags) (((flags) & PKCS7_BINARY) ? "rb" : "r")
#define _BIO_MODE_W(flags) (((flags) & PKCS7_BINARY) ? "wb" : "w")
#else
#define _BIO_MODE_R(flags) "r"
#define _BIO_MODE_W(flags) "w"
#endif
/* OpenSSL Certificate */
typedef struct certificate_object asio_cert_t;

/* OpenSSL AsymmetricKey */
typedef struct pkey_object asio_pkey_t;

/* OpenSSL Certificate Signing Request */
typedef struct x509_request_object asio_req_t;

C_API void asio_ssl_error(void);

C_API asio_pkey_t *pkey_create(u32 num_pairs, ...);
C_API asio_req_t *csr_create(EVP_PKEY *pkey, u32 num_pairs, ...);
C_API asio_cert_t *x509_create(EVP_PKEY *pkey, u32 num_pairs, ...);

C_API bool pkey_x509_export(EVP_PKEY *pkey, string_t path_noext);
C_API bool csr_x509_export(X509_REQ *req, string_t path_noext);
C_API bool cert_x509_export(X509 *cert, string_t path_noext);

C_API EVP_PKEY *rsa_pkey(int keylength);
C_API X509 *x509_self(EVP_PKEY *pkey, string_t country, string_t org, string_t domain);
C_API bool x509_self_export(EVP_PKEY *pkey, X509 *x509, string_t path_noext);
#ifdef __cplusplus
}
#endif

#endif /* _ASIO_H */
