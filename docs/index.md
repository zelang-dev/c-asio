# c-asio

[![Windows & Ubuntu & macOS x86_64](https://github.com/zelang-dev/c-asio/actions/workflows/ci.yml/badge.svg)](https://github.com/zelang-dev/c-asio/actions/workflows/ci.yml)[![CentOS Stream 9+](https://github.com/zelang-dev/c-asio/actions/workflows/ci_centos.yml/badge.svg)](https://github.com/zelang-dev/c-asio/actions/workflows/ci_centos.yml)[![armv7, aarch64, riscv64](https://github.com/zelang-dev/c-asio/actions/workflows/ci_cpu.yml/badge.svg)](https://github.com/zelang-dev/c-asio/actions/workflows/ci_cpu.yml)[![ppc64le - ucontext](https://github.com/zelang-dev/c-asio/actions/workflows/ci_cpu-ppc64le.yml/badge.svg)](https://github.com/zelang-dev/c-asio/actions/workflows/ci_cpu-ppc64le.yml)

A *memory safe* focus **C framework**, combining [c-raii](https://zelang-dev.github.io/c-raii), [libuv](http://docs.libuv.org), [coroutine](https://en.wikipedia.org/wiki/Coroutine) and other *concurrency primitives*.

## Table of Contents

* [Introduction](#introduction)
* [Design](#design)
  * [API layout](#api)
* [Synopsis](#synopsis)
* [Usage](#usage)
* [Installation](#installation)
* [Contributing](#contributing)
* [License](#license)

## Introduction

Attain the behavior of **C++** [boost.cobalt](https://github.com/boostorg/cobalt) and [boost.asio](https://www.boost.org/doc/libs/master/doc/html/boost_asio/overview.html) without the overhead.

This library provides **ease of use** *convenience* wrappers for **[libuv](http://docs.libuv.org)** combined with the power of **[c-raii](https://zelang-dev.github.io/c-raii)**, a **high level memory management** library similar to other languages, among other features. Like **[coroutine](https://github.com/zelang-dev/c-raii/blob/main/include/coro.h)** support, the otherwise needed **callback**, is now automatically back to the caller with *results*.

* All functions requiring *allocation* and *passing* **pointers**, now returns them instead, if needed.
* The general naming convention is to drop **~~uv_~~** prefix and require only *necessary* arguments/options.
* This integration also requires the use of **`uv_main(int argc, char **argv)`** as the *startup* entry routine:

**libuv** example from <https://github.com/libuv/libuv/tree/master/docs/code/>

<table>
<tr>
<th>helloworld.c</th>
<th>helloworld/main.c</th>
</tr>
<tr>
<td>

```c
#include "asio.h"

int uv_main(int argc, char **argv) {
    printf("Now quitting.\n");
    yield();

    return coro_err_code();
}
```

</td>
<td>

```c
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

int main() {
    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);

    printf("Now quitting.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);
    free(loop);
    return 0;
}
```

</td>
</tr>
</table>

**This general means there will be a dramatic reduction of lines of code repeated, repeatedly.**

*Libuv guides/examples:*

* [Reading/Writing files](https://docs.libuv.org/en/v1.x/guide/filesystem.html#reading-writing-files) as in [uvcat/main.c](https://github.com/libuv/libuv/blob/master/docs/code/uvcat/main.c) - 62 line *script*.
* [Buffers and Streams](https://docs.libuv.org/en/v1.x/guide/filesystem.html#buffers-and-streams) as in [uvtee/main.c](https://github.com/libuv/libuv/blob/master/docs/code/uvtee/main.c) - 79 line *script*.
* [Querying DNS](https://docs.libuv.org/en/v1.x/guide/networking.html#querying-dns) as in [dns/main.c](https://github.com/libuv/libuv/blob/master/docs/code/dns/main.c) - 80 line *script*.
* [Spawning child processes](https://docs.libuv.org/en/v1.x/guide/processes.html#spawning-child-processes) as in [spawn/main.c](https://github.com/libuv/libuv/blob/master/docs/code/spawn/main.c) - 36 line *script*.
* [Networking/TCP](https://docs.libuv.org/en/v1.x/guide/networking.html#tcp) as in [tcp-echo-server/main.c](https://github.com/libuv/libuv/blob/master/docs/code/tcp-echo-server/main.c) - 87 line *script*.

*Reduced to:*
<table>
<tr>
<th>uvcat.c - 13 lines</th>
<th>uvtee.c - 20 lines</th>
</tr>
<tr>
<td>

```c
#include "asio.h"

int uv_main(int argc, char **argv) {
    uv_file fd = fs_open(argv[1], O_RDONLY, 0);
    if (fd > 0) {
        string text = fs_read(fd, -1);
        fs_write(STDOUT_FILENO, text, -1);

        return fs_close(fd);
    }

    return fd;
}
```

</td>
<td>

```c
#include "asio.h"

int uv_main(int argc, char **argv) {
    string text = nullptr;
    uv_file fd = fs_open(argv[1], O_CREAT | O_RDWR, 0644);
    if (fd > 0) {
        pipe_file_t *file_pipe = pipe_file(fd, false);
        pipe_out_t *stdout_pipe = pipe_stdout(false);
        pipe_in_t *stdin_pipe = pipe_stdin(false);
        while (text = stream_read(stdin_pipe->reader)) {
            if (stream_write(stdout_pipe->writer, text)
                || stream_write(file_pipe->handle, text))
                break;
        }

        return fs_close(fd);
    }

    return fd;
}
```

</td>
</tr>
</table>

<table>
<tr>
<th>dns.c - 17 lines</th>
</tr>
<tr>
<td>

```c
#include "asio.h"

int uv_main(int argc, char **argv) {
    string text = nullptr;
    fprintf(stderr, "irc.libera.chat is...\033[0K\n");
    dnsinfo_t *dns = get_addrinfo("irc.libera.chat", "6667",
                                  3, kv(ai_flags, AF_UNSPEC),
                                  kv(ai_socktype, SOCK_STREAM),
                                  kv(ai_protocol, IPPROTO_TCP));

    fprintf(stderr, "%s\033[0K\n", addrinfo_ip(dns));
    uv_stream_t *server = stream_connect_ex(UV_TCP, addrinfo_ip(dns), 6667);
    while (text = stream_read(server))
        fprintf(stderr, "\033[0K%s", text);

    return coro_err_code();
}
```

</td>
</tr>
</table>

<table>
<tr>
<th>spawn.c - 14 lines</th>
</tr>
<tr>
<td>

```c
#include "asio.h"

void _on_exit(int64_t exit_status, int term_signal) {
    fprintf(stderr, "\nProcess exited with status %" PRId64 ", signal %d\n",
            exit_status, term_signal);
}

int uv_main(int argc, char **argv) {
    spawn_t child = spawn("mkdir", "test-dir", nullptr);
    if (!spawn_atexit(child, _on_exit))
        fprintf(stderr, "\nLaunched process with ID %d\n", spawn_pid(child));

    return coro_err_code();
}
```

</td>
</tr>
</table>

<table>
<tr>
<th>tcp-echo-server.c - 27 lines</th>
</tr>
<tr>
<td>

```c
#include "asio.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

void new_connection(uv_stream_t *socket) {
    string data = stream_read(socket);
    stream_write(socket, data);
}

int uv_main(int argc, char **argv) {
    uv_stream_t *client, *server;
    char addr[UV_MAXHOSTNAMESIZE] = nil;

    if (snprintf(addr, sizeof(addr), "0.0.0.0:%d", DEFAULT_PORT)) {
        server = stream_bind(addr, 0);
        while (server) {
            if (is_empty(client = stream_listen(server, DEFAULT_BACKLOG))) {
                fprintf(stderr, "Listen error %s\n", uv_strerror(coro_err_code()));
                break;
            }

            stream_handler(new_connection, client);
        }
    }

    return coro_err_code();
}
```

</td>
</tr>
</table>

See `branches` for previous setup, `main` is an complete makeover of previous implementation approaches.

Similar approach has been made for ***C++20***, an implementation in [uvco](https://github.com/dermesser/uvco).
The *[tests](https://github.com/dermesser/uvco/tree/master/test)* presented there currently being reimplemented for *C89* here, this project will be considered stable when *completed* and *passing*. And another approach in [libasync](https://github.com/btrask/libasync) mixing [libco](https://github.com/higan-emu/libco) with **libuv**. Both approaches are **Linux** only.

## Design

The *intergration* pattern for all **libuv** functions taking *callback* is as [waitgroup_work.c](https://github.com/zelang-dev/c-asio/tree/main/examples/waitgroup_work.c) **example**:

```c
#define USE_CORO
#include "raii.h"

#define FIB_UNTIL 25

long fib_(long t) {
    if (t == 0 || t == 1)
        return 1;
    else
        return fib_(t-1) + fib_(t-2);
}

void_t fib(params_t req) {
    int n = req->integer;
    if (random() % 2)
        sleepfor(1);
    else
        sleepfor(3);

    long fib = fib_(n);
    fprintf(stderr, "%dth fibonacci is %lu in thrd: #%d\033[0K\n", n, fib, coro_thrd_id());

    return casting(fib);
}

void after_fib(int status, rid_t id) {
    fprintf(stderr, "Done calculating %dth fibonacci, result: %d\n", status, result_for(id).integer);
}

int main(int argc, char **argv) {
    rid_t data[FIB_UNTIL];
    int i;

    waitgroup_t wg = waitgroup_ex(FIB_UNTIL);
    for (i = 0; i < FIB_UNTIL; i++) {
        data[i] = go(fib, 1, casting(i));
    }
    waitresult_t wgr = waitfor(wg);

    if ($size(wgr) == FIB_UNTIL)
        for (i = 0; i < FIB_UNTIL; i++) {
            after_fib(i, data[i]);
        }

    return 0;
}
```

Every system **thread** has a **run queue** assigned, a ~tempararay~ *FIFO queue*,
it holds **coroutine** *tasks*. This assignment is based on *system cpu cores* available,
and set at startup, a coroutine **thread pool** set before `uv_main` is called.

When a **go/coroutine** is created, it's given a *index* `result id` from *global* **array** like struct,
a `coroutine id`, and `thread id`. Then placed into a *global* **run queue**, a *hashtable*,
the *key* being `result id`, for schedularing. The `thread id` determines which *thread pool*
coroutine gets assigned to.

These three *data structures* are atomically accessable by all threads.

* The **main thread** determines and move *coroutines* from *global queue* to each *thread queue*.
* Each **thread's** *scheduler* manages it's own *local* **run queue** of *coroutines* by ~thread local storage~.
  * It takes `coroutine tasks` from it's ~tempararay~ *FIFO queue* to *local storage*.
* Each *coroutine* is *self containing*, can be assigned to any *thread*, at any point within a `yield` execution.

All **libuv** functions *outlined/api*, is as **example**, but having a `waitgroup` of *one*.
Demonstrating `true` *libuv/Coroutine* **multi threading** is *disabled* by how current *[tests](https://github.com/zelang-dev/c-asio/tree/main/tests)* and *[examples](https://github.com/zelang-dev/c-asio/tree/main/examples)* startup.

If the *number* of coroutines *created* before the first `yield` encountered, does not equal **cpu core** *count* plus *one*.
Then **main thread** will move all *coroutines* to itself, set each *coroutine* `thread id` to itself,
and *mark* whole system feature *disabled*.

* Codebase will need current **libuv** function wrapper implementations to have **all arguments pass** into **coroutine** creation, right now the *initaliaztion* process using a **uv_loop_t** *thread* `handle` of wrong **coroutine thread pool**, disabling is a **tempararay** fix.

The approach *outlined* and *things still to be worked out*, is as **Go** [The Scheduler Saga](https://youtu.be/YHRO5WQGh0k), [Queues, Fairness, and The Go Scheduler](https://youtu.be/wQpC99Xu1U4) and **Rust**
[Making the Tokio scheduler 10x faster](https://tokio.rs/blog/2019-10-scheduler).

### API

The *documentation* at [boost.cobalt](https://www.boost.org/doc/libs/master/libs/cobalt/doc/html/index.html) is a good staring point. The *principles* still apply, just done *automatically*, with some *naming differences* hereforth. Like *boost.asio* **io_context** is *similar* to **uv_loop_t** in *libuv* and *others* in:

* [Coroutine Patterns: Problems and Solutions Using Coroutines in a Modern Codebase](https://youtu.be/Iqrd9vsLrak) **YouTube**
* [Introduction to C++ Coroutines Through a Thread Scheduling Demonstration](https://youtu.be/kIPzED3VD3w) **YouTube**
* [C++ Coroutine Intuition](https://youtu.be/NNqVt73OsfI) **YouTube**
* [Asynchrony with ASIO and coroutines](https://youtu.be/0i_pFZSijZc) **YouTube**

```c
/* This library provides its own ~main~,
which call this function as an coroutine! */
C_API int uv_main(int, char **);

C_API uv_loop_t *asio_loop(void);
C_API u32 delay(u32 ms);

C_API string fs_readfile(string_t path);
C_API int fs_writefile(string_t path, string_t text);

C_API bool fs_touch(string_t filepath);

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
#define foreach_scandir(...)    foreach_xp(foreach_in_dir, (__VA_ARGS__))

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
#define foreach_addrinfo(...)   foreach_xp(foreach_in_info, (__VA_ARGS__))

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
* - Pause/loop current `coroutine` until connection to `address`.
* - The returned `stream` handle `type` depends on `scheme` part of `address`.
*
* NOTE: Combines `uv_pipe_connect`, `uv_tcp_connect`, `uv_ip4_addr`, `uv_ip6_addr`. */
C_API uv_stream_t *stream_connect(string_t address);
C_API uv_stream_t *stream_connect_ex(uv_handle_type scheme, string_t address, int port);

/*
* Starts listing for `new` incoming connections on the given `stream` handle.
* - Pause/loop current `coroutine` until accepted connection.
* - The returned ~client~ handle `type` depends on `scheme` part of `stream_bind` call.
* - This new ~stream~ MUST CALL `stream_handler` for processing.
*
* NOTE: Combines `uv_listen` and `uv_accept`. */
C_API uv_stream_t *stream_listen(uv_stream_t *, int backlog);

/*
* Parse `address` separating `scheme`, `host`, and `port`.
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

C_API bool is_promise(void_t);
C_API bool is_future(void_t);

/*
This runs the function `fn` asynchronously (potentially in a separate thread which
might be a part of a thread pool) and returns a `future` that will eventually hold
the result of that function call.

Similar to: https://en.cppreference.com/w/cpp/thread/async.html
https://en.cppreference.com/w/cpp/thread/packaged_task.html

MUST call either `queue_then()` or `queue_get()` to actually start execution in thread.
*/
C_API future queue_work(thrd_func_t fn, size_t num_args, ...);

/*
This will complete an normal `uv_queue_work()` setup execution and allow thread to run
`queue_work()` provided `fn`.

Will return `promise` only useful with `queue_get()`.

Similar to: https://en.cppreference.com/w/cpp/thread/promise.html */
C_API promise *queue_then(future, queue_cb callback);

/*
This waits aka `yield` until the `future` or `promise` is ready, then retrieves
the value stored. Right after calling this function `queue_is_valid()` is `false`.

Similar to: https://en.cppreference.com/w/cpp/thread/future/get.html */
C_API template_t queue_get(void_t);

/*
Checks if the ~future/uv_work_t~ refers to a shared state aka `promise`, and `running`.

Similar to: https://en.cppreference.com/w/cpp/thread/future/valid.html
*/
C_API bool queue_is_valid(future);

/*
Will `pause` and `yield` to another `coroutine` until `ALL` ~future/uv_work_t~
results/requests in `array` become available/done. Calls `queue_is_valid()` on each.

Similar to: https://en.cppreference.com/w/cpp/thread/future/wait.html */
C_API void queue_wait(arrays_t);

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

/**
*@param fd file descriptor
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
*@param handle streams
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
C_API uv_stdio_container_t *stdio_pipeduplex(void);
C_API uv_stdio_container_t *stdio_piperead(void);
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
 * Can change the child process’ user/group id. This happens only when the appropriate bits are
 * set in the flags fields.
 * - Note:  This is not supported on Windows, uv_spawn() will fail and set the error to UV_ENOTSUP.
 *
 * @param no_of_stdio Number of `uv_stdio_container_t` for each stream or file descriptors to
 * be passed to a child process. Use `stdio_stream()` or `stdio_fd()` functions to create.
 */
C_API spawn_options_t *spawn_opts(string env, string_t cwd, int flags, uv_uid_t uid, uv_gid_t gid, int no_of_stdio, ...);
C_API bool is_spawning(spawn_t);
C_API int spawn_handler(spawn_t child, spawn_handler_cb std_func);
C_API int spawn_atexit(spawn_t, spawn_cb exit_func);
C_API int spawn_detach(spawn_t);
C_API int spawn_pid(spawn_t);
C_API int spawn_signal(spawn_t, int sig);
```

## Synopsis

* [Coroutines (C++20)](https://en.cppreference.com/w/cpp/language/coroutines.html)

```c
/* Creates an coroutine of given function with arguments,
and add to schedular, same behavior as Go. */
C_API rid_t go(callable_t, u64, ...);

/* Returns results of an completed coroutine, by `result id`, will panic,
if called before `waitfor` returns, `coroutine` still running, or no result
possible function. */
C_API template result_for(rid_t);

/* Check status of an `result id` */
C_API bool result_is_ready(rid_t);

/* Explicitly give up the CPU for at least ms milliseconds.
Other tasks continue to run during this time. */
C_API u32 sleepfor(u32 ms);

/* Creates an coroutine of given function with argument,
and immediately execute. */
C_API void launch(func_t, u64, ...);

/* Yield execution to another coroutine and reschedule current. */
C_API void yield(void);

/* Suspends the execution of current `Generator/Coroutine`, and passing ~data~.
WILL PANIC if not an ~Generator~ function called in.
WILL `yield` until ~data~ is retrived using `yield_for`. */
C_API void yielding(void_t);

/* Creates an `Generator/Coroutine` of given function with arguments,
MUST use `yielding` to pass data, and `yield_for` to get data. */
C_API generator_t generator(callable_t, u64, ...);

/* Resume specified ~coroutine/generator~, returning data from `yielding`. */
C_API template yield_for(generator_t);

/* Return `generator id` in scope for last `yield_for` execution. */
C_API rid_t yield_id(void);

/* Defer execution `LIFO` of given function with argument,
to when current coroutine exits/returns. */
C_API void defer(func_t, void_t);

/* Same as `defer` but allows recover from an Error condition throw/panic,
you must call `catching` inside function to mark Error condition handled. */
C_API void defer_recover(func_t, void_t);

/* Compare `err` to current error condition of coroutine,
will mark exception handled, if `true`. */
C_API bool catching(string_t);

/* Get current error condition string. */
C_API string_t catch_message(void);

/* Creates/initialize the next series/collection of coroutine's created
to be part of `wait group`, same behavior of Go's waitGroups.

All coroutines here behaves like regular functions, meaning they return values,
and indicate a terminated/finish status.

The initialization ends when `waitfor` is called, as such current coroutine will pause,
and execution will begin and wait for the group of coroutines to finished. */
C_API waitgroup_t waitgroup(void);
C_API waitgroup_t waitgroup_ex(u32 capacity);

/* Pauses current coroutine, and begin execution of coroutines in `wait group` object,
will wait for all to finish.

Returns `vector/array` of `results id`, accessible using `result_for` function. */
C_API waitresult_t waitfor(waitgroup_t);

C_API awaitable_t async(callable_t, u64, ...);
C_API template await(awaitable_t);

/* Return handle to current coroutine. */
C_API routine_t *coro_active(void);

C_API void coro_data_set(routine_t *, void_t data);
C_API void_t coro_data(void);
C_API void_t get_coro_data(routine_t *);

C_API memory_t *coro_scope(void);
C_API memory_t *get_coro_scope(routine_t *);

/* Calls ~fn~ (with ~number of args~ then ~actaul arguments~) in separate thread,
returning without waiting for the execution of ~fn~ to complete.
The value returned by ~fn~ can be accessed
by calling `thrd_get()`. */
C_API future thrd_async(thrd_func_t fn, size_t, ...);

/* Calls ~fn~ (with ~args~ as argument) in separate thread, returning without waiting
for the execution of ~fn~ to complete. The value returned by ~fn~ can be accessed
by calling `thrd_get()`. */
C_API future thrd_launch(thrd_func_t fn, void_t args);

/* Returns the value of `future` ~promise~, a thread's shared object, If not ready, this
function blocks the calling thread and waits until it is ready. */
C_API template_t thrd_get(future);

/* This function blocks the calling thread and waits until `future` is ready,
will execute provided `yield` callback function continuously. */
C_API void thrd_wait(future, wait_func yield);

/* Same as `thrd_wait`, but `yield` execution to another coroutine and reschedule current,
until `thread` ~future~ is ready, completed execution. */
C_API void thrd_until(future);

/* Check status of `future` object state, if `true` indicates thread execution has ended,
any call thereafter to `thrd_get` is guaranteed non-blocking. */
C_API bool thrd_is_done(future);
C_API uintptr_t thrd_self(void);
C_API size_t thrd_cpu_count(void);

/* Return/create an arbitrary `vector/array` set of `values`,
only available within `thread/future` */
C_API vectors_t thrd_data(size_t, ...);

/* Return/create an single `vector/array` ~value~,
only available within `thread/future` */
#define $(val) thrd_data(1, (val))

/* Return/create an pair `vector/array` ~values~,
only available within `thread/future` */
#define $$(val1, val2) thrd_data(2, (val1), (val2))

/* Request/return raw memory of given `size`,
using smart memory pointer's lifetime scope handle.
DO NOT `free`, will be freed with given `func`,
when scope smart pointer panics/returns/exits. */
C_API void_t malloc_full(memory_t *scope, size_t size, func_t func);

/* Request/return raw memory of given `size`,
using smart memory pointer's lifetime scope handle.
DO NOT `free`, will be freed with given `func`,
when scope smart pointer panics/returns/exits. */
C_API void_t calloc_full(memory_t *scope, int count, size_t size, func_t func);

/* Returns protected raw memory pointer of given `size`,
DO NOT FREE, will `throw/panic` if memory request fails.
This uses current `context` smart pointer, being in `guard` blocks,
inside `thread/future`, or active `coroutine` call. */
C_API void_t malloc_local(size_t size);

/* Returns protected raw memory pointer of given `size`,
DO NOT FREE, will `throw/panic` if memory request fails.
This uses current `context` smart pointer, being in `guard` blocks,
inside `thread/future`, or active `coroutine` call. */
C_API void_t calloc_local(int count, size_t size);
```

Should only be used for the development of a *function* to this **library**, to intergrate into **libuv** callback system.

```c
/* Prepare/mark next `Go/coroutine` as `interrupt` event to be ~detached~. */
C_API void coro_mark(void);

/* Set name on `Go` result `id`, and finish an previous `coro_mark` ~interrupt~ setup. */
C_API routine_t *coro_unmark(rid_t cid, string_t name);

/* Detach an `interrupt` coroutine that was `coro_mark`, will not prevent system from shuting down. */
C_API void coro_detached(routine_t *);

/* This function forms the basics for `integrating` with an `callback/event loop` like system.
Internally referenced as an `interrupt`.

The function provided and arguments will be launch in separate coroutine,
there should be an `preset` callback having either:

- `coro_await_finish(routine_t *co, void_t result, ptrdiff_t plain, bool is_plain)`
- `coro_await_exit`
- `coro_await_upgrade`

These functions are designed to break the `waitfor` loop, set `result`, and `return` to ~caller~.
The launched coroutine should first call `coro_active()` and store the `required` context. */
C_API template coro_await(callable_t, size_t, ...);

/* Create an coroutine and immediately execute, intended to be used to launch
another coroutine like `coro_await` to create an background `interrupt` coroutine. */
C_API void coro_launch(callable_t fn, u64 num_of_args, ...);

/* Same as `coro_await_finish`, but adding conditionals to either `stop` or `switch`.
Should be used to control `waitfor` loop, can `continue` after returning some `temporay data/result`.

Meant for `special` network connection handling. */
C_API void coro_await_upgrade(routine_t *co, void_t result, ptrdiff_t plain, bool is_plain,
                              bool halted, bool switching);

/* Similar to `coro_await_upgrade`, but does not ~halt/exit~,
should be used for `Generator` callback handling.
WILL switch to `generator` function `called` then ~conditionally~ back to `caller`. */
C_API void coro_await_yield(routine_t *co, void_t result, ptrdiff_t plain, bool is_plain, bool switching);

/* Should be used inside an `preset` callback, this function:
- signal `coroutine` in `waitfor` loop to `stop`.
- set `result`, either `pointer` or `non-pointer` return type.
- then `switch` to stored `coroutine context` to return to `caller`.

Any `resource` release `routines` should be placed after this function. */
C_API void coro_await_finish(routine_t *co, void_t result, ptrdiff_t plain, bool is_plain);

/* Similar to `coro_await_finish`, but should be used for exiting some
 `background running coroutine` to perform cleanup. */
C_API void coro_await_exit(routine_t *co, void_t result, ptrdiff_t plain, bool is_plain);

/* Should be used as part of `coro_await` initialization function to
indicate an `error` condition, where the `preset` callback WILL NOT be called.
- This will `set` coroutine to `error state` then `switch` to stored `coroutine context`
to return to `caller`. */
C_API void coro_await_canceled(routine_t *, signed int code);

/* Should be used as part of an `preset` ~interrupt~ callback
to `record/indicate` an `error` condition. */
C_API void_t coro_await_erred(routine_t *, int);
```

## Usage

### See [examples](https://github.com/zelang-dev/c-asio/tree/main/examples) and [tests](https://github.com/zelang-dev/c-asio/tree/main/tests) folder

## Installation

The build system uses **cmake**, that produces **static** libraries by default.

**Linux**

```shell
mkdir build
cd build
cmake .. -D CMAKE_BUILD_TYPE=Debug/Release -D BUILD_EXAMPLES=ON -D BUILD_TESTS=ON # use to build files in tests/examples folder
cmake --build .
```

**Windows**

```shell
mkdir build
cd build
cmake .. -D BUILD_EXAMPLES=ON -D BUILD_TESTS=ON # use to build files in tests/examples folder
cmake --build . --config Debug/Release
```

## Contributing

Contributions are encouraged and welcome; I am always happy to get feedback or pull requests on Github :) Create [Github Issues](https://github.com/zelang-dev/c-asio/issues) for bugs and new features and comment on the ones you are interested in.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
