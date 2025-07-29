# uv_coroutine

[![windows & linux & macOS](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci.yml)[![macOS](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_macos.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_macos.yml)[![armv7, aarch64, ppc64le](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu_others.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu_others.yml)[![riscv64 & s390x by ucontext  .](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu.yml)

## Table of Contents

* [Introduction](#introduction)
* [Design](#design)
* [Synopsis](#synopsis)
* [Usage](#usage)
* [Installation](#installation)
* [Contributing](#contributing)
* [License](#license)

## Introduction

This library provides **ease of use** *convenience* wrappers for **[libuv](http://docs.libuv.org)** combined with the power of **[c-raii](https://zelang-dev.github.io/c-raii)**, a **high level memory management** library similar to other languages, among other features. Like **[coroutine](https://github.com/zelang-dev/c-raii/blob/main/include/coro.h)** support, the otherwise **callback** needed, is now automatically back to the caller with *results*.

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
#include "uv_coro.h"

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
#include "uv_coro.h"

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
#include "uv_coro.h"

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
#include "uv_coro.h"

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
#include "uv_coro.h"

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
#include "uv_coro.h"

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
The *[tests](https://github.com/dermesser/uvco/tree/master/test)* presented there currently being reimplemented for *C89* here, this project will be considered stable when *completed*. And another approach in [libasync](https://github.com/btrask/libasync) mixing [libco](https://github.com/higan-emu/libco) with **libuv**. Both approaches are **Linux** only.

## Design

The *intergration* pattern for all **libuv** functions taking *callback* is as [queue-work.c](https://github.com/zelang-dev/uv_coroutine/tree/main/examples/queue-work.c) example:

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

The **main thread** determines and move *coroutines* from *global queue* to each *thread queue*.

Each **thread's** *scheduler* manages it's own *local* **run queue** of *coroutines* by ~thread local storage~.
It takes `coroutine tasks` from it's ~tempararay~ *FIFO queue* to *local storage*.

All **libuv** functions *outlined* is as **example**, but a `waitgroup_ex(1)` of *one*.
Currently, demonstrating `true` *libuv/Coroutine* **multi threading** is *disabled* by how current *tests* and *examples* startup.

If the number of *coroutines created* before first `yield()` encountered does not equal **cpu core** *count* plus *one*.
Then **main thread** will move all *coroutines* to itself, set each *coroutine* `thread id` to itself,
and *mark* whole system feature *disabled*.

## Synopsis

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

## Usage

### See [examples](https://github.com/zelang-dev/uv_coroutine/tree/main/examples) and [tests](https://github.com/zelang-dev/uv_coroutine/tree/main/tests) folder

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

Contributions are encouraged and welcome; I am always happy to get feedback or pull requests on Github :) Create [Github Issues](https://github.com/zelang-dev/uv_coroutine/issues) for bugs and new features and comment on the ones you are interested in.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
