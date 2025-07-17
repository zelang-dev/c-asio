# uv_coroutine

[![windows & linux & macOS](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci.yml)[![macOS](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_macos.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_macos.yml)[![armv7, aarch64, ppc64le](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu_others.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu_others.yml)[![riscv64 & s390x by ucontext  .](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu.yml/badge.svg)](https://github.com/zelang-dev/uv_coroutine/actions/workflows/ci_qemu.yml)

## Table of Contents

* [Introduction](#introduction)
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

    fprintf(stderr, "%s\033[0K\n", dns->ip_addr);
    uv_stream_t *server = stream_connect_ex(RAII_SCHEME_TCP, dns->ip_addr, 6667);
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

## Synopsis

```c

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
