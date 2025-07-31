
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
