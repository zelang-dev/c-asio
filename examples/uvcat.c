
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
