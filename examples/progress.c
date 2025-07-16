#define USE_CORO
#include "raii.h"

double percentage;

void_t fake_download(args_t req) {
    int size = req->integer;
    int downloaded = 0;
    while (downloaded < size) {
        percentage = downloaded*100.0/size;
        usleep(500);
        downloaded += (200+random())%1000; // can only download max 1000bytes/sec,
                                           // but at least a 200;
    }

    return $(downloaded);
}

void print_progress(void) {
    fprintf(stderr, "Downloaded %.2f%%\033[0K\n", percentage);
    coro_yield_info();
}

int main(int argc, char **argv) {
    int size = 10240;
    future fut = thrd_launch(fake_download, casting(size));

    if (!thrd_is_done(fut))
        thrd_wait(fut, print_progress);

    fprintf(stderr, "\n\nDownload complete: %d Total\033[0K\n", thrd_get(fut).integer);

    return 0;
}
