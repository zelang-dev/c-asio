#include "assertions.h"

string_t watch_path = "watchdir";
static int watch_count = 0;

void_t worker_misc(params_t args) {
    ASSERT_WORKER(($size(args) > 1));
    delay(args[0].u_int);
    ASSERT_WORKER(is_str_eq("event", args[1].char_ptr));
    yield();
    return "fs_watch";
}

int watch_handler(string_t filename, int events, int status) {
    ASSERT_STR("watchdir", fs_watch_path());
    watch_count++;

    if (events & UV_RENAME) {
        ASSERT_TRUE((is_str_eq("file1.txt", filename) || is_str_eq("watchdir", filename) || is_str_empty(filename)));
    }

    if (events & UV_CHANGE) {
        ASSERT_TRUE((is_str_eq("file1.txt", filename) || is_str_eq("watchdir", filename) || is_str_empty(filename)));
    }
}

TEST(fs_watch) {
    char filepath[SCRAPE_SIZE] = nil;
    int i = 0;
    rid_t res = go(worker_misc, 2, 1000, "event");
    ASSERT_EQ(0, fs_mkdir(watch_path, 0));
    ASSERT_FALSE(result_is_ready(res));

    fs_watch(watch_path, (event_cb)watch_handler);
    ASSERT_FALSE(result_is_ready(res));

    snprintf(filepath, SCRAPE_SIZE, "%s/file%d.txt", watch_path, 1);
    ASSERT_EQ(5, fs_writefile(filepath, "hello"));
    ASSERT_EQ(0, fs_unlink(filepath));

    delay(10);
    ASSERT_EQ(0, fs_rmdir(watch_path));
    while (!result_is_ready(res))
        yield();

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "fs_watch");
    ASSERT_EQ(2, watch_count);

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(fs_watch);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}