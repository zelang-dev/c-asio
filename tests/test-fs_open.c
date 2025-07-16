#include "assertions.h"

/******hello  world******/

string buf = "blablabla";
string path = "write.temp";
string dir_path = "tmp_dir";
string ren_path = "tmp_temp";
string scan_path = "scandir";
string_t watch_path = "watchdir";

void_t worker3(params_t args) {
    ASSERT_WORKER(($size(args) == 2));
    delay(args[0].u_int);
    ASSERT_WORKER((args[0].u_int == 25));
    ASSERT_WORKER(is_str_eq("worker", args[1].char_ptr));
    return "finish";
}

TEST(fs_open) {
    rid_t res = go(worker3, 2, 25, "worker");
    ASSERT_EQ(fs_open("does_not_exist", O_RDONLY, 0), UV_ENOENT);
    printf("\nWill indicate memory leak at exit, no `fs_close()`.\n");
    uv_file fd = fs_open(__FILE__, O_RDONLY, 0);
    ASSERT_TRUE((fd > 0));
    ASSERT_STR("/******hello  world******/", str_trim(fs_read(fd, 27), 26));
    while (!result_is_ready(res)) {
        yield();
    }

    ASSERT_TRUE(result_is_ready(res));
    ASSERT_STR(result_for(res).char_ptr, "finish");

    return 0;
}

TEST(list) {
    int result = 0;

    EXEC_TEST(fs_open);

    return result;
}

int uv_main(int argc, char **argv) {
    TEST_FUNC(list());
}