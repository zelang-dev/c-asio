#ifndef TEST_ASSERT_H_
#define TEST_ASSERT_H_

#include "asio.h"
#include <assert.h>

inline void assert_expected(long res, long expected, const char *file, unsigned int line, const char *expr, const char *expected_str) {
    if (res != expected) {
        fflush(stdout);
        fprintf(stderr, "%s:%u: %s: error %li, expected %s\033[0K\n", file, line, expr, res, expected_str);
        abort();
    }
}

#define CHK_EXPECTED(a, b) assert_expected(a, b, __FILE__, __LINE__, #a, #b)

#define EXEC_TEST(name) \
    if (test_##name() != 0) { result = -1; printf( #name ": fail\033[0K\n\n"); } \
    else { printf(#name ": pass\033[0K\n\n"); }

#define TEST(name)  int test_##name(void)

#ifdef __linux__
#  define PRINT_COLOR
#endif

#ifdef PRINT_COLOR
#  define COLOR_RED  "\x1B[31m"
#  define COLOR_GREEN  "\x1B[32m"
#  define COLOR_RESET "\033[0m"
#else
#  define COLOR_RED
#  define COLOR_GREEN
#  define COLOR_RESET
#endif

#define PRINT_ERR(...) printf(COLOR_RED "Failure" COLOR_RESET __VA_ARGS__)
#define PRINT_OK(...) printf(COLOR_GREEN "Passed" COLOR_RESET __VA_ARGS__)

#define ASSERT_EQ_(expected, actual, cmp, print_op) do { \
    if (!(cmp)) \
      { \
	PRINT_ERR(" %s %d:\n   * %s != %s\n   * Expected: " print_op	\
          "\n   * Actual: " print_op "\n", __FILE__, __LINE__, \
          #expected, #actual, expected, actual); \
    return 1; \
      } \
    PRINT_OK(" %s == %s\033[0K\n", #expected, #actual); \
  } while (0)

#define ASSERT_ERR_(expected, actual, cmp, print_op) do { \
    if (!(cmp)) \
      { \
	PRINT_ERR(" %s %d:\n   * %s != %s\n   * Expected: " print_op	\
          "\n   * Actual: " print_op "\n", __FILE__, __LINE__, \
          #expected, #actual, expected, actual); \
    return $$$(1); \
      } \
    PRINT_OK(" %s == %s\033[0K\n", #expected, #actual); \
  } while (0)

#define ASSERT_THREAD_EQ(expected, actual, cmp, print_op) do { \
    if (!(cmp)) \
      { \
	PRINT_ERR(" %s %d:\n   * %s != %s\n   * Expected: " print_op	\
          "\n   * Actual: " print_op "\n", __FILE__, __LINE__, \
          #expected, #actual, expected, actual); \
    return 0; \
      } \
    PRINT_OK(" %s == %s\033[0K\n", #expected, #actual); \
  } while (0)

#define ASSERT_NEQ_(expected, actual, cmp, print_op) do { \
    if (!(cmp)) \
      { \
	PRINT_ERR(" %s %d:\n   * %s == %s\n   * Expected: " print_op	\
          "\n   * Actual: " print_op "\n", __FILE__, __LINE__, \
          #expected, #actual, expected, actual); \
    return 1; \
      } \
    PRINT_OK(" %s != %s\033[0K\n", #expected, #actual); \
  } while (0)

#define ASSERT_STR(expected, actual) ASSERT_EQ_(expected, actual, strcmp(expected, actual) == 0, "%s")
#define ASSERT_PTR(expected, actual) ASSERT_EQ_(expected, actual, memcmp(expected, actual, sizeof(actual)) == 0, "%p")
#define ASSERT_UEQ(expected, actual) ASSERT_EQ_((long unsigned)expected, actual, expected == actual, "%lu")
#define ASSERT_DOUBLE(expected, actual) ASSERT_EQ_(expected, actual, expected == actual, "%f")
#define ASSERT_EQ(expected, actual) ASSERT_EQ_((int)expected, actual, expected == actual, "%d")
#define ASSERT_EQU(expected, actual) ASSERT_ERR_((int)expected, actual, expected == actual, "%d")
#define ASSERT_CHAR(expected, actual) ASSERT_EQ_((char)expected, (char)actual, expected == actual, "%c")
#define ASSERT_LEQ(expected, actual) ASSERT_EQ_(expected, actual, expected == actual, "%i")
#define ASSERT_XEQ(expected, actual) ASSERT_EQ_((long)(expected), (long)(actual), expected == actual, "%ld")
#define ASSERT_NULL(actual) ASSERT_EQ_(NULL, actual, NULL == actual, "%p")
#define ASSERT_NOTNULL(actual) ASSERT_NEQ_(NULL, actual, NULL != actual, "%p")
#define ASSERT_TRUE(actual) ASSERT_EQ_(true, actual, true == actual, "%c")
#define ASSERT_FALSE(actual) ASSERT_EQ_(false, actual, false == actual, "%d")
#define ASSERT_THREAD(actual) ASSERT_THREAD_EQ(true, actual, true == actual, "%c")
#define ASSERT_WORKER(actual) ASSERT_THREAD_EQ(true, actual, true == actual, "%c")

#define ASSERT_FUNC(FNC_CALL) do { \
    if (FNC_CALL) { \
      return 1; \
    } \
  } while (0)

#define TEST_FUNC(name) ASSERT_FUNC(test_##name);  \
    printf("\nAll tests successful!\n"); \
    return 0
#endif
