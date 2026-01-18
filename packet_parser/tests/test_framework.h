/**
 * @file test_framework.h
 * @brief 轻量级单元测试框架
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

/* 测试统计 */
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

/* 颜色定义 */
#define TEST_COLOR_RED     "\033[31m"
#define TEST_COLOR_GREEN   "\033[32m"
#define TEST_COLOR_YELLOW  "\033[33m"
#define TEST_COLOR_RESET   "\033[0m"
#define TEST_COLOR_BOLD    "\033[1m"

/* 断言宏 */
#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf(TEST_COLOR_GREEN "  [PASS] " TEST_COLOR_RESET "%s\n", msg); \
    } else { \
        g_tests_failed++; \
        printf(TEST_COLOR_RED "  [FAIL] " TEST_COLOR_RESET "%s (line %d)\n", msg, __LINE__); \
    } \
} while(0)

#define TEST_ASSERT_EQ(expected, actual, msg) \
    TEST_ASSERT((expected) == (actual), msg)

#define TEST_ASSERT_NE(expected, actual, msg) \
    TEST_ASSERT((expected) != (actual), msg)

#define TEST_ASSERT_TRUE(cond, msg) \
    TEST_ASSERT((cond), msg)

#define TEST_ASSERT_FALSE(cond, msg) \
    TEST_ASSERT(!(cond), msg)

#define TEST_ASSERT_NULL(ptr, msg) \
    TEST_ASSERT((ptr) == NULL, msg)

#define TEST_ASSERT_NOT_NULL(ptr, msg) \
    TEST_ASSERT((ptr) != NULL, msg)

#define TEST_ASSERT_MEM_EQ(expected, actual, len, msg) \
    TEST_ASSERT(memcmp(expected, actual, len) == 0, msg)

/* 测试套件宏 */
#define TEST_SUITE_BEGIN(name) do { \
    printf(TEST_COLOR_BOLD "\n[TEST SUITE] %s\n" TEST_COLOR_RESET, name); \
    printf("─────────────────────────────────────────\n"); \
} while(0)

#define TEST_SUITE_END() do { \
    printf("─────────────────────────────────────────\n"); \
} while(0)

/* 测试用例宏 */
#define TEST_CASE(name) do { \
    printf(TEST_COLOR_YELLOW "\n[TEST] %s\n" TEST_COLOR_RESET, name); \
} while(0)

/* 打印测试摘要 */
static inline void test_print_summary(void) {
    printf(TEST_COLOR_BOLD "\n═══════════════════════════════════════════════\n");
    printf("                Test Summary                    \n");
    printf("═══════════════════════════════════════════════\n" TEST_COLOR_RESET);
    printf("Total:  %d\n", g_tests_run);
    printf(TEST_COLOR_GREEN "Passed: %d" TEST_COLOR_RESET "\n", g_tests_passed);
    if (g_tests_failed > 0) {
        printf(TEST_COLOR_RED "Failed: %d" TEST_COLOR_RESET "\n", g_tests_failed);
    } else {
        printf("Failed: %d\n", g_tests_failed);
    }
    printf("═══════════════════════════════════════════════\n");
    
    if (g_tests_failed == 0) {
        printf(TEST_COLOR_GREEN TEST_COLOR_BOLD "\n✓ All tests passed!\n" TEST_COLOR_RESET);
    } else {
        printf(TEST_COLOR_RED TEST_COLOR_BOLD "\n✗ Some tests failed!\n" TEST_COLOR_RESET);
    }
}

/* 返回测试结果 */
static inline int test_get_result(void) {
    return (g_tests_failed == 0) ? 0 : 1;
}

#endif /* TEST_FRAMEWORK_H */
