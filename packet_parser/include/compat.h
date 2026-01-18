/**
 * @file compat.h
 * @brief 跨平台兼容层
 * @description 提供 GCC/Clang/MSVC 兼容的类型和函数定义
 * @version 3.2
 */

#ifndef COMPAT_H
#define COMPAT_H

/* ======================= 编译器检测 ======================= */

#if defined(_MSC_VER)
    #define COMPILER_MSVC 1
    #define COMPILER_NAME "MSVC"
#elif defined(__clang__)
    #define COMPILER_CLANG 1
    #define COMPILER_NAME "Clang"
#elif defined(__GNUC__)
    #define COMPILER_GCC 1
    #define COMPILER_NAME "GCC"
#else
    #define COMPILER_UNKNOWN 1
    #define COMPILER_NAME "Unknown"
#endif

/* ======================= 平台检测 ======================= */

#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
    #define PLATFORM_NAME "Windows"
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_NAME "Linux"
#elif defined(__APPLE__)
    #define PLATFORM_MACOS 1
    #define PLATFORM_NAME "macOS"
#else
    #define PLATFORM_UNKNOWN 1
    #define PLATFORM_NAME "Unknown"
#endif

/* ======================= MSVC 兼容性 ======================= */

#ifdef COMPILER_MSVC
    /* 禁用某些警告 */
    #pragma warning(disable: 4996)  /* 'fopen' unsafe warning */
    #pragma warning(disable: 4244)  /* possible loss of data */
    #pragma warning(disable: 4267)  /* size_t to int conversion */
    
    /* POSIX 函数映射 */
    #define strncasecmp _strnicmp
    #define strcasecmp  _stricmp
    #define snprintf    _snprintf
    #define fileno      _fileno
    #define isatty      _isatty
    
    /* 定义 ssize_t (MSVC 没有) */
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
    
    /* 内联关键字 */
    #define inline __inline
    
    /* restrict 关键字 */
    #define restrict __restrict
    
    /* __attribute__ 兼容 */
    #define __attribute__(x)
    
#else /* GCC/Clang */
    
    /* 确保有 POSIX 函数 */
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif
    
    #include <strings.h>  /* strcasecmp */
    
#endif

/* ======================= 字节序检测 ======================= */

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define HOST_BIG_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define HOST_LITTLE_ENDIAN 1
#elif defined(_WIN32) || defined(__i386__) || defined(__x86_64__) || defined(__amd64__)
    /* 大多数常见平台是小端 */
    #define HOST_LITTLE_ENDIAN 1
#else
    /* 默认假设小端 */
    #define HOST_LITTLE_ENDIAN 1
#endif

/* ======================= 64位类型打印格式 ======================= */

#ifdef COMPILER_MSVC
    #define PRIu64 "I64u"
    #define PRId64 "I64d"
    #define PRIx64 "I64x"
#else
    #include <inttypes.h>
#endif

/* ======================= 静态断言 ======================= */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    /* C11 _Static_assert */
    #define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#elif defined(COMPILER_MSVC)
    #define STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
    /* 备用方案 */
    #define STATIC_ASSERT(cond, msg) \
        typedef char static_assert_##__LINE__[(cond) ? 1 : -1]
#endif

/* ======================= 对齐属性 ======================= */

#ifdef COMPILER_MSVC
    #define ALIGNED(n) __declspec(align(n))
#else
    #define ALIGNED(n) __attribute__((aligned(n)))
#endif

/* ======================= 未使用参数 ======================= */

#ifdef COMPILER_MSVC
    #define UNUSED(x) (void)(x)
#else
    #define UNUSED(x) (void)(x)
#endif

/* ======================= likely/unlikely 分支预测 ======================= */

#if defined(COMPILER_GCC) || defined(COMPILER_CLANG)
    #define likely(x)   __builtin_expect(!!(x), 1)
    #define unlikely(x) __builtin_expect(!!(x), 0)
#else
    #define likely(x)   (x)
    #define unlikely(x) (x)
#endif

/* ======================= 函数属性 ======================= */

#if defined(COMPILER_GCC) || defined(COMPILER_CLANG)
    #define PRINTF_FORMAT(fmt_idx, arg_idx) \
        __attribute__((format(printf, fmt_idx, arg_idx)))
    #define NORETURN __attribute__((noreturn))
    #define UNUSED_FUNC __attribute__((unused))
#else
    #define PRINTF_FORMAT(fmt_idx, arg_idx)
    #define NORETURN
    #define UNUSED_FUNC
#endif

/* ======================= 平台相关头文件 ======================= */

#ifdef PLATFORM_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    /* Windows 头文件在需要时包含 */
#else
    #include <unistd.h>
    #include <sys/time.h>
#endif

/* ======================= 调试输出 ======================= */

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        fprintf(stderr, "[DEBUG] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#endif /* COMPAT_H */
