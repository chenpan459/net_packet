/**
 * @file log.h
 * @brief 企业级日志系统
 * @description 支持多级别日志、文件输出、带时间戳
 * @version 3.0
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

/* ======================= 日志级别定义 ======================= */

typedef enum {
    LOG_LEVEL_TRACE = 0,    /* 最详细的追踪信息 */
    LOG_LEVEL_DEBUG = 1,    /* 调试信息 */
    LOG_LEVEL_INFO  = 2,    /* 一般信息 */
    LOG_LEVEL_WARN  = 3,    /* 警告信息 */
    LOG_LEVEL_ERROR = 4,    /* 错误信息 */
    LOG_LEVEL_FATAL = 5,    /* 致命错误 */
    LOG_LEVEL_OFF   = 6     /* 关闭日志 */
} log_level_t;

/* ======================= 日志配置 ======================= */

typedef struct {
    log_level_t level;          /* 当前日志级别 */
    FILE *output;               /* 输出文件指针 */
    int use_color;              /* 是否使用颜色 */
    int show_timestamp;         /* 是否显示时间戳 */
    int show_file_line;         /* 是否显示文件和行号 */
    char log_file[256];         /* 日志文件路径 */
} log_config_t;

/* ======================= 全局日志配置 ======================= */

extern log_config_t g_log_config;

/* ======================= 颜色定义 ======================= */

#define LOG_COLOR_RESET     "\033[0m"
#define LOG_COLOR_TRACE     "\033[90m"      /* 灰色 */
#define LOG_COLOR_DEBUG     "\033[36m"      /* 青色 */
#define LOG_COLOR_INFO      "\033[32m"      /* 绿色 */
#define LOG_COLOR_WARN      "\033[33m"      /* 黄色 */
#define LOG_COLOR_ERROR     "\033[31m"      /* 红色 */
#define LOG_COLOR_FATAL     "\033[35;1m"    /* 粗体紫色 */

/* ======================= API 函数 ======================= */

/**
 * @brief 初始化日志系统
 * @param level 日志级别
 * @param log_file 日志文件路径 (NULL表示只输出到控制台)
 */
void log_init(log_level_t level, const char *log_file);

/**
 * @brief 关闭日志系统
 */
void log_shutdown(void);

/**
 * @brief 设置日志级别
 */
void log_set_level(log_level_t level);

/**
 * @brief 获取当前日志级别
 */
log_level_t log_get_level(void);

/**
 * @brief 启用/禁用颜色输出
 */
void log_set_color(int enable);

/**
 * @brief 启用/禁用时间戳
 */
void log_set_timestamp(int enable);

/**
 * @brief 启用/禁用文件行号
 */
void log_set_file_line(int enable);

/**
 * @brief 核心日志函数
 */
void log_write(log_level_t level, const char *file, int line, 
               const char *fmt, ...);

/**
 * @brief 获取级别名称
 */
const char* log_level_name(log_level_t level);

/**
 * @brief 从字符串解析日志级别
 */
log_level_t log_level_from_string(const char *str);

/* ======================= 日志宏 ======================= */

#define LOG_TRACE(...) \
    log_write(LOG_LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_DEBUG(...) \
    log_write(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_INFO(...) \
    log_write(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_WARN(...) \
    log_write(LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_ERROR(...) \
    log_write(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_FATAL(...) \
    log_write(LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

/* 条件日志 */
#define LOG_IF(cond, level, ...) \
    do { if (cond) log_write(level, __FILE__, __LINE__, __VA_ARGS__); } while(0)

/* 性能追踪 */
#define LOG_PERF_START(name) \
    clock_t _perf_start_##name = clock()

#define LOG_PERF_END(name) \
    do { \
        clock_t _perf_end_##name = clock(); \
        double _perf_ms = ((double)(_perf_end_##name - _perf_start_##name)) / CLOCKS_PER_SEC * 1000.0; \
        LOG_DEBUG("[PERF] %s: %.3f ms", #name, _perf_ms); \
    } while(0)

#endif /* LOG_H */
