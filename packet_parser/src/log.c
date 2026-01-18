/**
 * @file log.c
 * @brief 企业级日志系统实现
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include "../include/log.h"

/* 全局日志配置 */
log_config_t g_log_config = {
    .level = LOG_LEVEL_INFO,
    .output = NULL,
    .use_color = 1,
    .show_timestamp = 1,
    .show_file_line = 0,
    .log_file = {0}
};

/* 级别对应的颜色 */
static const char* level_colors[] = {
    LOG_COLOR_TRACE,    /* TRACE */
    LOG_COLOR_DEBUG,    /* DEBUG */
    LOG_COLOR_INFO,     /* INFO */
    LOG_COLOR_WARN,     /* WARN */
    LOG_COLOR_ERROR,    /* ERROR */
    LOG_COLOR_FATAL     /* FATAL */
};

/* 级别名称 */
static const char* level_names[] = {
    "TRACE",
    "DEBUG",
    "INFO ",
    "WARN ",
    "ERROR",
    "FATAL"
};

/**
 * @brief 初始化日志系统
 */
void log_init(log_level_t level, const char *log_file) {
    g_log_config.level = level;
    g_log_config.output = stderr;
    g_log_config.use_color = 1;
    g_log_config.show_timestamp = 1;
    g_log_config.show_file_line = 0;
    
    if (log_file && strlen(log_file) > 0) {
        FILE *fp = fopen(log_file, "a");
        if (fp) {
            g_log_config.output = fp;
            g_log_config.use_color = 0;  /* 文件输出不使用颜色 */
            strncpy(g_log_config.log_file, log_file, sizeof(g_log_config.log_file) - 1);
        }
    }
}

/**
 * @brief 关闭日志系统
 */
void log_shutdown(void) {
    if (g_log_config.output && 
        g_log_config.output != stderr && 
        g_log_config.output != stdout) {
        fclose(g_log_config.output);
    }
    g_log_config.output = stderr;
}

/**
 * @brief 设置日志级别
 */
void log_set_level(log_level_t level) {
    g_log_config.level = level;
}

/**
 * @brief 获取当前日志级别
 */
log_level_t log_get_level(void) {
    return g_log_config.level;
}

/**
 * @brief 启用/禁用颜色输出
 */
void log_set_color(int enable) {
    g_log_config.use_color = enable;
}

/**
 * @brief 启用/禁用时间戳
 */
void log_set_timestamp(int enable) {
    g_log_config.show_timestamp = enable;
}

/**
 * @brief 启用/禁用文件行号
 */
void log_set_file_line(int enable) {
    g_log_config.show_file_line = enable;
}

/**
 * @brief 获取级别名称
 */
const char* log_level_name(log_level_t level) {
    if (level >= LOG_LEVEL_TRACE && level <= LOG_LEVEL_FATAL) {
        return level_names[level];
    }
    return "UNKNOWN";
}

/**
 * @brief 从字符串解析日志级别
 */
log_level_t log_level_from_string(const char *str) {
    if (!str) return LOG_LEVEL_INFO;
    
    if (strcasecmp(str, "trace") == 0) return LOG_LEVEL_TRACE;
    if (strcasecmp(str, "debug") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "info") == 0)  return LOG_LEVEL_INFO;
    if (strcasecmp(str, "warn") == 0)  return LOG_LEVEL_WARN;
    if (strcasecmp(str, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "fatal") == 0) return LOG_LEVEL_FATAL;
    if (strcasecmp(str, "off") == 0)   return LOG_LEVEL_OFF;
    
    return LOG_LEVEL_INFO;
}

/**
 * @brief 获取时间戳字符串
 */
static void get_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * @brief 提取文件名 (不含路径)
 */
static const char* extract_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (!filename) {
        filename = strrchr(path, '\\');
    }
    return filename ? filename + 1 : path;
}

/**
 * @brief 核心日志函数
 */
void log_write(log_level_t level, const char *file, int line, 
               const char *fmt, ...) {
    /* 检查日志级别 */
    if (level < g_log_config.level || level >= LOG_LEVEL_OFF) {
        return;
    }
    
    FILE *out = g_log_config.output ? g_log_config.output : stderr;
    
    /* 时间戳 */
    if (g_log_config.show_timestamp) {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(out, "[%s] ", timestamp);
    }
    
    /* 级别 (带颜色) */
    if (g_log_config.use_color) {
        fprintf(out, "%s[%s]%s ", 
                level_colors[level], 
                level_names[level],
                LOG_COLOR_RESET);
    } else {
        fprintf(out, "[%s] ", level_names[level]);
    }
    
    /* 文件和行号 */
    if (g_log_config.show_file_line && file) {
        fprintf(out, "(%s:%d) ", extract_filename(file), line);
    }
    
    /* 消息内容 */
    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    
    fprintf(out, "\n");
    fflush(out);
}
