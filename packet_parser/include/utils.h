/**
 * @file utils.h
 * @brief 工具函数
 * @description 字节序转换、校验和计算等通用工具
 * @version 3.0
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

/* ======================= 字节序转换 ======================= */
/* 
 * 主要的字节序转换函数 - 应用代码请使用这些函数
 * 
 * 注意: protocols.h 中也有一个内部版本 _proto_ntohs_internal，
 *       仅供该头文件中的宏定义使用，外部代码不应直接调用
 */

static inline uint16_t net_to_host16(uint16_t net) {
    return ((net >> 8) & 0xFF) | ((net << 8) & 0xFF00);
}

static inline uint32_t net_to_host32(uint32_t net) {
    return ((net >> 24) & 0x000000FF) |
           ((net >> 8)  & 0x0000FF00) |
           ((net << 8)  & 0x00FF0000) |
           ((net << 24) & 0xFF000000);
}

#define host_to_net16(h) net_to_host16(h)
#define host_to_net32(h) net_to_host32(h)

/* ======================= 校验和计算 ======================= */

/**
 * @brief 计算Internet校验和
 */
uint16_t calc_checksum(const uint8_t *data, size_t len);

/**
 * @brief 验证校验和
 */
int verify_checksum(const uint8_t *data, size_t len);

/**
 * @brief 计算带伪首部的校验和 (TCP/UDP)
 */
uint16_t calc_pseudo_checksum(const uint8_t *pseudo_hdr, size_t pseudo_len,
                               const uint8_t *data, size_t data_len);

/**
 * @brief 验证IPv4 TCP/UDP校验和
 */
int verify_transport_checksum(uint32_t src_ip, uint32_t dst_ip, 
                               uint8_t protocol,
                               const uint8_t *data, size_t len);

/**
 * @brief 验证IPv6 TCP/UDP/ICMPv6校验和
 */
int verify_transport_checksum_v6(const uint8_t *src_ip, const uint8_t *dst_ip,
                                  uint8_t protocol,
                                  const uint8_t *data, size_t len);

/* ======================= 十六进制输出 ======================= */

void hex_dump(const uint8_t *data, size_t len, int bytes_per_line);

/* ======================= 颜色输出 ======================= */

#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_BOLD      "\033[1m"

#define COLOR_CHECKSUM_OK     COLOR_GREEN
#define COLOR_CHECKSUM_ERROR  COLOR_RED
#define COLOR_CHECKSUM_SKIP   COLOR_YELLOW

/* ======================= 性能测量 ======================= */

#include <time.h>

typedef struct {
    clock_t start;
    clock_t end;
    double elapsed_ms;
} perf_timer_t;

static inline void perf_timer_start(perf_timer_t *timer) {
    timer->start = clock();
}

static inline double perf_timer_stop(perf_timer_t *timer) {
    timer->end = clock();
    timer->elapsed_ms = ((double)(timer->end - timer->start)) / CLOCKS_PER_SEC * 1000.0;
    return timer->elapsed_ms;
}

#endif /* UTILS_H */
