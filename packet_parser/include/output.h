/**
 * @file output.h
 * @brief 输出格式模块
 * @description 支持TEXT、JSON、CSV等多种输出格式
 * @version 3.2
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include <stdint.h>
#include "parser.h"
#include "pcap_parser.h"

/* 输出格式类型 */
typedef enum {
    OUTPUT_FORMAT_TEXT = 0,     /* 人类可读文本 (默认) */
    OUTPUT_FORMAT_JSON,         /* JSON格式 */
    OUTPUT_FORMAT_CSV,          /* CSV格式 */
    OUTPUT_FORMAT_JSONL         /* JSON Lines (每行一条记录) */
} output_format_t;

/* 输出上下文 */
typedef struct {
    output_format_t format;     /* 输出格式 */
    FILE *fp;                   /* 输出文件指针 (NULL=stdout) */
    int pretty;                 /* 美化输出 (JSON) */
    int with_header;            /* 包含CSV头 */
    int packet_count;           /* 已输出数据包数 */
    int first_record;           /* 是否第一条记录 (JSON数组) */
} output_context_t;

/* ======================= API函数 ======================= */

/**
 * @brief 初始化输出上下文
 * @param ctx 输出上下文
 * @param format 输出格式
 * @param filename 输出文件名 (NULL=stdout)
 * @return 0成功, -1失败
 */
int output_init(output_context_t *ctx, output_format_t format, const char *filename);

/**
 * @brief 关闭输出
 */
void output_close(output_context_t *ctx);

/**
 * @brief 输出文件头 (CSV标题行, JSON数组开始)
 */
void output_header(output_context_t *ctx);

/**
 * @brief 输出文件尾 (JSON数组结束)
 */
void output_footer(output_context_t *ctx);

/**
 * @brief 输出数据包信息
 */
void output_packet(output_context_t *ctx, const packet_info_t *pkt,
                   const ethernet_header_t *eth, const vlan_info_t *vlan,
                   const ipv4_info_t *ipv4, const ipv6_info_t *ipv6,
                   const tcp_info_t *tcp, const udp_info_t *udp,
                   const icmp_info_t *icmp, const arp_info_t *arp);

/**
 * @brief 输出统计信息
 */
void output_stats(output_context_t *ctx, const pcap_stats_t *stats,
                  uint32_t eth_count, uint32_t ipv4_count, uint32_t ipv6_count,
                  uint32_t tcp_count, uint32_t udp_count, uint32_t icmp_count,
                  uint32_t arp_count);

/**
 * @brief 解析输出格式字符串
 */
output_format_t parse_output_format(const char *str);

/**
 * @brief 获取输出格式名称
 */
const char* output_format_name(output_format_t format);

/* ======================= JSON 辅助函数 ======================= */

/**
 * @brief 输出JSON字符串 (自动转义)
 */
void json_write_string(FILE *fp, const char *str);

/**
 * @brief 输出MAC地址为JSON字符串
 */
void json_write_mac(FILE *fp, const uint8_t *mac);

/**
 * @brief 输出IPv4地址为JSON字符串
 */
void json_write_ipv4(FILE *fp, uint32_t ip);

/**
 * @brief 输出IPv6地址为JSON字符串
 */
void json_write_ipv6(FILE *fp, const uint8_t *ip);

#endif /* OUTPUT_H */
