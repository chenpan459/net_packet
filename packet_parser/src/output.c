/**
 * @file output.c
 * @brief 输出格式模块实现
 * @version 3.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/output.h"
#include "../include/utils.h"
#include "../include/log.h"

/* ======================= 工具函数 ======================= */

/**
 * @brief 解析输出格式字符串
 */
output_format_t parse_output_format(const char *str) {
    if (!str) return OUTPUT_FORMAT_TEXT;
    
    if (strcasecmp(str, "text") == 0 || strcasecmp(str, "txt") == 0) {
        return OUTPUT_FORMAT_TEXT;
    } else if (strcasecmp(str, "json") == 0) {
        return OUTPUT_FORMAT_JSON;
    } else if (strcasecmp(str, "jsonl") == 0 || strcasecmp(str, "ndjson") == 0) {
        return OUTPUT_FORMAT_JSONL;
    } else if (strcasecmp(str, "csv") == 0) {
        return OUTPUT_FORMAT_CSV;
    }
    
    LOG_WARN("Unknown output format: %s, using text", str);
    return OUTPUT_FORMAT_TEXT;
}

/**
 * @brief 获取输出格式名称
 */
const char* output_format_name(output_format_t format) {
    switch (format) {
        case OUTPUT_FORMAT_TEXT:  return "text";
        case OUTPUT_FORMAT_JSON:  return "json";
        case OUTPUT_FORMAT_JSONL: return "jsonl";
        case OUTPUT_FORMAT_CSV:   return "csv";
        default:                  return "unknown";
    }
}

/**
 * @brief 初始化输出上下文
 */
int output_init(output_context_t *ctx, output_format_t format, const char *filename) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(output_context_t));
    ctx->format = format;
    ctx->pretty = 1;
    ctx->with_header = 1;
    ctx->first_record = 1;
    
    if (filename) {
        ctx->fp = fopen(filename, "w");
        if (!ctx->fp) {
            LOG_ERROR("Cannot open output file: %s", filename);
            return -1;
        }
        LOG_INFO("Output to file: %s (format=%s)", filename, output_format_name(format));
    } else {
        ctx->fp = stdout;
    }
    
    return 0;
}

/**
 * @brief 关闭输出
 */
void output_close(output_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->fp && ctx->fp != stdout) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
}

/* ======================= JSON 辅助函数 ======================= */

/**
 * @brief 输出JSON字符串 (自动转义)
 */
void json_write_string(FILE *fp, const char *str) {
    if (!fp) return;
    
    fputc('"', fp);
    if (str) {
        while (*str) {
            switch (*str) {
                case '"':  fprintf(fp, "\\\""); break;
                case '\\': fprintf(fp, "\\\\"); break;
                case '\n': fprintf(fp, "\\n"); break;
                case '\r': fprintf(fp, "\\r"); break;
                case '\t': fprintf(fp, "\\t"); break;
                default:
                    if ((unsigned char)*str < 0x20) {
                        fprintf(fp, "\\u%04x", (unsigned char)*str);
                    } else {
                        fputc(*str, fp);
                    }
            }
            str++;
        }
    }
    fputc('"', fp);
}

/**
 * @brief 输出MAC地址为JSON字符串
 */
void json_write_mac(FILE *fp, const uint8_t *mac) {
    if (!fp || !mac) return;
    fprintf(fp, "\"%02x:%02x:%02x:%02x:%02x:%02x\"",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * @brief 输出IPv4地址为JSON字符串
 */
void json_write_ipv4(FILE *fp, uint32_t ip) {
    if (!fp) return;
    uint8_t *bytes = (uint8_t *)&ip;
    fprintf(fp, "\"%u.%u.%u.%u\"", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * @brief 输出IPv6地址为JSON字符串
 */
void json_write_ipv6(FILE *fp, const uint8_t *ip) {
    if (!fp || !ip) return;
    fprintf(fp, "\"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\"",
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
}

/* ======================= 输出头尾 ======================= */

/**
 * @brief 输出文件头
 */
void output_header(output_context_t *ctx) {
    if (!ctx || !ctx->fp) return;
    
    switch (ctx->format) {
        case OUTPUT_FORMAT_JSON:
            fprintf(ctx->fp, "{\n  \"packets\": [\n");
            break;
            
        case OUTPUT_FORMAT_CSV:
            if (ctx->with_header) {
                fprintf(ctx->fp, "packet_num,timestamp,src_mac,dst_mac,eth_type,"
                        "vlan_id,src_ip,dst_ip,protocol,src_port,dst_port,"
                        "tcp_flags,icmp_type,length\n");
            }
            break;
            
        default:
            break;
    }
}

/**
 * @brief 输出文件尾
 */
void output_footer(output_context_t *ctx) {
    if (!ctx || !ctx->fp) return;
    
    switch (ctx->format) {
        case OUTPUT_FORMAT_JSON:
            fprintf(ctx->fp, "\n  ]\n}\n");
            break;
            
        default:
            break;
    }
}

/* ======================= 数据包输出 ======================= */

/**
 * @brief 输出JSON格式数据包
 */
static void output_packet_json(output_context_t *ctx, const packet_info_t *pkt,
                               const ethernet_header_t *eth, const vlan_info_t *vlan,
                               const ipv4_info_t *ipv4, const ipv6_info_t *ipv6,
                               const tcp_info_t *tcp, const udp_info_t *udp,
                               const icmp_info_t *icmp, const arp_info_t *arp) {
    FILE *fp = ctx->fp;
    const char *indent = ctx->format == OUTPUT_FORMAT_JSONL ? "" : "    ";
    const char *newline = ctx->format == OUTPUT_FORMAT_JSONL ? "" : "\n";
    
    /* JSON数组分隔符 */
    if (ctx->format == OUTPUT_FORMAT_JSON) {
        if (!ctx->first_record) {
            fprintf(fp, ",\n");
        }
        ctx->first_record = 0;
    }
    
    fprintf(fp, "%s{%s", indent, newline);
    
    /* 基本信息 */
    fprintf(fp, "%s  \"packet_number\": %u,%s", indent, pkt->packet_number, newline);
    fprintf(fp, "%s  \"timestamp\": %u.%06u,%s", indent, 
            pkt->timestamp_sec, pkt->timestamp_usec, newline);
    fprintf(fp, "%s  \"captured_length\": %u,%s", indent, pkt->captured_len, newline);
    fprintf(fp, "%s  \"original_length\": %u,%s", indent, pkt->original_len, newline);
    
    /* 以太网 */
    if (eth) {
        fprintf(fp, "%s  \"ethernet\": {%s", indent, newline);
        fprintf(fp, "%s    \"src_mac\": ", indent);
        json_write_mac(fp, eth->src_mac);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"dst_mac\": ", indent);
        json_write_mac(fp, eth->dst_mac);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"ether_type\": \"0x%04X\"%s", indent, eth->ether_type, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* VLAN */
    if (vlan && vlan->vlan_id > 0) {
        fprintf(fp, "%s  \"vlan\": {%s", indent, newline);
        fprintf(fp, "%s    \"id\": %u,%s", indent, vlan->vlan_id, newline);
        fprintf(fp, "%s    \"priority\": %u%s", indent, vlan->priority, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* IPv4 */
    if (ipv4) {
        fprintf(fp, "%s  \"ipv4\": {%s", indent, newline);
        fprintf(fp, "%s    \"src_ip\": ", indent);
        json_write_ipv4(fp, ipv4->src_ip);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"dst_ip\": ", indent);
        json_write_ipv4(fp, ipv4->dst_ip);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"protocol\": %u,%s", indent, ipv4->protocol, newline);
        fprintf(fp, "%s    \"ttl\": %u%s", indent, ipv4->ttl, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* IPv6 */
    if (ipv6) {
        fprintf(fp, "%s  \"ipv6\": {%s", indent, newline);
        fprintf(fp, "%s    \"src_ip\": ", indent);
        json_write_ipv6(fp, ipv6->src_ip);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"dst_ip\": ", indent);
        json_write_ipv6(fp, ipv6->dst_ip);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"next_header\": %u,%s", indent, ipv6->next_header, newline);
        fprintf(fp, "%s    \"hop_limit\": %u%s", indent, ipv6->hop_limit, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* TCP */
    if (tcp) {
        fprintf(fp, "%s  \"tcp\": {%s", indent, newline);
        fprintf(fp, "%s    \"src_port\": %u,%s", indent, tcp->src_port, newline);
        fprintf(fp, "%s    \"dst_port\": %u,%s", indent, tcp->dst_port, newline);
        fprintf(fp, "%s    \"seq\": %u,%s", indent, tcp->seq_num, newline);
        fprintf(fp, "%s    \"ack\": %u,%s", indent, tcp->ack_num, newline);
        fprintf(fp, "%s    \"flags\": \"0x%02X\",%s", indent, tcp->flags, newline);
        fprintf(fp, "%s    \"window\": %u%s", indent, tcp->window, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* UDP */
    if (udp) {
        fprintf(fp, "%s  \"udp\": {%s", indent, newline);
        fprintf(fp, "%s    \"src_port\": %u,%s", indent, udp->src_port, newline);
        fprintf(fp, "%s    \"dst_port\": %u,%s", indent, udp->dst_port, newline);
        fprintf(fp, "%s    \"length\": %u%s", indent, udp->length, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* ICMP */
    if (icmp) {
        fprintf(fp, "%s  \"icmp\": {%s", indent, newline);
        fprintf(fp, "%s    \"type\": %u,%s", indent, icmp->type, newline);
        fprintf(fp, "%s    \"code\": %u%s", indent, icmp->code, newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* ARP */
    if (arp) {
        fprintf(fp, "%s  \"arp\": {%s", indent, newline);
        fprintf(fp, "%s    \"operation\": %u,%s", indent, arp->opcode, newline);
        fprintf(fp, "%s    \"sender_mac\": ", indent);
        json_write_mac(fp, arp->sender_mac);
        fprintf(fp, ",%s", newline);
        fprintf(fp, "%s    \"sender_ip\": \"%u.%u.%u.%u\",%s", indent,
                arp->sender_ip[0], arp->sender_ip[1], 
                arp->sender_ip[2], arp->sender_ip[3], newline);
        fprintf(fp, "%s    \"target_ip\": \"%u.%u.%u.%u\"%s", indent,
                arp->target_ip[0], arp->target_ip[1],
                arp->target_ip[2], arp->target_ip[3], newline);
        fprintf(fp, "%s  },%s", indent, newline);
    }
    
    /* 协议类型 */
    const char *proto = "unknown";
    if (tcp) proto = "tcp";
    else if (udp) proto = "udp";
    else if (icmp) proto = "icmp";
    else if (arp) proto = "arp";
    else if (ipv4) proto = "ipv4";
    else if (ipv6) proto = "ipv6";
    
    fprintf(fp, "%s  \"protocol\": \"%s\"%s", indent, proto, newline);
    fprintf(fp, "%s}", indent);
    
    /* JSONL换行 */
    if (ctx->format == OUTPUT_FORMAT_JSONL) {
        fprintf(fp, "\n");
    }
}

/**
 * @brief 输出CSV格式数据包
 */
static void output_packet_csv(output_context_t *ctx, const packet_info_t *pkt,
                              const ethernet_header_t *eth, const vlan_info_t *vlan,
                              const ipv4_info_t *ipv4, const ipv6_info_t *ipv6,
                              const tcp_info_t *tcp, const udp_info_t *udp,
                              const icmp_info_t *icmp, const arp_info_t *arp) {
    FILE *fp = ctx->fp;
    (void)arp;  /* CSV格式暂不输出ARP详细信息 */
    
    /* packet_num */
    fprintf(fp, "%u,", pkt->packet_number);
    
    /* timestamp */
    fprintf(fp, "%u.%06u,", pkt->timestamp_sec, pkt->timestamp_usec);
    
    /* src_mac, dst_mac, eth_type */
    if (eth) {
        fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x,",
                eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
                eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
        fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x,",
                eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
                eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);
        fprintf(fp, "0x%04X,", eth->ether_type);
    } else {
        fprintf(fp, ",,,");
    }
    
    /* vlan_id */
    if (vlan && vlan->vlan_id > 0) {
        fprintf(fp, "%u,", vlan->vlan_id);
    } else {
        fprintf(fp, ",");
    }
    
    /* src_ip, dst_ip, protocol */
    if (ipv4) {
        uint8_t *s = (uint8_t *)&ipv4->src_ip;
        uint8_t *d = (uint8_t *)&ipv4->dst_ip;
        fprintf(fp, "%u.%u.%u.%u,", s[0], s[1], s[2], s[3]);
        fprintf(fp, "%u.%u.%u.%u,", d[0], d[1], d[2], d[3]);
        fprintf(fp, "%u,", ipv4->protocol);
    } else if (ipv6) {
        /* 简化IPv6地址输出 */
        fprintf(fp, "%02x%02x:%02x%02x::,", 
                ipv6->src_ip[0], ipv6->src_ip[1], ipv6->src_ip[2], ipv6->src_ip[3]);
        fprintf(fp, "%02x%02x:%02x%02x::,",
                ipv6->dst_ip[0], ipv6->dst_ip[1], ipv6->dst_ip[2], ipv6->dst_ip[3]);
        fprintf(fp, "%u,", ipv6->next_header);
    } else {
        fprintf(fp, ",,,");
    }
    
    /* src_port, dst_port */
    if (tcp) {
        fprintf(fp, "%u,%u,", tcp->src_port, tcp->dst_port);
    } else if (udp) {
        fprintf(fp, "%u,%u,", udp->src_port, udp->dst_port);
    } else {
        fprintf(fp, ",,");
    }
    
    /* tcp_flags */
    if (tcp) {
        fprintf(fp, "0x%02X,", tcp->flags);
    } else {
        fprintf(fp, ",");
    }
    
    /* icmp_type */
    if (icmp) {
        fprintf(fp, "%u,", icmp->type);
    } else {
        fprintf(fp, ",");
    }
    
    /* length */
    fprintf(fp, "%u\n", pkt->captured_len);
}

/**
 * @brief 输出数据包信息
 */
void output_packet(output_context_t *ctx, const packet_info_t *pkt,
                   const ethernet_header_t *eth, const vlan_info_t *vlan,
                   const ipv4_info_t *ipv4, const ipv6_info_t *ipv6,
                   const tcp_info_t *tcp, const udp_info_t *udp,
                   const icmp_info_t *icmp, const arp_info_t *arp) {
    if (!ctx || !ctx->fp || !pkt) return;
    
    ctx->packet_count++;
    
    switch (ctx->format) {
        case OUTPUT_FORMAT_JSON:
        case OUTPUT_FORMAT_JSONL:
            output_packet_json(ctx, pkt, eth, vlan, ipv4, ipv6, tcp, udp, icmp, arp);
            break;
            
        case OUTPUT_FORMAT_CSV:
            output_packet_csv(ctx, pkt, eth, vlan, ipv4, ipv6, tcp, udp, icmp, arp);
            break;
            
        case OUTPUT_FORMAT_TEXT:
        default:
            /* TEXT格式使用原有的print_xxx函数，这里不重复 */
            break;
    }
}

/**
 * @brief 输出统计信息
 */
void output_stats(output_context_t *ctx, const pcap_stats_t *stats,
                  uint32_t eth_count, uint32_t ipv4_count, uint32_t ipv6_count,
                  uint32_t tcp_count, uint32_t udp_count, uint32_t icmp_count,
                  uint32_t arp_count) {
    if (!ctx || !ctx->fp) return;
    
    FILE *fp = ctx->fp;
    
    switch (ctx->format) {
        case OUTPUT_FORMAT_JSON:
            fprintf(fp, ",\n  \"statistics\": {\n");
            fprintf(fp, "    \"total_packets\": %u,\n", stats->total_packets);
            fprintf(fp, "    \"total_bytes\": %lu,\n", (unsigned long)stats->total_bytes);
            fprintf(fp, "    \"protocols\": {\n");
            fprintf(fp, "      \"ethernet\": %u,\n", eth_count);
            fprintf(fp, "      \"ipv4\": %u,\n", ipv4_count);
            fprintf(fp, "      \"ipv6\": %u,\n", ipv6_count);
            fprintf(fp, "      \"tcp\": %u,\n", tcp_count);
            fprintf(fp, "      \"udp\": %u,\n", udp_count);
            fprintf(fp, "      \"icmp\": %u,\n", icmp_count);
            fprintf(fp, "      \"arp\": %u\n", arp_count);
            fprintf(fp, "    }\n");
            fprintf(fp, "  }\n");
            break;
            
        case OUTPUT_FORMAT_CSV:
            /* CSV不输出统计 */
            break;
            
        default:
            break;
    }
}
