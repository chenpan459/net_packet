/**
 * @file tcp.c
 * @brief TCP协议解析实现 (带校验和验证和选项解析)
 * @version 3.1 - 支持TCP选项解析
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 解析TCP选项
 */
int parse_tcp_options(const uint8_t *options, size_t len, tcp_options_t *opts) {
    size_t offset = 0;
    
    if (!options || !opts) {
        return -1;
    }
    
    /* 初始化选项结构 */
    memset(opts, 0, sizeof(tcp_options_t));
    opts->options_len = (uint8_t)len;
    
    while (offset < len) {
        uint8_t kind = options[offset];
        
        /* End of Options */
        if (kind == TCP_OPT_END) {
            break;
        }
        
        /* NOP - 填充 */
        if (kind == TCP_OPT_NOP) {
            offset++;
            continue;
        }
        
        /* 其他选项需要长度字段 */
        if (offset + 1 >= len) {
            LOG_DEBUG("TCP option truncated at offset %zu", offset);
            break;
        }
        
        uint8_t opt_len = options[offset + 1];
        
        /* 检查选项长度有效性 */
        if (opt_len < 2 || offset + opt_len > len) {
            LOG_DEBUG("Invalid TCP option length: %u at offset %zu", opt_len, offset);
            break;
        }
        
        switch (kind) {
            case TCP_OPT_MSS:
                /* MSS: Kind(1) + Length(1) + MSS(2) = 4 bytes */
                if (opt_len == 4 && offset + 4 <= len) {
                    opts->has_mss = 1;
                    opts->mss = (options[offset + 2] << 8) | options[offset + 3];
                    LOG_DEBUG("TCP Option MSS: %u", opts->mss);
                }
                break;
                
            case TCP_OPT_WSCALE:
                /* Window Scale: Kind(1) + Length(1) + Shift(1) = 3 bytes */
                if (opt_len == 3 && offset + 3 <= len) {
                    opts->has_wscale = 1;
                    opts->wscale = options[offset + 2];
                    LOG_DEBUG("TCP Option Window Scale: %u", opts->wscale);
                }
                break;
                
            case TCP_OPT_SACK_PERM:
                /* SACK Permitted: Kind(1) + Length(1) = 2 bytes */
                if (opt_len == 2) {
                    opts->has_sack_perm = 1;
                    LOG_DEBUG("TCP Option SACK Permitted");
                }
                break;
                
            case TCP_OPT_SACK:
                /* SACK: Kind(1) + Length(1) + Blocks(n*8) */
                if (opt_len >= 10 && ((opt_len - 2) % 8 == 0)) {
                    opts->has_sack = 1;
                    opts->sack_block_count = (opt_len - 2) / 8;
                    if (opts->sack_block_count > MAX_SACK_BLOCKS) {
                        opts->sack_block_count = MAX_SACK_BLOCKS;
                    }
                    for (int i = 0; i < opts->sack_block_count; i++) {
                        size_t block_offset = offset + 2 + i * 8;
                        opts->sack_blocks[i].left_edge = 
                            (options[block_offset] << 24) |
                            (options[block_offset + 1] << 16) |
                            (options[block_offset + 2] << 8) |
                            options[block_offset + 3];
                        opts->sack_blocks[i].right_edge =
                            (options[block_offset + 4] << 24) |
                            (options[block_offset + 5] << 16) |
                            (options[block_offset + 6] << 8) |
                            options[block_offset + 7];
                    }
                    LOG_DEBUG("TCP Option SACK: %u blocks", opts->sack_block_count);
                }
                break;
                
            case TCP_OPT_TIMESTAMP:
                /* Timestamp: Kind(1) + Length(1) + TSval(4) + TSecr(4) = 10 bytes */
                if (opt_len == 10 && offset + 10 <= len) {
                    opts->has_timestamp = 1;
                    opts->ts_val = 
                        (options[offset + 2] << 24) |
                        (options[offset + 3] << 16) |
                        (options[offset + 4] << 8) |
                        options[offset + 5];
                    opts->ts_ecr =
                        (options[offset + 6] << 24) |
                        (options[offset + 7] << 16) |
                        (options[offset + 8] << 8) |
                        options[offset + 9];
                    LOG_DEBUG("TCP Option Timestamp: TSval=%u, TSecr=%u", 
                              opts->ts_val, opts->ts_ecr);
                }
                break;
                
            default:
                LOG_DEBUG("Unknown TCP option: kind=%u, len=%u", kind, opt_len);
                break;
        }
        
        offset += opt_len;
    }
    
    return 0;
}

/**
 * @brief 解析TCP报文 (不验证校验和)
 */
int parse_tcp(const uint8_t *data, size_t len, tcp_info_t *info) {
    const tcp_header_t *tcp_hdr = NULL;
    uint8_t data_offset = 0;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 初始化 */
    memset(info, 0, sizeof(tcp_info_t));
    
    /* 检查最小长度 */
    if (len < TCP_HDR_MIN_LEN) {
        LOG_ERROR("TCP segment too short: %zu bytes", len);
        return -1;
    }
    
    tcp_hdr = (const tcp_header_t *)data;
    
    /* 获取数据偏移(首部长度) */
    data_offset = TCP_DATA_OFFSET(tcp_hdr);
    
    /* 验证首部长度 */
    if (data_offset < TCP_HDR_MIN_LEN) {
        LOG_ERROR("Invalid TCP header length: %u", data_offset);
        return -1;
    }
    
    /* 填充解析结果 */
    info->src_port = net_to_host16(tcp_hdr->src_port);
    info->dst_port = net_to_host16(tcp_hdr->dst_port);
    info->seq_num = net_to_host32(tcp_hdr->seq_num);
    info->ack_num = net_to_host32(tcp_hdr->ack_num);
    info->data_offset = data_offset;
    info->flags = tcp_hdr->flags;
    info->window = net_to_host16(tcp_hdr->window);
    info->checksum_status = CHECKSUM_SKIPPED;
    
    /* 解析TCP选项 */
    if (data_offset > TCP_HDR_MIN_LEN) {
        size_t options_len = data_offset - TCP_HDR_MIN_LEN;
        if (options_len > 0 && TCP_HDR_MIN_LEN + options_len <= len) {
            parse_tcp_options(data + TCP_HDR_MIN_LEN, options_len, &info->options);
        }
    }
    
    /* 设置载荷 */
    if (data_offset <= len) {
        info->payload = data + data_offset;
        info->payload_len = len - data_offset;
    } else {
        info->payload = NULL;
        info->payload_len = 0;
    }
    
    return 0;
}

/**
 * @brief 解析TCP报文 (带IPv4校验和验证)
 * @note 校验和错误可能由网卡 checksum offload 功能导致，并非真正的包错误
 */
int parse_tcp_with_checksum(const uint8_t *data, size_t len,
                            uint32_t src_ip, uint32_t dst_ip,
                            tcp_info_t *info) {
    /* 先进行基本解析 */
    if (parse_tcp(data, len, info) != 0) {
        return -1;
    }
    
    /* 验证TCP校验和 */
    if (verify_transport_checksum(src_ip, dst_ip, IP_PROTO_TCP, data, len)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
        LOG_DEBUG("TCP checksum error (may be due to checksum offload)");
    }
    
    return 0;
}

/**
 * @brief 解析TCP报文 (带IPv6校验和验证)
 */
int parse_tcp_with_checksum_v6(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                tcp_info_t *info) {
    /* 先进行基本解析 */
    if (parse_tcp(data, len, info) != 0) {
        return -1;
    }
    
    /* 验证TCP校验和 (IPv6) */
    if (verify_transport_checksum_v6(src_ip, dst_ip, IP_PROTO_TCP, data, len)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
        LOG_DEBUG("TCP checksum error (may be due to checksum offload)");
    }
    
    return 0;
}

/**
 * @brief TCP标志转字符串
 */
void tcp_flags_to_string(uint8_t flags, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return;
    
    buf[0] = '\0';
    
    if (flags & TCP_FLAG_CWR) strncat(buf, "CWR ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_ECE) strncat(buf, "ECE ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_URG) strncat(buf, "URG ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_ACK) strncat(buf, "ACK ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_PSH) strncat(buf, "PSH ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_RST) strncat(buf, "RST ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_SYN) strncat(buf, "SYN ", buf_len - strlen(buf) - 1);
    if (flags & TCP_FLAG_FIN) strncat(buf, "FIN ", buf_len - strlen(buf) - 1);
    
    /* 移除末尾空格 */
    size_t slen = strlen(buf);
    if (slen > 0 && buf[slen - 1] == ' ') {
        buf[slen - 1] = '\0';
    }
}

/**
 * @brief 获取常见端口服务名
 */
static const char* get_service_name(uint16_t port) {
    switch (port) {
        case 20:  return "FTP-Data";
        case 21:  return "FTP";
        case 22:  return "SSH";
        case 23:  return "Telnet";
        case 25:  return "SMTP";
        case 53:  return "DNS";
        case 80:  return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        default:  return NULL;
    }
}

/**
 * @brief 打印TCP选项信息
 */
void print_tcp_options(const tcp_options_t *opts) {
    if (!opts || opts->options_len == 0) return;
    
    printf("│ " COLOR_MAGENTA "TCP Options (%u bytes):" COLOR_RESET "\n", opts->options_len);
    
    if (opts->has_mss) {
        printf("│   • MSS: %u bytes\n", opts->mss);
    }
    
    if (opts->has_wscale) {
        printf("│   • Window Scale: %u (multiply by %u)\n", 
               opts->wscale, 1 << opts->wscale);
    }
    
    if (opts->has_sack_perm) {
        printf("│   • SACK Permitted\n");
    }
    
    if (opts->has_sack && opts->sack_block_count > 0) {
        printf("│   • SACK Blocks (%u):\n", opts->sack_block_count);
        for (int i = 0; i < opts->sack_block_count; i++) {
            printf("│     [%u - %u]\n", 
                   opts->sack_blocks[i].left_edge,
                   opts->sack_blocks[i].right_edge);
        }
    }
    
    if (opts->has_timestamp) {
        printf("│   • Timestamps: TSval=%u, TSecr=%u\n", 
               opts->ts_val, opts->ts_ecr);
    }
}

/**
 * @brief 打印TCP信息
 */
void print_tcp_info(const tcp_info_t *info) {
    char flags_str[64];
    const char *src_service = NULL;
    const char *dst_service = NULL;
    const char *checksum_color = COLOR_CHECKSUM_SKIP;
    const char *checksum_note = "";
    
    if (!info) return;
    
    tcp_flags_to_string(info->flags, flags_str, sizeof(flags_str));
    src_service = get_service_name(info->src_port);
    dst_service = get_service_name(info->dst_port);
    
    /* 根据校验和状态选择颜色和说明 */
    switch (info->checksum_status) {
        case CHECKSUM_OK:
            checksum_color = COLOR_CHECKSUM_OK;
            break;
        case CHECKSUM_ERROR:
            checksum_color = COLOR_CHECKSUM_ERROR;
            checksum_note = " (offload?)";
            break;
        default:
            checksum_color = COLOR_CHECKSUM_SKIP;
            break;
    }
    
    printf(COLOR_RED "┌─ TCP Segment ────────────────────────────────┐\n" COLOR_RESET);
    
    /* 端口信息 */
    printf("│ Source Port:      %u", info->src_port);
    if (src_service) printf(" (%s)", src_service);
    printf("\n");
    
    printf("│ Destination Port: %u", info->dst_port);
    if (dst_service) printf(" (%s)", dst_service);
    printf("\n");
    
    /* 序列号和确认号 */
    printf("│ Sequence Number:  %u\n", info->seq_num);
    printf("│ Acknowledge Number: %u\n", info->ack_num);
    
    /* 首部长度和标志 */
    printf("│ Header Length: %u bytes\n", info->data_offset);
    printf("│ Flags: 0x%02X [%s]\n", info->flags, flags_str);
    printf("│ Window Size: %u\n", info->window);
    
    /* 校验和状态 */
    printf("│ Checksum: %s%s%s" COLOR_RESET "\n", 
           checksum_color, checksum_status_name(info->checksum_status), checksum_note);
    
    /* TCP选项 */
    print_tcp_options(&info->options);
    
    /* 载荷信息 */
    printf("│ Payload Length: %u bytes\n", info->payload_len);
    
    /* TCP连接状态提示 */
    if (info->flags == TCP_FLAG_SYN) {
        printf("│ " COLOR_CYAN "[TCP Connection: SYN - Initiating handshake]" COLOR_RESET "\n");
    } else if (info->flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        printf("│ " COLOR_CYAN "[TCP Connection: SYN+ACK - Handshake response]" COLOR_RESET "\n");
    } else if (info->flags == TCP_FLAG_ACK && info->payload_len == 0) {
        printf("│ " COLOR_CYAN "[TCP Connection: ACK - Pure acknowledgement]" COLOR_RESET "\n");
    } else if (info->flags & TCP_FLAG_FIN) {
        printf("│ " COLOR_CYAN "[TCP Connection: FIN - Closing connection]" COLOR_RESET "\n");
    } else if (info->flags & TCP_FLAG_RST) {
        printf("│ " COLOR_CYAN "[TCP Connection: RST - Reset connection]" COLOR_RESET "\n");
    }
    
    /* 打印部分载荷 */
    if (info->payload && info->payload_len > 0) {
        size_t show_len = (info->payload_len > 64) ? 64 : info->payload_len;
        printf("│ Payload (first %zu bytes):\n", show_len);
        hex_dump(info->payload, show_len, 16);
    }
    
    printf(COLOR_RED "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
