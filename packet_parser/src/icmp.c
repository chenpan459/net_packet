/**
 * @file icmp.c
 * @brief ICMP协议解析实现 (带校验和验证)
 * @version 3.0
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 解析ICMP报文
 */
int parse_icmp(const uint8_t *data, size_t len, icmp_info_t *info) {
    const icmp_header_t *icmp_hdr = NULL;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 检查最小长度 */
    if (len < ICMP_HDR_LEN) {
        LOG_ERROR("ICMP packet too short: %zu bytes", len);
        return -1;
    }
    
    icmp_hdr = (const icmp_header_t *)data;
    
    /* 验证ICMP校验和 (整个ICMP报文) */
    if (verify_checksum(data, len)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
    }
    
    /* 填充解析结果 */
    info->type = icmp_hdr->type;
    info->code = icmp_hdr->code;
    info->identifier = net_to_host16(icmp_hdr->identifier);
    info->sequence = net_to_host16(icmp_hdr->sequence);
    
    /* ICMP数据部分 */
    info->data = (len > ICMP_HDR_LEN) ? (data + ICMP_HDR_LEN) : NULL;
    info->data_len = (len > ICMP_HDR_LEN) ? (len - ICMP_HDR_LEN) : 0;
    
    return 0;
}

/**
 * @brief 获取ICMP类型描述
 */
const char* icmp_type_name(uint8_t type) {
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACH:
            return "Destination Unreachable";
        case 4:
            return "Source Quench";
        case 5:
            return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case 9:
            return "Router Advertisement";
        case 10:
            return "Router Solicitation";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case 12:
            return "Parameter Problem";
        case 13:
            return "Timestamp Request";
        case 14:
            return "Timestamp Reply";
        default:
            return "Unknown";
    }
}

/**
 * @brief 获取ICMP目标不可达代码描述
 */
static const char* icmp_dest_unreach_code(uint8_t code) {
    switch (code) {
        case 0:
            return "Network Unreachable";
        case 1:
            return "Host Unreachable";
        case 2:
            return "Protocol Unreachable";
        case 3:
            return "Port Unreachable";
        case 4:
            return "Fragmentation Needed";
        case 5:
            return "Source Route Failed";
        case 6:
            return "Destination Network Unknown";
        case 7:
            return "Destination Host Unknown";
        case 9:
            return "Network Administratively Prohibited";
        case 10:
            return "Host Administratively Prohibited";
        case 13:
            return "Communication Administratively Prohibited";
        default:
            return "Unknown";
    }
}

/**
 * @brief 获取ICMP时间超时代码描述
 */
static const char* icmp_time_exceeded_code(uint8_t code) {
    switch (code) {
        case 0:
            return "TTL exceeded in transit";
        case 1:
            return "Fragment reassembly time exceeded";
        default:
            return "Unknown";
    }
}

/**
 * @brief 打印ICMP信息
 */
void print_icmp_info(const icmp_info_t *info) {
    const char *checksum_color = COLOR_CHECKSUM_OK;
    
    if (!info) return;
    
    /* 根据校验和状态选择颜色 */
    switch (info->checksum_status) {
        case CHECKSUM_OK:
            checksum_color = COLOR_CHECKSUM_OK;
            break;
        case CHECKSUM_ERROR:
            checksum_color = COLOR_CHECKSUM_ERROR;
            break;
        default:
            checksum_color = COLOR_CHECKSUM_SKIP;
            break;
    }
    
    printf(COLOR_MAGENTA "┌─ ICMP Packet ────────────────────────────────┐\n" COLOR_RESET);
    printf("│ Type: %s (%u)\n", icmp_type_name(info->type), info->type);
    
    /* 根据类型显示代码含义 */
    if (info->type == ICMP_TYPE_DEST_UNREACH) {
        printf("│ Code: %s (%u)\n", icmp_dest_unreach_code(info->code), info->code);
    } else if (info->type == ICMP_TYPE_TIME_EXCEEDED) {
        printf("│ Code: %s (%u)\n", icmp_time_exceeded_code(info->code), info->code);
    } else {
        printf("│ Code: %u\n", info->code);
    }
    
    /* 校验和状态 */
    printf("│ Checksum: %s%s" COLOR_RESET "\n", 
           checksum_color, checksum_status_name(info->checksum_status));
    
    /* Echo Request/Reply 显示 ID 和序列号 */
    if (info->type == ICMP_TYPE_ECHO_REQUEST || 
        info->type == ICMP_TYPE_ECHO_REPLY) {
        printf("│ Identifier: 0x%04X (%u)\n", info->identifier, info->identifier);
        printf("│ Sequence: %u\n", info->sequence);
    }
    
    printf("│ Data Length: %u bytes\n", info->data_len);
    
    /* 打印部分数据 */
    if (info->data && info->data_len > 0) {
        size_t show_len = (info->data_len > 32) ? 32 : info->data_len;
        printf("│ Data (first %zu bytes):\n", show_len);
        hex_dump(info->data, show_len, 16);
    }
    
    printf(COLOR_MAGENTA "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
