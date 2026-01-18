/**
 * @file ipv4.c
 * @brief IPv4协议解析实现 (带校验和验证和分片检测)
 * @version 3.1 - 支持分片状态检测
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 获取分片状态名称
 */
const char* frag_status_name(frag_status_t status) {
    switch (status) {
        case FRAG_NONE:   return "Not Fragmented";
        case FRAG_FIRST:  return "First Fragment";
        case FRAG_MIDDLE: return "Middle Fragment";
        case FRAG_LAST:   return "Last Fragment";
        default:          return "Unknown";
    }
}

/**
 * @brief 解析IPv4报文
 */
int parse_ipv4(const uint8_t *data, size_t len, ipv4_info_t *info) {
    const ipv4_header_t *ip_hdr = NULL;
    uint8_t ihl = 0;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 初始化 */
    memset(info, 0, sizeof(ipv4_info_t));
    
    /* 检查最小长度 */
    if (len < IPV4_HDR_MIN_LEN) {
        LOG_ERROR("IPv4 packet too short: %zu bytes", len);
        return -1;
    }
    
    ip_hdr = (const ipv4_header_t *)data;
    
    /* 获取版本和首部长度 */
    info->version = IPV4_VERSION(ip_hdr);
    ihl = (ip_hdr->version_ihl & 0x0F) * 4;
    info->ihl = ihl;
    
    /* 验证版本号 */
    if (info->version != 4) {
        LOG_ERROR("Not IPv4 packet, version: %u", info->version);
        return -1;
    }
    
    /* 验证首部长度 */
    if (ihl < IPV4_HDR_MIN_LEN || ihl > len) {
        LOG_ERROR("Invalid IPv4 header length: %u", ihl);
        return -1;
    }
    
    /* 验证IPv4首部校验和 */
    if (verify_checksum(data, ihl)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
    }
    
    /* 填充解析结果 */
    info->tos = ip_hdr->tos;
    info->total_length = net_to_host16(ip_hdr->total_length);
    info->identification = net_to_host16(ip_hdr->identification);
    info->flags = IPV4_FLAGS(ip_hdr);
    info->fragment_offset = IPV4_FRAG_OFFSET(ip_hdr);
    info->ttl = ip_hdr->ttl;
    info->protocol = ip_hdr->protocol;
    info->src_ip = ip_hdr->src_ip;  /* 保持网络字节序 */
    info->dst_ip = ip_hdr->dst_ip;  /* 保持网络字节序 */
    
    /* 分片状态检测 */
    int mf_flag = (info->flags & IPV4_FLAG_MF);  /* More Fragments */
    uint16_t frag_off = info->fragment_offset;
    
    if (frag_off == 0 && !mf_flag) {
        /* 未分片 */
        info->frag_status = FRAG_NONE;
        info->is_fragmented = 0;
    } else if (frag_off == 0 && mf_flag) {
        /* 首片 */
        info->frag_status = FRAG_FIRST;
        info->is_fragmented = 1;
        LOG_DEBUG("IPv4 fragmented packet: First fragment, ID=0x%04X", info->identification);
    } else if (frag_off != 0 && mf_flag) {
        /* 中间片 */
        info->frag_status = FRAG_MIDDLE;
        info->is_fragmented = 1;
        LOG_DEBUG("IPv4 fragmented packet: Middle fragment, ID=0x%04X, offset=%u",
                  info->identification, frag_off * 8);
    } else {
        /* 末片 (offset != 0, MF = 0) */
        info->frag_status = FRAG_LAST;
        info->is_fragmented = 1;
        LOG_DEBUG("IPv4 fragmented packet: Last fragment, ID=0x%04X, offset=%u",
                  info->identification, frag_off * 8);
    }
    
    /* 设置载荷 */
    info->payload = data + ihl;
    info->payload_len = (info->total_length > ihl) ? (info->total_length - ihl) : 0;
    
    /* 确保载荷长度不超过实际数据 */
    if (info->payload_len > len - ihl) {
        info->payload_len = len - ihl;
    }
    
    return 0;
}

/**
 * @brief 打印IPv4地址
 */
void print_ipv4_addr(uint32_t ip) {
    uint8_t *bytes = (uint8_t *)&ip;
    printf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * @brief 打印IPv4信息
 */
void print_ipv4_info(const ipv4_info_t *info) {
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
    
    printf(COLOR_BLUE "┌─ IPv4 Packet ────────────────────────────────┐\n" COLOR_RESET);
    printf("│ Version: %u, Header Length: %u bytes\n", info->version, info->ihl);
    printf("│ Type of Service: 0x%02X\n", info->tos);
    printf("│ Total Length: %u bytes\n", info->total_length);
    printf("│ Identification: 0x%04X (%u)\n", info->identification, info->identification);
    printf("│ Flags: 0x%X", info->flags);
    if (info->flags & IPV4_FLAG_DF) printf(" [DF]");
    if (info->flags & IPV4_FLAG_MF) printf(" [MF]");
    printf(", Fragment Offset: %u", info->fragment_offset);
    if (info->fragment_offset > 0) {
        printf(" (byte %u)", info->fragment_offset * 8);
    }
    printf("\n");
    
    /* 分片状态 */
    if (info->is_fragmented) {
        printf("│ " COLOR_YELLOW "Fragmentation: %s" COLOR_RESET "\n", 
               frag_status_name(info->frag_status));
    }
    
    printf("│ TTL: %u\n", info->ttl);
    printf("│ Protocol: %s (%u)\n", ip_protocol_name(info->protocol), info->protocol);
    printf("│ Header Checksum: %s%s" COLOR_RESET "\n", 
           checksum_color, checksum_status_name(info->checksum_status));
    printf("│ Source IP:      ");
    print_ipv4_addr(info->src_ip);
    printf("\n");
    printf("│ Destination IP: ");
    print_ipv4_addr(info->dst_ip);
    printf("\n");
    printf("│ Payload Length: %u bytes\n", info->payload_len);
    printf(COLOR_BLUE "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
