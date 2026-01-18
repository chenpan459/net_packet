/**
 * @file udp.c
 * @brief UDP协议解析实现
 * @version 3.0 - 支持IPv6
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 解析UDP报文
 */
int parse_udp(const uint8_t *data, size_t len, udp_info_t *info) {
    const udp_header_t *udp_hdr = NULL;
    uint16_t udp_len = 0;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 检查最小长度 */
    if (len < UDP_HDR_LEN) {
        LOG_ERROR("UDP datagram too short: %zu bytes", len);
        return -1;
    }
    
    udp_hdr = (const udp_header_t *)data;
    
    /* 获取UDP长度 */
    udp_len = net_to_host16(udp_hdr->length);
    
    /* 验证长度字段 */
    if (udp_len < UDP_HDR_LEN) {
        LOG_ERROR("Invalid UDP length field: %u", udp_len);
        return -1;
    }
    
    /* 填充解析结果 */
    info->src_port = net_to_host16(udp_hdr->src_port);
    info->dst_port = net_to_host16(udp_hdr->dst_port);
    info->length = udp_len;
    info->checksum_status = CHECKSUM_SKIPPED;  /* 默认不验证 */
    
    /* 设置载荷 */
    info->payload = data + UDP_HDR_LEN;
    info->payload_len = (udp_len > UDP_HDR_LEN) ? (udp_len - UDP_HDR_LEN) : 0;
    
    /* 确保载荷长度不超过实际数据 */
    if (info->payload_len > len - UDP_HDR_LEN) {
        info->payload_len = len - UDP_HDR_LEN;
    }
    
    return 0;
}

/**
 * @brief 解析UDP报文 (带IPv4校验和验证)
 */
int parse_udp_with_checksum(const uint8_t *data, size_t len,
                            uint32_t src_ip, uint32_t dst_ip,
                            udp_info_t *info) {
    const udp_header_t *udp_hdr = NULL;
    
    /* 先进行基本解析 */
    if (parse_udp(data, len, info) != 0) {
        return -1;
    }
    
    udp_hdr = (const udp_header_t *)data;
    
    /* UDP校验和为0表示未使用 (仅IPv4允许) */
    if (udp_hdr->checksum == 0) {
        info->checksum_status = CHECKSUM_SKIPPED;
    } else {
        /* 验证校验和 */
        if (verify_transport_checksum(src_ip, dst_ip, IP_PROTO_UDP, data, len)) {
            info->checksum_status = CHECKSUM_OK;
        } else {
            info->checksum_status = CHECKSUM_ERROR;
        }
    }
    
    return 0;
}

/**
 * @brief 解析UDP报文 (带IPv6校验和验证)
 */
int parse_udp_with_checksum_v6(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                udp_info_t *info) {
    /* 先进行基本解析 */
    if (parse_udp(data, len, info) != 0) {
        return -1;
    }
    
    /* IPv6 UDP校验和是必须的 */
    if (verify_transport_checksum_v6(src_ip, dst_ip, IP_PROTO_UDP, data, len)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
    }
    
    return 0;
}

/**
 * @brief 获取常见UDP端口服务名
 */
static const char* get_udp_service_name(uint16_t port) {
    switch (port) {
        case 53:
            return "DNS";
        case 67:
            return "DHCP-Server";
        case 68:
            return "DHCP-Client";
        case 69:
            return "TFTP";
        case 123:
            return "NTP";
        case 137:
            return "NetBIOS-NS";
        case 138:
            return "NetBIOS-DGM";
        case 161:
            return "SNMP";
        case 162:
            return "SNMP-Trap";
        case 443:
            return "QUIC";
        case 500:
            return "IKE";
        case 514:
            return "Syslog";
        case 520:
            return "RIP";
        case 1900:
            return "SSDP";
        case 4500:
            return "NAT-T";
        case 5353:
            return "mDNS";
        case 5355:
            return "LLMNR";
        default:
            return NULL;
    }
}

/**
 * @brief 获取校验和状态描述
 */
const char* checksum_status_name(checksum_result_t status) {
    switch (status) {
        case CHECKSUM_OK:
            return "OK";
        case CHECKSUM_ERROR:
            return "ERROR";
        case CHECKSUM_SKIPPED:
            return "Not verified";
        default:
            return "Unknown";
    }
}

/**
 * @brief 打印UDP信息
 */
void print_udp_info(const udp_info_t *info) {
    const char *src_service = NULL;
    const char *dst_service = NULL;
    const char *checksum_color = COLOR_CHECKSUM_SKIP;
    
    if (!info) return;
    
    src_service = get_udp_service_name(info->src_port);
    dst_service = get_udp_service_name(info->dst_port);
    
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
    
    printf(COLOR_GREEN "┌─ UDP Datagram ───────────────────────────────┐\n" COLOR_RESET);
    
    /* 端口信息 */
    printf("│ Source Port:      %u", info->src_port);
    if (src_service) printf(" (%s)", src_service);
    printf("\n");
    
    printf("│ Destination Port: %u", info->dst_port);
    if (dst_service) printf(" (%s)", dst_service);
    printf("\n");
    
    /* 长度和校验和 */
    printf("│ Length: %u bytes\n", info->length);
    printf("│ Checksum: %s%s" COLOR_RESET "\n", 
           checksum_color, checksum_status_name(info->checksum_status));
    
    /* 载荷信息 */
    printf("│ Payload Length: %u bytes\n", info->payload_len);
    
    /* 尝试识别应用层协议 */
    if (info->src_port == 53 || info->dst_port == 53) {
        printf("│ " COLOR_CYAN "[Application: DNS Query/Response]" COLOR_RESET "\n");
    } else if (info->src_port == 67 || info->dst_port == 67 ||
               info->src_port == 68 || info->dst_port == 68) {
        printf("│ " COLOR_CYAN "[Application: DHCP]" COLOR_RESET "\n");
    } else if (info->src_port == 123 || info->dst_port == 123) {
        printf("│ " COLOR_CYAN "[Application: NTP Time Sync]" COLOR_RESET "\n");
    }
    
    /* 打印部分载荷 */
    if (info->payload && info->payload_len > 0) {
        size_t show_len = (info->payload_len > 64) ? 64 : info->payload_len;
        printf("│ Payload (first %zu bytes):\n", show_len);
        hex_dump(info->payload, show_len, 16);
    }
    
    printf(COLOR_GREEN "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
