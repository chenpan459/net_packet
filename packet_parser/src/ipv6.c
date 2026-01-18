/**
 * @file ipv6.c
 * @brief IPv6协议解析实现
 * @version 3.0
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 判断是否为IPv6扩展头
 */
static int is_ipv6_extension_header(uint8_t next_header) {
    switch (next_header) {
        case IP_PROTO_HOPOPT:     /* 逐跳选项 */
        case IP_PROTO_ROUTING:    /* 路由头 */
        case IP_PROTO_FRAGMENT:   /* 分片头 */
        case IP_PROTO_DSTOPTS:    /* 目的选项 */
            return 1;
        default:
            return 0;
    }
}

/**
 * @brief 解析IPv6报文
 */
int parse_ipv6(const uint8_t *data, size_t len, ipv6_info_t *info) {
    const ipv6_header_t *ip6_hdr = NULL;
    uint8_t next_header;
    const uint8_t *ptr;
    size_t remaining;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 检查最小长度 */
    if (len < IPV6_HDR_LEN) {
        LOG_ERROR("IPv6 packet too short: %zu bytes", len);
        return -1;
    }
    
    ip6_hdr = (const ipv6_header_t *)data;
    
    /* 验证版本号 */
    info->version = IPV6_VERSION(ip6_hdr);
    if (info->version != 6) {
        LOG_ERROR("Not IPv6 packet, version: %u", info->version);
        return -1;
    }
    
    /* 解析头部字段 */
    info->traffic_class = IPV6_TRAFFIC_CLASS(ip6_hdr);
    info->flow_label = IPV6_FLOW_LABEL(ip6_hdr);
    info->payload_length = net_to_host16(ip6_hdr->payload_length);
    info->hop_limit = ip6_hdr->hop_limit;
    memcpy(info->src_ip, ip6_hdr->src_ip, IPV6_ADDR_LEN);
    memcpy(info->dst_ip, ip6_hdr->dst_ip, IPV6_ADDR_LEN);
    
    /* 跳过扩展头，找到最终协议 */
    next_header = ip6_hdr->next_header;
    ptr = data + IPV6_HDR_LEN;
    remaining = len - IPV6_HDR_LEN;
    info->ext_headers_count = 0;
    
    while (is_ipv6_extension_header(next_header) && remaining > 0) {
        uint8_t ext_len;
        
        if (remaining < 2) {
            LOG_WARN("Truncated IPv6 extension header");
            break;
        }
        
        info->ext_headers_count++;
        
        if (next_header == IP_PROTO_FRAGMENT) {
            /* 分片头固定8字节 */
            if (remaining < 8) break;
            next_header = ptr[0];
            ptr += 8;
            remaining -= 8;
        } else {
            /* 其他扩展头: 长度字段是8字节为单位(不含前8字节) */
            ext_len = (ptr[1] + 1) * 8;
            if (remaining < ext_len) break;
            next_header = ptr[0];
            ptr += ext_len;
            remaining -= ext_len;
        }
        
        if (info->ext_headers_count > 10) {
            LOG_WARN("Too many IPv6 extension headers");
            break;
        }
    }
    
    info->next_header = next_header;
    info->payload = ptr;
    info->payload_len = (remaining < info->payload_length) ? remaining : info->payload_length;
    
    LOG_DEBUG("IPv6: %u ext headers, next=%u, payload=%u bytes",
              info->ext_headers_count, info->next_header, info->payload_len);
    
    return 0;
}

/**
 * @brief 打印IPv6地址
 */
void print_ipv6_addr(const uint8_t *ip) {
    if (!ip) return;
    
    /* 简化的IPv6地址打印 (不压缩零) */
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
           ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
}

/**
 * @brief 获取IP协议名称 (IPv4和IPv6共用)
 */
const char* ip_protocol_name(uint8_t proto) {
    switch (proto) {
        case IP_PROTO_HOPOPT:
            return "HOPOPT";
        case IP_PROTO_ICMP:
            return "ICMP";
        case IP_PROTO_TCP:
            return "TCP";
        case IP_PROTO_UDP:
            return "UDP";
        case IP_PROTO_IPV6:
            return "IPv6";
        case IP_PROTO_ROUTING:
            return "Routing";
        case IP_PROTO_FRAGMENT:
            return "Fragment";
        case IP_PROTO_ICMPV6:
            return "ICMPv6";
        case IP_PROTO_NONE:
            return "NoNext";
        case IP_PROTO_DSTOPTS:
            return "DstOpts";
        case 2:
            return "IGMP";
        case 47:
            return "GRE";
        case 50:
            return "ESP";
        case 51:
            return "AH";
        case 89:
            return "OSPF";
        default:
            return "Unknown";
    }
}

/**
 * @brief 打印IPv6信息
 */
void print_ipv6_info(const ipv6_info_t *info) {
    if (!info) return;
    
    printf(COLOR_BLUE "┌─ IPv6 Packet ────────────────────────────────┐\n" COLOR_RESET);
    printf("│ Version: %u\n", info->version);
    printf("│ Traffic Class: 0x%02X\n", info->traffic_class);
    printf("│ Flow Label: 0x%05X\n", info->flow_label);
    printf("│ Payload Length: %u bytes\n", info->payload_length);
    printf("│ Hop Limit: %u\n", info->hop_limit);
    printf("│ Next Header: %s (%u)\n", ip_protocol_name(info->next_header), info->next_header);
    if (info->ext_headers_count > 0) {
        printf("│ Extension Headers: %u\n", info->ext_headers_count);
    }
    printf("│ Source:      ");
    print_ipv6_addr(info->src_ip);
    printf("\n");
    printf("│ Destination: ");
    print_ipv6_addr(info->dst_ip);
    printf("\n");
    printf(COLOR_BLUE "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}

/**
 * @brief 解析ICMPv6报文
 */
int parse_icmpv6(const uint8_t *data, size_t len, icmpv6_info_t *info) {
    const icmpv6_header_t *hdr = NULL;
    
    if (!data || !info) {
        return -1;
    }
    
    if (len < ICMPV6_HDR_LEN) {
        LOG_ERROR("ICMPv6 packet too short: %zu bytes", len);
        return -1;
    }
    
    hdr = (const icmpv6_header_t *)data;
    
    info->type = hdr->type;
    info->code = hdr->code;
    info->checksum_status = CHECKSUM_SKIPPED;
    
    /* 根据类型解析特定字段 */
    if (info->type == ICMPV6_TYPE_ECHO_REQUEST || 
        info->type == ICMPV6_TYPE_ECHO_REPLY) {
        info->identifier = net_to_host16(hdr->data.echo.identifier);
        info->sequence = net_to_host16(hdr->data.echo.sequence);
    } else if (info->type == ICMPV6_TYPE_PKT_TOO_BIG) {
        info->mtu = net_to_host32(hdr->data.mtu);
    }
    
    info->data = (len > ICMPV6_HDR_LEN) ? (data + ICMPV6_HDR_LEN) : NULL;
    info->data_len = (len > ICMPV6_HDR_LEN) ? (len - ICMPV6_HDR_LEN) : 0;
    
    return 0;
}

/**
 * @brief 解析ICMPv6报文 (带校验和验证)
 */
int parse_icmpv6_with_checksum(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                icmpv6_info_t *info) {
    if (parse_icmpv6(data, len, info) != 0) {
        return -1;
    }
    
    /* ICMPv6校验和必须验证 */
    if (verify_transport_checksum_v6(src_ip, dst_ip, IP_PROTO_ICMPV6, data, len)) {
        info->checksum_status = CHECKSUM_OK;
    } else {
        info->checksum_status = CHECKSUM_ERROR;
    }
    
    return 0;
}

/**
 * @brief 获取ICMPv6类型描述
 */
const char* icmpv6_type_name(uint8_t type) {
    switch (type) {
        case ICMPV6_TYPE_DEST_UNREACH:
            return "Destination Unreachable";
        case ICMPV6_TYPE_PKT_TOO_BIG:
            return "Packet Too Big";
        case ICMPV6_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMPV6_TYPE_PARAM_PROBLEM:
            return "Parameter Problem";
        case ICMPV6_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMPV6_TYPE_ROUTER_SOL:
            return "Router Solicitation";
        case ICMPV6_TYPE_ROUTER_ADV:
            return "Router Advertisement";
        case ICMPV6_TYPE_NEIGHBOR_SOL:
            return "Neighbor Solicitation";
        case ICMPV6_TYPE_NEIGHBOR_ADV:
            return "Neighbor Advertisement";
        default:
            return "Unknown";
    }
}

/**
 * @brief 打印ICMPv6信息
 */
void print_icmpv6_info(const icmpv6_info_t *info) {
    const char *checksum_color = COLOR_CHECKSUM_SKIP;
    
    if (!info) return;
    
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
    
    printf(COLOR_MAGENTA "┌─ ICMPv6 Packet ──────────────────────────────┐\n" COLOR_RESET);
    printf("│ Type: %s (%u)\n", icmpv6_type_name(info->type), info->type);
    printf("│ Code: %u\n", info->code);
    printf("│ Checksum: %s%s" COLOR_RESET "\n",
           checksum_color, checksum_status_name(info->checksum_status));
    
    if (info->type == ICMPV6_TYPE_ECHO_REQUEST || 
        info->type == ICMPV6_TYPE_ECHO_REPLY) {
        printf("│ Identifier: 0x%04X (%u)\n", info->identifier, info->identifier);
        printf("│ Sequence: %u\n", info->sequence);
    } else if (info->type == ICMPV6_TYPE_PKT_TOO_BIG) {
        printf("│ MTU: %u\n", info->mtu);
    }
    
    printf("│ Data Length: %u bytes\n", info->data_len);
    printf(COLOR_MAGENTA "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
