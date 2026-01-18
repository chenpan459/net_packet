/**
 * @file arp.c
 * @brief ARP协议解析实现
 * @version 3.0
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 解析ARP报文
 */
int parse_arp(const uint8_t *data, size_t len, arp_info_t *info) {
    const arp_header_t *arp_hdr = NULL;
    
    if (!data || !info) {
        return -1;
    }
    
    /* 检查最小长度 */
    if (len < ARP_HDR_LEN) {
        LOG_ERROR("ARP packet too short: %zu bytes", len);
        return -1;
    }
    
    arp_hdr = (const arp_header_t *)data;
    
    /* 验证硬件类型和协议类型 */
    if (net_to_host16(arp_hdr->hw_type) != 1 ||       /* Ethernet */
        net_to_host16(arp_hdr->proto_type) != 0x0800) /* IPv4 */ {
        LOG_WARN("Non-Ethernet/IPv4 ARP packet");
    }
    
    /* 填充解析结果 */
    info->opcode = net_to_host16(arp_hdr->opcode);
    memcpy(info->sender_mac, arp_hdr->sender_mac, ETH_ADDR_LEN);
    memcpy(info->sender_ip, arp_hdr->sender_ip, IPV4_ADDR_LEN);
    memcpy(info->target_mac, arp_hdr->target_mac, ETH_ADDR_LEN);
    memcpy(info->target_ip, arp_hdr->target_ip, IPV4_ADDR_LEN);
    
    return 0;
}

/**
 * @brief 打印IPv4地址(数组形式)
 */
void print_ipv4_addr_array(const uint8_t *ip) {
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/**
 * @brief 获取ARP操作码描述
 */
static const char* arp_opcode_name(uint16_t opcode) {
    switch (opcode) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
        default:
            return "Unknown";
    }
}

/**
 * @brief 打印ARP信息
 */
void print_arp_info(const arp_info_t *info) {
    if (!info) return;
    
    printf(COLOR_YELLOW "┌─ ARP Packet ─────────────────────────────────┐\n" COLOR_RESET);
    printf("│ Operation: %s (%u)\n", arp_opcode_name(info->opcode), info->opcode);
    printf("│ Sender MAC: ");
    print_mac_addr(info->sender_mac);
    printf("\n");
    printf("│ Sender IP:  ");
    print_ipv4_addr_array(info->sender_ip);
    printf("\n");
    printf("│ Target MAC: ");
    print_mac_addr(info->target_mac);
    printf("\n");
    printf("│ Target IP:  ");
    print_ipv4_addr_array(info->target_ip);
    printf("\n");
    
    /* 打印ARP摘要 */
    if (info->opcode == ARP_OP_REQUEST) {
        printf("│ " COLOR_GREEN "Summary: Who has ");
        print_ipv4_addr_array(info->target_ip);
        printf("? Tell ");
        print_ipv4_addr_array(info->sender_ip);
        printf(COLOR_RESET "\n");
    } else if (info->opcode == ARP_OP_REPLY) {
        printf("│ " COLOR_GREEN "Summary: ");
        print_ipv4_addr_array(info->sender_ip);
        printf(" is at ");
        print_mac_addr(info->sender_mac);
        printf(COLOR_RESET "\n");
    }
    
    printf(COLOR_YELLOW "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
