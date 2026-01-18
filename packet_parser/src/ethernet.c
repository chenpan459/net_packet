/**
 * @file ethernet.c
 * @brief 以太网帧解析实现 (含VLAN支持)
 * @version 3.1 - 支持802.1Q VLAN标签
 */

#include <stdio.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/**
 * @brief 解析以太网帧 (不处理VLAN)
 */
int parse_ethernet(const uint8_t *data, size_t len,
                   ethernet_header_t *eth_hdr,
                   const uint8_t **payload, size_t *payload_len) {
    
    if (!data || !eth_hdr) {
        return -1;
    }
    
    /* 检查最小长度 */
    if (len < ETH_HDR_LEN) {
        LOG_ERROR("Ethernet frame too short: %zu bytes", len);
        return -1;
    }
    
    /* 复制以太网头 */
    memcpy(eth_hdr, data, sizeof(ethernet_header_t));
    
    /* 转换字节序 */
    eth_hdr->ether_type = net_to_host16(eth_hdr->ether_type);
    
    /* 设置载荷 */
    if (payload) {
        *payload = data + ETH_HDR_LEN;
    }
    if (payload_len) {
        *payload_len = len - ETH_HDR_LEN;
    }
    
    return 0;
}

/**
 * @brief 解析VLAN标签
 */
int parse_vlan(const uint8_t *data, size_t len, vlan_info_t *info,
               const uint8_t **payload, size_t *payload_len) {
    
    if (!data || !info) {
        return -1;
    }
    
    /* VLAN标签至少4字节 */
    if (len < VLAN_TAG_LEN) {
        LOG_ERROR("VLAN tag too short: %zu bytes", len);
        return -1;
    }
    
    const vlan_tag_t *vlan = (const vlan_tag_t *)data;
    uint16_t tci = net_to_host16(vlan->tci);
    
    info->vlan_id = VLAN_VID(tci);
    info->priority = VLAN_PCP(tci);
    info->dei = VLAN_DEI(tci);
    
    /* 内层以太网类型在VLAN标签后 */
    if (len >= VLAN_TAG_LEN + 2) {
        info->ether_type = net_to_host16(*(uint16_t *)(data + 2));
    } else {
        info->ether_type = 0;
    }
    
    /* 设置载荷 (跳过VLAN标签) */
    if (payload) {
        *payload = data + VLAN_TAG_LEN;
    }
    if (payload_len) {
        *payload_len = len - VLAN_TAG_LEN;
    }
    
    LOG_DEBUG("VLAN: ID=%u, Priority=%u, DEI=%u, InnerType=0x%04X",
              info->vlan_id, info->priority, info->dei, info->ether_type);
    
    return 0;
}

/**
 * @brief 解析以太网帧 (含VLAN处理)
 */
int parse_ethernet_vlan(const uint8_t *data, size_t len,
                        ethernet_header_t *eth_hdr,
                        vlan_info_t *vlan_info, int *has_vlan,
                        const uint8_t **payload, size_t *payload_len) {
    
    if (!data || !eth_hdr) {
        return -1;
    }
    
    if (has_vlan) {
        *has_vlan = 0;
    }
    
    /* 先解析基本以太网头 */
    if (parse_ethernet(data, len, eth_hdr, NULL, NULL) != 0) {
        return -1;
    }
    
    const uint8_t *next_payload = data + ETH_HDR_LEN;
    size_t next_len = len - ETH_HDR_LEN;
    
    /* 检查是否有VLAN标签 */
    if (eth_hdr->ether_type == ETHERTYPE_VLAN) {
        if (vlan_info && next_len >= VLAN_TAG_LEN) {
            /* 解析VLAN标签 */
            const vlan_tag_t *vlan = (const vlan_tag_t *)next_payload;
            uint16_t tci = net_to_host16(vlan->tci);
            
            vlan_info->vlan_id = VLAN_VID(tci);
            vlan_info->priority = VLAN_PCP(tci);
            vlan_info->dei = VLAN_DEI(tci);
            
            /* 跳过TPID和TCI，获取内层EtherType */
            if (next_len >= VLAN_TAG_LEN) {
                /* 注意：vlan_tag_t包含tpid(2) + tci(2)，内层ethertype紧随其后 */
                /* 但我们的结构定义中tpid已经被外层ethertype位置使用 */
                /* 所以VLAN payload从TCI后开始，而内层ethertype在原tci位置后2字节 */
                next_payload = data + ETH_HDR_LEN + VLAN_TAG_LEN;
                next_len = len - ETH_HDR_LEN - VLAN_TAG_LEN;
                
                /* 更新eth_hdr的ether_type为内层类型 */
                if (len >= ETH_HDR_LEN + VLAN_TAG_LEN) {
                    /* 读取VLAN标签后的EtherType */
                    vlan_info->ether_type = net_to_host16(
                        *(uint16_t *)(data + ETH_HDR_LEN + 2));
                    eth_hdr->ether_type = vlan_info->ether_type;
                }
            }
            
            if (has_vlan) {
                *has_vlan = 1;
            }
            
            LOG_DEBUG("802.1Q VLAN detected: ID=%u, Priority=%u", 
                      vlan_info->vlan_id, vlan_info->priority);
        }
    }
    
    /* 设置最终载荷 */
    if (payload) {
        *payload = next_payload;
    }
    if (payload_len) {
        *payload_len = next_len;
    }
    
    return 0;
}

/**
 * @brief VLAN优先级名称
 */
const char* vlan_priority_name(uint8_t pcp) {
    static const char* names[] = {
        "Best Effort (BE)",           /* 0 */
        "Background (BK)",            /* 1 */
        "Excellent Effort (EE)",      /* 2 */
        "Critical Apps (CA)",         /* 3 */
        "Video (VI)",                 /* 4 */
        "Voice (VO)",                 /* 5 */
        "Internetwork Control (IC)",  /* 6 */
        "Network Control (NC)"        /* 7 */
    };
    
    if (pcp > 7) return "Unknown";
    return names[pcp];
}

/**
 * @brief 打印MAC地址
 */
void print_mac_addr(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * @brief 打印VLAN信息
 */
void print_vlan_info(const vlan_info_t *info) {
    if (!info) return;
    
    printf(COLOR_YELLOW "┌─ 802.1Q VLAN Tag ────────────────────────────┐\n" COLOR_RESET);
    printf("│ VLAN ID: %u\n", info->vlan_id);
    printf("│ Priority (PCP): %u - %s\n", info->priority, vlan_priority_name(info->priority));
    printf("│ DEI (Drop Eligible): %s\n", info->dei ? "Yes" : "No");
    printf("│ Inner EtherType: 0x%04X", info->ether_type);
    
    switch (info->ether_type) {
        case ETHERTYPE_IPV4:
            printf(" (IPv4)");
            break;
        case ETHERTYPE_IPV6:
            printf(" (IPv6)");
            break;
        case ETHERTYPE_ARP:
            printf(" (ARP)");
            break;
    }
    printf("\n");
    
    printf(COLOR_YELLOW "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}

/**
 * @brief 打印以太网帧信息
 */
void print_ethernet_info(const ethernet_header_t *eth) {
    const char *type_str = "Unknown";
    
    if (!eth) return;
    
    switch (eth->ether_type) {
        case ETHERTYPE_IPV4:
            type_str = "IPv4";
            break;
        case ETHERTYPE_ARP:
            type_str = "ARP";
            break;
        case ETHERTYPE_IPV6:
            type_str = "IPv6";
            break;
        case ETHERTYPE_VLAN:
            type_str = "802.1Q VLAN";
            break;
    }
    
    printf(COLOR_CYAN "┌─ Ethernet Frame ─────────────────────────────┐\n" COLOR_RESET);
    printf("│ Src MAC: ");
    print_mac_addr(eth->src_mac);
    printf("\n");
    printf("│ Dst MAC: ");
    print_mac_addr(eth->dst_mac);
    printf("\n");
    printf("│ Type: 0x%04X (%s)\n", eth->ether_type, type_str);
    printf(COLOR_CYAN "└──────────────────────────────────────────────┘\n" COLOR_RESET);
}
