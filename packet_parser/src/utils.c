/**
 * @file utils.c
 * @brief 工具函数实现
 * @version 3.0
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../include/utils.h"
#include "../include/protocols.h"

/**
 * @brief 计算Internet校验和
 */
uint16_t calc_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;
    size_t count = len;
    
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}

/**
 * @brief 验证校验和
 */
int verify_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;
    size_t count = len;
    
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ((uint16_t)sum == 0xFFFF);
}

/**
 * @brief 计算带伪首部的校验和
 */
uint16_t calc_pseudo_checksum(const uint8_t *pseudo_hdr, size_t pseudo_len,
                               const uint8_t *data, size_t data_len) {
    uint32_t sum = 0;
    const uint16_t *ptr;
    size_t count;
    
    ptr = (const uint16_t *)pseudo_hdr;
    count = pseudo_len;
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    ptr = (const uint16_t *)data;
    count = data_len;
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}

/**
 * @brief 验证IPv4 TCP/UDP校验和
 */
int verify_transport_checksum(uint32_t src_ip, uint32_t dst_ip, 
                               uint8_t protocol,
                               const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr;
    size_t count;
    
    /* 构建伪首部并累加 */
    uint8_t pseudo[12];
    memcpy(&pseudo[0], &src_ip, 4);
    memcpy(&pseudo[4], &dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = protocol;
    uint16_t len_net = host_to_net16((uint16_t)len);
    memcpy(&pseudo[10], &len_net, 2);
    
    ptr = (const uint16_t *)pseudo;
    count = sizeof(pseudo);
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    
    ptr = (const uint16_t *)data;
    count = len;
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ((uint16_t)sum == 0xFFFF);
}

/**
 * @brief 验证IPv6 TCP/UDP/ICMPv6校验和
 */
int verify_transport_checksum_v6(const uint8_t *src_ip, const uint8_t *dst_ip,
                                  uint8_t protocol,
                                  const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr;
    size_t count;
    
    /* IPv6 伪首部: src(16) + dst(16) + len(4) + zeros(3) + next_header(1) = 40字节 */
    uint8_t pseudo[40];
    memcpy(&pseudo[0], src_ip, 16);
    memcpy(&pseudo[16], dst_ip, 16);
    
    /* 长度字段 (32位，网络字节序) */
    uint32_t len32 = host_to_net32((uint32_t)len);
    memcpy(&pseudo[32], &len32, 4);
    
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = protocol;
    
    /* 累加伪首部 */
    ptr = (const uint16_t *)pseudo;
    count = sizeof(pseudo);
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    
    /* 累加数据 */
    ptr = (const uint16_t *)data;
    count = len;
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ((uint16_t)sum == 0xFFFF);
}

/**
 * @brief 以十六进制格式打印数据
 */
void hex_dump(const uint8_t *data, size_t len, int bytes_per_line) {
    size_t i, j;
    
    if (!data || len == 0) {
        return;
    }
    
    if (bytes_per_line <= 0) {
        bytes_per_line = 16;
    }
    
    for (i = 0; i < len; i += bytes_per_line) {
        printf("  %04zx: ", i);
        
        for (j = 0; j < (size_t)bytes_per_line; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) {
                printf(" ");
            }
        }
        
        printf(" |");
        
        for (j = 0; j < (size_t)bytes_per_line && i + j < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("|\n");
    }
}
