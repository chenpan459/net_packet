/**
 * @file test_fuzz.c
 * @brief 模糊测试和边界条件测试
 * @version 3.1
 * 
 * 测试内容:
 * - 随机数据输入
 * - 边界条件 (零长度、最小长度、最大长度)
 * - 畸形数据包
 * - 截断数据包
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/parser.h"
#include "../include/protocols.h"
#include "../include/utils.h"
#include "../include/log.h"

/* 测试配置 */
#define FUZZ_ITERATIONS     10000
#define MAX_PACKET_SIZE     65535
#define RANDOM_SEED         0  /* 0 = 使用时间作为种子 */

/* 测试统计 */
static struct {
    int total_tests;
    int crashes;
    int parse_errors;
    int parse_success;
} fuzz_stats = {0};

/* ======================= 工具函数 ======================= */

/**
 * @brief 生成随机字节
 */
static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

/**
 * @brief 生成随机长度
 */
static size_t random_len(size_t max) {
    if (max == 0) return 0;
    return rand() % (max + 1);
}

/* ======================= 边界测试 ======================= */

/**
 * @brief 测试零长度输入
 */
static void test_zero_length(void) {
    printf("  Testing zero-length inputs...\n");
    
    ethernet_header_t eth;
    ipv4_info_t ipv4;
    ipv6_info_t ipv6;
    tcp_info_t tcp;
    udp_info_t udp;
    icmp_info_t icmp;
    arp_info_t arp;
    
    /* 所有解析器应安全处理零长度 */
    parse_ethernet(NULL, 0, &eth, NULL, NULL);
    parse_ipv4(NULL, 0, &ipv4);
    parse_ipv6(NULL, 0, &ipv6);
    parse_tcp(NULL, 0, &tcp);
    parse_udp(NULL, 0, &udp);
    parse_icmp(NULL, 0, &icmp);
    parse_arp(NULL, 0, &arp);
    
    uint8_t empty[1] = {0};
    parse_ethernet(empty, 0, &eth, NULL, NULL);
    parse_ipv4(empty, 0, &ipv4);
    parse_ipv6(empty, 0, &ipv6);
    parse_tcp(empty, 0, &tcp);
    parse_udp(empty, 0, &udp);
    parse_icmp(empty, 0, &icmp);
    parse_arp(empty, 0, &arp);
    
    printf("    [PASS] Zero-length inputs handled safely\n");
}

/**
 * @brief 测试最小长度边界
 */
static void test_min_length(void) {
    printf("  Testing minimum length boundaries...\n");
    
    uint8_t buf[100];
    memset(buf, 0, sizeof(buf));
    
    ethernet_header_t eth;
    ipv4_info_t ipv4;
    tcp_info_t tcp;
    udp_info_t udp;
    
    /* 测试刚好小于最小长度 */
    for (size_t len = 0; len < ETH_HDR_LEN; len++) {
        if (parse_ethernet(buf, len, &eth, NULL, NULL) == 0) {
            printf("    [FAIL] Ethernet accepted %zu bytes (min=%d)\n", len, ETH_HDR_LEN);
            return;
        }
    }
    
    for (size_t len = 0; len < IPV4_HDR_MIN_LEN; len++) {
        if (parse_ipv4(buf, len, &ipv4) == 0) {
            printf("    [FAIL] IPv4 accepted %zu bytes (min=%d)\n", len, IPV4_HDR_MIN_LEN);
            return;
        }
    }
    
    for (size_t len = 0; len < TCP_HDR_MIN_LEN; len++) {
        if (parse_tcp(buf, len, &tcp) == 0) {
            printf("    [FAIL] TCP accepted %zu bytes (min=%d)\n", len, TCP_HDR_MIN_LEN);
            return;
        }
    }
    
    for (size_t len = 0; len < UDP_HDR_LEN; len++) {
        if (parse_udp(buf, len, &udp) == 0) {
            printf("    [FAIL] UDP accepted %zu bytes (min=%d)\n", len, UDP_HDR_LEN);
            return;
        }
    }
    
    printf("    [PASS] Minimum length checks working\n");
}

/**
 * @brief 测试畸形头部
 */
static void test_malformed_headers(void) {
    printf("  Testing malformed headers...\n");
    
    uint8_t buf[100];
    ipv4_info_t ipv4;
    tcp_info_t tcp;
    
    /* IPv4: 错误的版本号 */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x65;  /* 版本6, IHL=5 */
    buf[9] = 6;     /* TCP */
    if (parse_ipv4(buf, IPV4_HDR_MIN_LEN, &ipv4) == 0) {
        printf("    [FAIL] IPv4 accepted version 6\n");
        return;
    }
    
    /* IPv4: IHL 太小 */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x43;  /* 版本4, IHL=3 (12 bytes < 20) */
    if (parse_ipv4(buf, IPV4_HDR_MIN_LEN, &ipv4) == 0) {
        printf("    [FAIL] IPv4 accepted IHL=3\n");
        return;
    }
    
    /* TCP: Data Offset 太小 */
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x30;  /* Data Offset = 3 (12 bytes < 20) */
    if (parse_tcp(buf, TCP_HDR_MIN_LEN, &tcp) == 0) {
        printf("    [FAIL] TCP accepted Data Offset < 5\n");
        return;
    }
    
    printf("    [PASS] Malformed headers rejected\n");
}

/* ======================= 随机模糊测试 ======================= */

/**
 * @brief 对单个解析器进行模糊测试
 */
static void fuzz_parser(const char *name, 
                        int (*parser)(const uint8_t*, size_t, void*),
                        void *info, size_t info_size) {
    uint8_t *buf = malloc(MAX_PACKET_SIZE);
    if (!buf) return;
    
    int local_crashes = 0;
    int local_errors = 0;
    int local_success = 0;
    
    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        /* 生成随机长度和数据 */
        size_t len = random_len(MAX_PACKET_SIZE);
        random_bytes(buf, len);
        
        /* 清空info结构 */
        memset(info, 0, info_size);
        
        /* 尝试解析 */
        int ret = parser(buf, len, info);
        
        if (ret == 0) {
            local_success++;
        } else {
            local_errors++;
        }
        
        fuzz_stats.total_tests++;
    }
    
    printf("    %s: %d success, %d errors (no crashes)\n", 
           name, local_success, local_errors);
    
    fuzz_stats.parse_success += local_success;
    fuzz_stats.parse_errors += local_errors;
    
    free(buf);
}

/**
 * @brief 包装函数 - 适配不同的解析器签名
 */
static int wrap_ethernet(const uint8_t *data, size_t len, void *info) {
    return parse_ethernet(data, len, (ethernet_header_t*)info, NULL, NULL);
}

static int wrap_ipv4(const uint8_t *data, size_t len, void *info) {
    return parse_ipv4(data, len, (ipv4_info_t*)info);
}

static int wrap_ipv6(const uint8_t *data, size_t len, void *info) {
    return parse_ipv6(data, len, (ipv6_info_t*)info);
}

static int wrap_tcp(const uint8_t *data, size_t len, void *info) {
    return parse_tcp(data, len, (tcp_info_t*)info);
}

static int wrap_udp(const uint8_t *data, size_t len, void *info) {
    return parse_udp(data, len, (udp_info_t*)info);
}

static int wrap_icmp(const uint8_t *data, size_t len, void *info) {
    return parse_icmp(data, len, (icmp_info_t*)info);
}

static int wrap_arp(const uint8_t *data, size_t len, void *info) {
    return parse_arp(data, len, (arp_info_t*)info);
}

/**
 * @brief 运行随机模糊测试
 */
static void run_random_fuzz(void) {
    printf("  Running random fuzz tests (%d iterations per parser)...\n", FUZZ_ITERATIONS);
    
    ethernet_header_t eth;
    ipv4_info_t ipv4;
    ipv6_info_t ipv6;
    tcp_info_t tcp;
    udp_info_t udp;
    icmp_info_t icmp;
    arp_info_t arp;
    
    fuzz_parser("Ethernet", wrap_ethernet, &eth, sizeof(eth));
    fuzz_parser("IPv4", wrap_ipv4, &ipv4, sizeof(ipv4));
    fuzz_parser("IPv6", wrap_ipv6, &ipv6, sizeof(ipv6));
    fuzz_parser("TCP", wrap_tcp, &tcp, sizeof(tcp));
    fuzz_parser("UDP", wrap_udp, &udp, sizeof(udp));
    fuzz_parser("ICMP", wrap_icmp, &icmp, sizeof(icmp));
    fuzz_parser("ARP", wrap_arp, &arp, sizeof(arp));
}

/* ======================= TCP选项模糊测试 ======================= */

/**
 * @brief TCP选项专项模糊测试
 */
static void fuzz_tcp_options(void) {
    printf("  Running TCP options fuzz tests...\n");
    
    uint8_t buf[100];
    tcp_options_t opts;
    int errors = 0;
    
    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        size_t len = random_len(40);  /* TCP选项最大40字节 */
        random_bytes(buf, len);
        
        /* 这不应该崩溃 */
        parse_tcp_options(buf, len, &opts);
    }
    
    /* 测试特定边界情况 */
    
    /* 1. 选项长度为0 */
    buf[0] = TCP_OPT_MSS;
    buf[1] = 0;  /* 无效长度 */
    parse_tcp_options(buf, 10, &opts);
    
    /* 2. 选项长度超过剩余数据 */
    buf[0] = TCP_OPT_MSS;
    buf[1] = 100;  /* 超长 */
    parse_tcp_options(buf, 10, &opts);
    
    /* 3. 未终止的选项列表 */
    for (int j = 0; j < 40; j++) {
        buf[j] = TCP_OPT_NOP;
    }
    parse_tcp_options(buf, 40, &opts);
    
    printf("    [PASS] TCP options fuzz completed\n");
}

/* ======================= VLAN模糊测试 ======================= */

/**
 * @brief VLAN解析模糊测试
 */
static void fuzz_vlan(void) {
    printf("  Running VLAN fuzz tests...\n");
    
    uint8_t buf[100];
    vlan_info_t vlan;
    
    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        size_t len = random_len(20);
        random_bytes(buf, len);
        
        parse_vlan(buf, len, &vlan, NULL, NULL);
    }
    
    printf("    [PASS] VLAN fuzz completed\n");
}

/* ======================= 主函数 ======================= */

int main(int argc, char *argv[]) {
    unsigned int seed = RANDOM_SEED;
    
    if (seed == 0) {
        seed = (unsigned int)time(NULL);
    }
    srand(seed);
    
    /* 禁用日志输出 */
    log_set_level(LOG_LEVEL_FATAL);
    
    printf("\n");
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║     Packet Parser Fuzz Testing                 ║\n");
    printf("╚════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Random seed: %u\n\n", seed);
    
    /* 边界测试 */
    printf("[TEST SUITE] Boundary Tests\n");
    test_zero_length();
    test_min_length();
    test_malformed_headers();
    printf("\n");
    
    /* 随机模糊测试 */
    printf("[TEST SUITE] Random Fuzz Tests\n");
    run_random_fuzz();
    printf("\n");
    
    /* 专项模糊测试 */
    printf("[TEST SUITE] Specialized Fuzz Tests\n");
    fuzz_tcp_options();
    fuzz_vlan();
    printf("\n");
    
    /* 汇总 */
    printf("═══════════════════════════════════════════════\n");
    printf("              Fuzz Test Summary                \n");
    printf("═══════════════════════════════════════════════\n");
    printf("Total Tests:    %d\n", fuzz_stats.total_tests);
    printf("Parse Success:  %d\n", fuzz_stats.parse_success);
    printf("Parse Errors:   %d (expected)\n", fuzz_stats.parse_errors);
    printf("Crashes:        %d\n", fuzz_stats.crashes);
    printf("═══════════════════════════════════════════════\n");
    
    if (fuzz_stats.crashes == 0) {
        printf(COLOR_GREEN "✓ All fuzz tests passed - no crashes detected!\n" COLOR_RESET);
        return 0;
    } else {
        printf(COLOR_RED "✗ Fuzz tests found %d crashes!\n" COLOR_RESET, fuzz_stats.crashes);
        return 1;
    }
}
