/**
 * @file benchmark.c
 * @brief 性能基准测试
 * @description 测试解析器的吞吐量和延迟
 * @version 3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/pcap_parser.h"
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/* 基准测试结果 */
typedef struct {
    char name[64];
    uint32_t iterations;
    double total_time_ms;
    double avg_time_us;
    double min_time_us;
    double max_time_us;
    double ops_per_sec;
} bench_result_t;

/* 全局测试数据 */
static uint8_t g_eth_packet[64];
static uint8_t g_ipv4_packet[60];
static uint8_t g_tcp_packet[40];

/**
 * @brief 初始化测试数据
 */
static void init_test_data(void) {
    /* 以太网帧头 */
    memset(g_eth_packet, 0, sizeof(g_eth_packet));
    g_eth_packet[12] = 0x08;
    g_eth_packet[13] = 0x00;
    
    /* IPv4数据包 */
    memset(g_ipv4_packet, 0, sizeof(g_ipv4_packet));
    g_ipv4_packet[0] = 0x45;  /* version + ihl */
    g_ipv4_packet[2] = 0x00;  /* total length */
    g_ipv4_packet[3] = 0x3c;
    g_ipv4_packet[8] = 64;    /* ttl */
    g_ipv4_packet[9] = 6;     /* protocol: TCP */
    
    /* TCP段 */
    memset(g_tcp_packet, 0, sizeof(g_tcp_packet));
    g_tcp_packet[12] = 0x50;  /* data offset */
    g_tcp_packet[13] = 0x02;  /* SYN */
}

/**
 * @brief 获取高精度时间 (微秒)
 */
static double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

/**
 * @brief 运行单个基准测试
 */
static void run_benchmark(const char *name, 
                          void (*func)(void), 
                          uint32_t iterations,
                          bench_result_t *result) {
    double start, end, elapsed;
    double min_time = 1e9, max_time = 0;
    double total_time = 0;
    
    /* 预热 */
    for (uint32_t i = 0; i < 1000; i++) {
        func();
    }
    
    /* 实际测试 */
    for (uint32_t i = 0; i < iterations; i++) {
        start = get_time_us();
        func();
        end = get_time_us();
        
        elapsed = end - start;
        total_time += elapsed;
        
        if (elapsed < min_time) min_time = elapsed;
        if (elapsed > max_time) max_time = elapsed;
    }
    
    strncpy(result->name, name, sizeof(result->name) - 1);
    result->iterations = iterations;
    result->total_time_ms = total_time / 1000.0;
    result->avg_time_us = total_time / iterations;
    result->min_time_us = min_time;
    result->max_time_us = max_time;
    result->ops_per_sec = iterations / (total_time / 1000000.0);
}

/* ======================= 测试函数 ======================= */

static void bench_ethernet_parse(void) {
    ethernet_header_t eth;
    const uint8_t *payload;
    size_t payload_len;
    parse_ethernet(g_eth_packet, sizeof(g_eth_packet), &eth, &payload, &payload_len);
}

static void bench_ipv4_parse(void) {
    ipv4_info_t info;
    parse_ipv4(g_ipv4_packet, sizeof(g_ipv4_packet), &info);
}

static void bench_tcp_parse(void) {
    tcp_info_t info;
    parse_tcp(g_tcp_packet, sizeof(g_tcp_packet), &info);
}

static void bench_checksum(void) {
    calc_checksum(g_ipv4_packet, 20);
}

static void bench_byte_swap16(void) {
    volatile uint16_t val = 0x1234;
    volatile uint16_t result = net_to_host16(val);
    (void)result;
}

static void bench_byte_swap32(void) {
    volatile uint32_t val = 0x12345678;
    volatile uint32_t result = net_to_host32(val);
    (void)result;
}

/**
 * @brief 打印基准测试结果
 */
static void print_result(const bench_result_t *result) {
    printf("│ %-25s │ %10.2f │ %10.2f │ %10.2f │ %12.0f │\n",
           result->name,
           result->avg_time_us,
           result->min_time_us,
           result->max_time_us,
           result->ops_per_sec);
}

/**
 * @brief PCAP文件基准测试
 */
static void bench_pcap_file(const char *filename) {
    pcap_context_t ctx;
    packet_info_t pkt;
    double start, end;
    uint32_t packet_count = 0;
    uint64_t total_bytes = 0;
    
    printf("\n" COLOR_CYAN "PCAP File Benchmark: %s\n" COLOR_RESET, filename);
    printf("─────────────────────────────────────────────────────────────────\n");
    
    if (pcap_open(filename, &ctx) != 0) {
        printf("Failed to open PCAP file\n");
        return;
    }
    
    start = get_time_us();
    
    while (pcap_read_packet(&ctx, &pkt) == 1) {
        /* 完整解析数据包 */
        ethernet_header_t eth;
        const uint8_t *payload;
        size_t payload_len;
        
        if (parse_ethernet(pkt.data, pkt.captured_len, &eth, &payload, &payload_len) == 0) {
            if (eth.ether_type == ETHERTYPE_IPV4) {
                ipv4_info_t ipv4;
                if (parse_ipv4(payload, payload_len, &ipv4) == 0) {
                    if (ipv4.protocol == IP_PROTO_TCP) {
                        tcp_info_t tcp;
                        parse_tcp(ipv4.payload, ipv4.payload_len, &tcp);
                    } else if (ipv4.protocol == IP_PROTO_UDP) {
                        udp_info_t udp;
                        parse_udp(ipv4.payload, ipv4.payload_len, &udp);
                    }
                }
            }
        }
        
        packet_count++;
        total_bytes += pkt.captured_len;
    }
    
    end = get_time_us();
    
    double elapsed_ms = (end - start) / 1000.0;
    double pps = packet_count / (elapsed_ms / 1000.0);
    double mbps = (total_bytes * 8.0) / (elapsed_ms / 1000.0) / 1000000.0;
    
    printf("Packets:    %u\n", packet_count);
    printf("Bytes:      %lu\n", (unsigned long)total_bytes);
    printf("Time:       %.3f ms\n", elapsed_ms);
    printf("Throughput: %.0f pps, %.2f Mbps\n", pps, mbps);
    
    pcap_close(&ctx);
}

/**
 * @brief 主函数
 */
int main(int argc, char *argv[]) {
    bench_result_t results[10];
    int result_count = 0;
    uint32_t iterations = 1000000;
    
    log_init(LOG_LEVEL_WARN, NULL);
    
    printf(COLOR_BOLD COLOR_CYAN
           "\n╔════════════════════════════════════════════════════════════════╗\n"
           "║           Packet Parser Benchmark Suite v3.0                   ║\n"
           "╚════════════════════════════════════════════════════════════════╝\n\n"
           COLOR_RESET);
    
    init_test_data();
    
    printf(COLOR_YELLOW "Configuration:\n" COLOR_RESET);
    printf("  Iterations: %u\n", iterations);
    printf("  CPU warmup: 1000 iterations\n\n");
    
    /* 运行基准测试 */
    printf(COLOR_CYAN "Running micro-benchmarks...\n" COLOR_RESET);
    
    run_benchmark("Byte Swap 16-bit", bench_byte_swap16, iterations, &results[result_count++]);
    run_benchmark("Byte Swap 32-bit", bench_byte_swap32, iterations, &results[result_count++]);
    run_benchmark("Checksum (20 bytes)", bench_checksum, iterations, &results[result_count++]);
    run_benchmark("Ethernet Parse", bench_ethernet_parse, iterations, &results[result_count++]);
    run_benchmark("IPv4 Parse", bench_ipv4_parse, iterations, &results[result_count++]);
    run_benchmark("TCP Parse", bench_tcp_parse, iterations, &results[result_count++]);
    
    /* 打印结果 */
    printf("\n" COLOR_BOLD "Benchmark Results:\n" COLOR_RESET);
    printf("┌───────────────────────────┬────────────┬────────────┬────────────┬──────────────┐\n");
    printf("│ Benchmark                 │   Avg (us) │   Min (us) │   Max (us) │      Ops/sec │\n");
    printf("├───────────────────────────┼────────────┼────────────┼────────────┼──────────────┤\n");
    
    for (int i = 0; i < result_count; i++) {
        print_result(&results[i]);
    }
    
    printf("└───────────────────────────┴────────────┴────────────┴────────────┴──────────────┘\n");
    
    /* PCAP文件基准测试 */
    if (argc > 1) {
        bench_pcap_file(argv[1]);
    } else {
        printf("\n" COLOR_YELLOW "Tip: Run with PCAP file for throughput benchmark:\n" COLOR_RESET);
        printf("  ./benchmark capture.pcap\n");
    }
    
    /* 性能总结 */
    printf("\n" COLOR_BOLD "Performance Summary:\n" COLOR_RESET);
    printf("  - Single packet parse: ~%.2f us\n", 
           results[3].avg_time_us + results[4].avg_time_us + results[5].avg_time_us);
    printf("  - Theoretical max: ~%.0f Kpps (single thread)\n",
           1000000.0 / (results[3].avg_time_us + results[4].avg_time_us + results[5].avg_time_us));
    
    log_shutdown();
    
    return 0;
}
