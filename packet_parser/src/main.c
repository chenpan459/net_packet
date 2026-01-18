/**
 * @file main.c
 * @brief 报文解析框架主程序
 * @description 企业级报文解析工具，支持 IPv4/IPv6、流式解析、日志控制
 * @version 3.0
 * 
 * Usage: ./packet_parser [options] <pcap_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/pcap_parser.h"
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/* 程序配置 */
typedef struct {
    const char *input_file;
    const char *log_file;
    log_level_t log_level;
    int verbose;
    int quiet;
    int stats_only;
    int show_progress;
    pcap_mode_t pcap_mode;
} config_t;

/* 默认配置 */
static config_t g_config = {
    .input_file = NULL,
    .log_file = NULL,
    .log_level = LOG_LEVEL_INFO,
    .verbose = 0,
    .quiet = 0,
    .stats_only = 0,
    .show_progress = 0,
    .pcap_mode = PCAP_MODE_MEMORY
};

/* 统计信息 */
typedef struct {
    uint32_t total_packets;
    uint32_t eth_packets;
    uint32_t arp_packets;
    uint32_t ipv4_packets;
    uint32_t ipv6_packets;
    uint32_t icmp_packets;
    uint32_t icmpv6_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t other_packets;
    uint32_t checksum_ok;
    uint32_t checksum_error;
    uint32_t checksum_skipped;
    uint64_t total_bytes;
} parse_stats_t;

static parse_stats_t g_stats = {0};

/**
 * @brief 更新校验和统计
 */
static void update_checksum_stats(checksum_result_t status) {
    switch (status) {
        case CHECKSUM_OK:
            g_stats.checksum_ok++;
            break;
        case CHECKSUM_ERROR:
            g_stats.checksum_error++;
            break;
        case CHECKSUM_SKIPPED:
            g_stats.checksum_skipped++;
            break;
    }
}

/**
 * @brief 解析完整数据包
 */
void parse_packet(const packet_info_t *pkt) {
    ethernet_header_t eth_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    
    if (!pkt || !pkt->data || pkt->captured_len == 0) {
        return;
    }
    
    g_stats.total_packets++;
    g_stats.total_bytes += pkt->captured_len;
    
    if (!g_config.quiet && !g_config.stats_only) {
        printf("\n" COLOR_BOLD "═══════════ Packet #%u ═══════════" COLOR_RESET "\n", 
               pkt->packet_number);
        printf("Timestamp: %u.%06u | Size: %u/%u bytes\n", 
               pkt->timestamp_sec, pkt->timestamp_usec,
               pkt->captured_len, pkt->original_len);
    }
    
    /* 解析以太网帧 */
    if (parse_ethernet(pkt->data, pkt->captured_len, &eth_hdr, 
                       &payload, &payload_len) != 0) {
        LOG_WARN("Failed to parse Ethernet frame");
        return;
    }
    
    g_stats.eth_packets++;
    if (!g_config.quiet && !g_config.stats_only) {
        print_ethernet_info(&eth_hdr);
    }
    
    /* 根据以太网类型解析上层协议 */
    switch (eth_hdr.ether_type) {
        case ETHERTYPE_ARP: {
            arp_info_t arp_info;
            if (parse_arp(payload, payload_len, &arp_info) == 0) {
                g_stats.arp_packets++;
                if (!g_config.quiet && !g_config.stats_only) {
                    print_arp_info(&arp_info);
                }
            }
            break;
        }
        
        case ETHERTYPE_IPV4: {
            ipv4_info_t ipv4_info;
            if (parse_ipv4(payload, payload_len, &ipv4_info) == 0) {
                g_stats.ipv4_packets++;
                update_checksum_stats(ipv4_info.checksum_status);
                if (!g_config.quiet && !g_config.stats_only) {
                    print_ipv4_info(&ipv4_info);
                }
                
                switch (ipv4_info.protocol) {
                    case IP_PROTO_ICMP: {
                        icmp_info_t icmp_info;
                        if (parse_icmp(ipv4_info.payload, ipv4_info.payload_len, 
                                      &icmp_info) == 0) {
                            g_stats.icmp_packets++;
                            update_checksum_stats(icmp_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_icmp_info(&icmp_info);
                            }
                        }
                        break;
                    }
                    
                    case IP_PROTO_TCP: {
                        tcp_info_t tcp_info;
                        if (parse_tcp_with_checksum(ipv4_info.payload, 
                                                    ipv4_info.payload_len,
                                                    ipv4_info.src_ip,
                                                    ipv4_info.dst_ip,
                                                    &tcp_info) == 0) {
                            g_stats.tcp_packets++;
                            update_checksum_stats(tcp_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_tcp_info(&tcp_info);
                            }
                        }
                        break;
                    }
                    
                    case IP_PROTO_UDP: {
                        udp_info_t udp_info;
                        if (parse_udp_with_checksum(ipv4_info.payload,
                                                    ipv4_info.payload_len,
                                                    ipv4_info.src_ip,
                                                    ipv4_info.dst_ip,
                                                    &udp_info) == 0) {
                            g_stats.udp_packets++;
                            update_checksum_stats(udp_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_udp_info(&udp_info);
                            }
                        }
                        break;
                    }
                    
                    default:
                        g_stats.other_packets++;
                        LOG_DEBUG("Unknown IPv4 protocol: %u", ipv4_info.protocol);
                        break;
                }
            }
            break;
        }
        
        case ETHERTYPE_IPV6: {
            ipv6_info_t ipv6_info;
            if (parse_ipv6(payload, payload_len, &ipv6_info) == 0) {
                g_stats.ipv6_packets++;
                if (!g_config.quiet && !g_config.stats_only) {
                    print_ipv6_info(&ipv6_info);
                }
                
                switch (ipv6_info.next_header) {
                    case IP_PROTO_ICMPV6: {
                        icmpv6_info_t icmpv6_info;
                        if (parse_icmpv6_with_checksum(ipv6_info.payload,
                                                       ipv6_info.payload_len,
                                                       ipv6_info.src_ip,
                                                       ipv6_info.dst_ip,
                                                       &icmpv6_info) == 0) {
                            g_stats.icmpv6_packets++;
                            update_checksum_stats(icmpv6_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_icmpv6_info(&icmpv6_info);
                            }
                        }
                        break;
                    }
                    
                    case IP_PROTO_TCP: {
                        tcp_info_t tcp_info;
                        if (parse_tcp_with_checksum_v6(ipv6_info.payload,
                                                       ipv6_info.payload_len,
                                                       ipv6_info.src_ip,
                                                       ipv6_info.dst_ip,
                                                       &tcp_info) == 0) {
                            g_stats.tcp_packets++;
                            update_checksum_stats(tcp_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_tcp_info(&tcp_info);
                            }
                        }
                        break;
                    }
                    
                    case IP_PROTO_UDP: {
                        udp_info_t udp_info;
                        if (parse_udp_with_checksum_v6(ipv6_info.payload,
                                                       ipv6_info.payload_len,
                                                       ipv6_info.src_ip,
                                                       ipv6_info.dst_ip,
                                                       &udp_info) == 0) {
                            g_stats.udp_packets++;
                            update_checksum_stats(udp_info.checksum_status);
                            if (!g_config.quiet && !g_config.stats_only) {
                                print_udp_info(&udp_info);
                            }
                        }
                        break;
                    }
                    
                    default:
                        g_stats.other_packets++;
                        break;
                }
            }
            break;
        }
        
        default:
            g_stats.other_packets++;
            LOG_DEBUG("Unknown EtherType: 0x%04X", eth_hdr.ether_type);
            break;
    }
}

/**
 * @brief 打印统计信息
 */
static void print_stats(double elapsed_ms) {
    double pps = (elapsed_ms > 0) ? 
                 (g_stats.total_packets / (elapsed_ms / 1000.0)) : 0;
    double mbps = (elapsed_ms > 0) ? 
                  ((g_stats.total_bytes * 8.0) / (elapsed_ms / 1000.0) / 1000000.0) : 0;
    
    printf("\n" COLOR_BOLD 
           "╔═══════════════════════════════════════════════════════════════╗\n"
           "║                      Statistics                               ║\n"
           "╚═══════════════════════════════════════════════════════════════╝\n" 
           COLOR_RESET);
    
    printf("\n" COLOR_CYAN "Protocol Distribution:" COLOR_RESET "\n");
    printf("  Total Packets:    %u\n", g_stats.total_packets);
    printf("  Total Bytes:      %lu\n", (unsigned long)g_stats.total_bytes);
    printf("  ├── Ethernet:     %u\n", g_stats.eth_packets);
    printf("  ├── ARP:          %u\n", g_stats.arp_packets);
    printf("  ├── IPv4:         %u\n", g_stats.ipv4_packets);
    printf("  │   ├── ICMP:     %u\n", g_stats.icmp_packets);
    printf("  │   ├── TCP:      %u\n", g_stats.tcp_packets);
    printf("  │   └── UDP:      %u\n", g_stats.udp_packets);
    printf("  ├── IPv6:         %u\n", g_stats.ipv6_packets);
    printf("  │   └── ICMPv6:   %u\n", g_stats.icmpv6_packets);
    printf("  └── Other:        %u\n", g_stats.other_packets);
    
    printf("\n" COLOR_CYAN "Checksum Verification:" COLOR_RESET "\n");
    printf("  " COLOR_GREEN "Valid:   %u" COLOR_RESET "\n", g_stats.checksum_ok);
    if (g_stats.checksum_error > 0) {
        printf("  " COLOR_YELLOW "Invalid: %u" COLOR_RESET "\n", g_stats.checksum_error);
    } else {
        printf("  Invalid: %u\n", g_stats.checksum_error);
    }
    printf("  Skipped: %u\n", g_stats.checksum_skipped);
    
    if (g_stats.checksum_error > 0) {
        printf("\n" COLOR_YELLOW "  Note: Checksum errors may be caused by NIC checksum offload.\n"
               "        This is normal for locally captured traffic." COLOR_RESET "\n");
    }
    
    printf("\n" COLOR_CYAN "Performance:" COLOR_RESET "\n");
    printf("  Parse Time:  %.3f ms\n", elapsed_ms);
    printf("  Throughput:  %.0f pps, %.2f Mbps\n", pps, mbps);
}

/**
 * @brief 打印使用说明
 */
static void print_usage(const char *prog_name) {
    printf("Usage: %s [options] <pcap_file>\n\n", prog_name);
    printf("Enterprise-grade packet parser with IPv4/IPv6 support.\n\n");
    printf("Options:\n");
    printf("  -l, --log-level <level>  Set log level (trace,debug,info,warn,error,off)\n");
    printf("  -L, --log-file <file>    Write logs to file\n");
    printf("  -s, --stats-only         Only show statistics, no packet details\n");
    printf("  -q, --quiet              Suppress all output except errors\n");
    printf("  -p, --progress           Show parsing progress\n");
    printf("  -m, --mode <mode>        Force parse mode (memory,stream)\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nSupported Protocols:\n");
    printf("  Layer 2: Ethernet\n");
    printf("  Layer 3: ARP, IPv4, IPv6\n");
    printf("  Layer 4: ICMP, ICMPv6, TCP, UDP\n");
    printf("\nExamples:\n");
    printf("  %s capture.pcap\n", prog_name);
    printf("  %s -s -l warn large_capture.pcap\n", prog_name);
    printf("  %s -m stream -p huge_file.pcap\n", prog_name);
}

/**
 * @brief 解析命令行参数
 */
static int parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"log-level",  required_argument, 0, 'l'},
        {"log-file",   required_argument, 0, 'L'},
        {"stats-only", no_argument,       0, 's'},
        {"quiet",      no_argument,       0, 'q'},
        {"progress",   no_argument,       0, 'p'},
        {"mode",       required_argument, 0, 'm'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "l:L:sqpm:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'l':
                g_config.log_level = log_level_from_string(optarg);
                break;
            case 'L':
                g_config.log_file = optarg;
                break;
            case 's':
                g_config.stats_only = 1;
                break;
            case 'q':
                g_config.quiet = 1;
                break;
            case 'p':
                g_config.show_progress = 1;
                break;
            case 'm':
                if (strcmp(optarg, "stream") == 0) {
                    g_config.pcap_mode = PCAP_MODE_STREAM;
                } else {
                    g_config.pcap_mode = PCAP_MODE_MEMORY;
                }
                break;
            case 'v':
                g_config.verbose = 1;
                g_config.log_level = LOG_LEVEL_DEBUG;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                return -1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: No input file specified\n");
        print_usage(argv[0]);
        return -1;
    }
    
    g_config.input_file = argv[optind];
    return 0;
}

/**
 * @brief 主函数
 */
int main(int argc, char *argv[]) {
    pcap_context_t ctx;
    packet_info_t pkt;
    int result = 0;
    perf_timer_t timer;
    
    /* 解析参数 */
    if (parse_args(argc, argv) != 0) {
        return 1;
    }
    
    /* 初始化日志 */
    log_init(g_config.log_level, g_config.log_file);
    
    if (!g_config.quiet) {
        printf(COLOR_BOLD COLOR_CYAN 
               "\n╔═══════════════════════════════════════════════════════════════╗\n"
               "║           Packet Parser Framework v3.0 Enterprise             ║\n"
               "║   Supports: IPv4, IPv6, ARP, ICMP, ICMPv6, TCP, UDP            ║\n"
               "║   Features: Streaming, Logging, Checksum Verification          ║\n"
               "╚═══════════════════════════════════════════════════════════════╝\n\n" 
               COLOR_RESET);
    }
    
    /* 打开PCAP文件 */
    LOG_INFO("Opening PCAP file: %s", g_config.input_file);
    
    if (pcap_open_ex(g_config.input_file, &ctx, g_config.pcap_mode) != 0) {
        LOG_FATAL("Failed to open PCAP file: %s", g_config.input_file);
        return 1;
    }
    
    if (ctx.link_type != LINKTYPE_ETHERNET) {
        LOG_WARN("Non-Ethernet link type (%s), results may be incorrect", 
                 pcap_linktype_name(ctx.link_type));
    }
    
    /* 开始解析 */
    LOG_INFO("Starting packet parsing...");
    perf_timer_start(&timer);
    
    int last_progress = -1;
    while ((result = pcap_read_packet(&ctx, &pkt)) == 1) {
        parse_packet(&pkt);
        
        /* 显示进度 */
        if (g_config.show_progress && !g_config.quiet) {
            int progress = pcap_get_progress(&ctx);
            if (progress != last_progress && progress % 10 == 0) {
                printf("\rProgress: %d%%", progress);
                fflush(stdout);
                last_progress = progress;
            }
        }
    }
    
    if (g_config.show_progress && !g_config.quiet) {
        printf("\rProgress: 100%%\n");
    }
    
    double elapsed_ms = perf_timer_stop(&timer);
    
    if (result < 0) {
        LOG_ERROR("Error reading packets");
    }
    
    /* 打印统计 */
    if (!g_config.quiet) {
        print_stats(elapsed_ms);
    }
    
    /* 清理 */
    pcap_close(&ctx);
    log_shutdown();
    
    LOG_INFO("Parsing complete");
    
    return 0;
}
