/**
 * @file test_parser.c
 * @brief 协议解析器单元测试
 * @version 3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_framework.h"
#include "../include/protocols.h"
#include "../include/parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/* ======================= 测试数据 ======================= */

/* ARP请求报文 (42字节以太网帧) */
static const uint8_t test_arp_request[] = {
    /* Ethernet Header */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst: broadcast */
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,  /* src */
    0x08, 0x06,                          /* type: ARP */
    /* ARP Header */
    0x00, 0x01,                          /* hw type: Ethernet */
    0x08, 0x00,                          /* proto type: IPv4 */
    0x06,                                /* hw len */
    0x04,                                /* proto len */
    0x00, 0x01,                          /* opcode: request */
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,  /* sender MAC */
    0xc0, 0xa8, 0x01, 0x64,              /* sender IP: 192.168.1.100 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* target MAC */
    0xc0, 0xa8, 0x01, 0x01               /* target IP: 192.168.1.1 */
};

/* ICMP Echo Request (74字节) */
static const uint8_t test_icmp_echo_request[] = {
    /* Ethernet Header */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,
    0x08, 0x00,
    /* IPv4 Header (20 bytes) */
    0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00,
    0x40, 0x01, 0xb6, 0x56,
    0xc0, 0xa8, 0x01, 0x64,
    0xc0, 0xa8, 0x01, 0x01,
    /* ICMP Header + Data (40 bytes) */
    0x08, 0x00, 0xf7, 0xf2, 0x00, 0x01, 0x00, 0x01,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
};

/* TCP SYN (54字节) */
static const uint8_t test_tcp_syn[] = {
    /* Ethernet Header */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,
    0x08, 0x00,
    /* IPv4 Header */
    0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x64,
    0x08, 0x08, 0x08, 0x08,
    /* TCP Header */
    0xd4, 0x31, 0x00, 0x50, 0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00
};

/* UDP DNS Query (60字节) */
static const uint8_t test_udp_dns[] = {
    /* Ethernet Header */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,
    0x08, 0x00,
    /* IPv4 Header */
    0x45, 0x00, 0x00, 0x2e, 0x12, 0x34, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x64,
    0x08, 0x08, 0x08, 0x08,
    /* UDP Header */
    0xc0, 0x00, 0x00, 0x35, 0x00, 0x1a, 0x00, 0x00,
    /* DNS Data */
    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x06, 0x67
};

/* IPv6 Echo Request (简化) */
static const uint8_t test_ipv6_packet[] = {
    /* Ethernet Header */
    0x33, 0x33, 0x00, 0x00, 0x00, 0x01,
    0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33,
    0x86, 0xdd,
    /* IPv6 Header (40 bytes) */
    0x60, 0x00, 0x00, 0x00,  /* version + traffic class + flow label */
    0x00, 0x10,              /* payload length: 16 */
    0x3a,                    /* next header: ICMPv6 */
    0x40,                    /* hop limit: 64 */
    /* src: fe80::1 */
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /* dst: ff02::1 */
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /* ICMPv6 Echo Request (8 + 8 bytes) */
    0x80, 0x00,              /* type: Echo Request, code: 0 */
    0x00, 0x00,              /* checksum (placeholder) */
    0x00, 0x01, 0x00, 0x01,  /* id, seq */
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48  /* data */
};

/* ======================= 测试用例 ======================= */

void test_byte_order(void) {
    TEST_CASE("Byte Order Conversion");
    
    uint16_t val16 = 0x1234;
    uint16_t swapped16 = net_to_host16(val16);
    TEST_ASSERT_EQ(0x3412, swapped16, "net_to_host16(0x1234) == 0x3412");
    TEST_ASSERT_EQ(val16, net_to_host16(swapped16), "Double conversion returns original");
    
    uint32_t val32 = 0x12345678;
    uint32_t swapped32 = net_to_host32(val32);
    TEST_ASSERT_EQ(0x78563412, swapped32, "net_to_host32(0x12345678) == 0x78563412");
    TEST_ASSERT_EQ(val32, net_to_host32(swapped32), "Double conversion returns original");
}

void test_checksum(void) {
    TEST_CASE("Checksum Calculation");
    
    uint8_t data1[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t checksum1 = calc_checksum(data1, sizeof(data1));
    TEST_ASSERT_NE(0, checksum1, "Checksum calculated for test data");
    
    uint8_t data2[] = {0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00,
                       0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64,
                       0xc0, 0xa8, 0x01, 0x01};
    uint16_t cs = calc_checksum(data2, sizeof(data2));
    data2[10] = (cs >> 8) & 0xFF;
    data2[11] = cs & 0xFF;
    TEST_ASSERT_TRUE(verify_checksum(data2, sizeof(data2)), "Checksum verification passed");
}

void test_ethernet_parsing(void) {
    TEST_CASE("Ethernet Frame Parsing");
    
    ethernet_header_t eth;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    
    int result = parse_ethernet(test_arp_request, sizeof(test_arp_request),
                                &eth, &payload, &payload_len);
    
    TEST_ASSERT_EQ(0, result, "Ethernet parsing succeeded");
    TEST_ASSERT_EQ(ETHERTYPE_ARP, eth.ether_type, "EtherType is ARP (0x0806)");
    TEST_ASSERT_NOT_NULL(payload, "Payload pointer is not NULL");
    TEST_ASSERT_EQ(28, payload_len, "Payload length is 28 (ARP)");
    
    uint8_t expected_dst[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t expected_src[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
    TEST_ASSERT_MEM_EQ(expected_dst, eth.dst_mac, 6, "Destination MAC is broadcast");
    TEST_ASSERT_MEM_EQ(expected_src, eth.src_mac, 6, "Source MAC correct");
}

void test_arp_parsing(void) {
    TEST_CASE("ARP Packet Parsing");
    
    arp_info_t arp;
    const uint8_t *arp_data = test_arp_request + 14;
    
    int result = parse_arp(arp_data, 28, &arp);
    
    TEST_ASSERT_EQ(0, result, "ARP parsing succeeded");
    TEST_ASSERT_EQ(ARP_OP_REQUEST, arp.opcode, "ARP opcode is Request (1)");
    
    uint8_t expected_sender_ip[] = {192, 168, 1, 100};
    uint8_t expected_target_ip[] = {192, 168, 1, 1};
    TEST_ASSERT_MEM_EQ(expected_sender_ip, arp.sender_ip, 4, "Sender IP is 192.168.1.100");
    TEST_ASSERT_MEM_EQ(expected_target_ip, arp.target_ip, 4, "Target IP is 192.168.1.1");
}

void test_ipv4_parsing(void) {
    TEST_CASE("IPv4 Packet Parsing");
    
    ipv4_info_t ipv4;
    const uint8_t *ipv4_data = test_icmp_echo_request + 14;
    
    int result = parse_ipv4(ipv4_data, 60, &ipv4);
    
    TEST_ASSERT_EQ(0, result, "IPv4 parsing succeeded");
    TEST_ASSERT_EQ(4, ipv4.version, "IP version is 4");
    TEST_ASSERT_EQ(20, ipv4.ihl, "Header length is 20 bytes");
    TEST_ASSERT_EQ(64, ipv4.ttl, "TTL is 64");
    TEST_ASSERT_EQ(IP_PROTO_ICMP, ipv4.protocol, "Protocol is ICMP (1)");
    TEST_ASSERT_EQ(60, ipv4.total_length, "Total length is 60");
    TEST_ASSERT_EQ(CHECKSUM_OK, ipv4.checksum_status, "IPv4 checksum is valid");
}

void test_ipv6_parsing(void) {
    TEST_CASE("IPv6 Packet Parsing");
    
    ipv6_info_t ipv6;
    const uint8_t *ipv6_data = test_ipv6_packet + 14;
    
    int result = parse_ipv6(ipv6_data, 56, &ipv6);
    
    TEST_ASSERT_EQ(0, result, "IPv6 parsing succeeded");
    TEST_ASSERT_EQ(6, ipv6.version, "IP version is 6");
    TEST_ASSERT_EQ(64, ipv6.hop_limit, "Hop limit is 64");
    TEST_ASSERT_EQ(IP_PROTO_ICMPV6, ipv6.next_header, "Next header is ICMPv6 (58)");
    TEST_ASSERT_EQ(16, ipv6.payload_length, "Payload length is 16");
    TEST_ASSERT_EQ(0, ipv6.ext_headers_count, "No extension headers");
}

void test_icmp_parsing(void) {
    TEST_CASE("ICMP Packet Parsing");
    
    icmp_info_t icmp;
    const uint8_t *icmp_data = test_icmp_echo_request + 14 + 20;
    
    int result = parse_icmp(icmp_data, 40, &icmp);
    
    TEST_ASSERT_EQ(0, result, "ICMP parsing succeeded");
    TEST_ASSERT_EQ(ICMP_TYPE_ECHO_REQUEST, icmp.type, "ICMP type is Echo Request (8)");
    TEST_ASSERT_EQ(0, icmp.code, "ICMP code is 0");
    TEST_ASSERT_EQ(1, icmp.identifier, "Identifier is 1");
    TEST_ASSERT_EQ(1, icmp.sequence, "Sequence is 1");
    TEST_ASSERT_EQ(32, icmp.data_len, "Data length is 32");
}

void test_tcp_parsing(void) {
    TEST_CASE("TCP Segment Parsing");
    
    tcp_info_t tcp;
    const uint8_t *tcp_data = test_tcp_syn + 14 + 20;
    
    int result = parse_tcp(tcp_data, 20, &tcp);
    
    TEST_ASSERT_EQ(0, result, "TCP parsing succeeded");
    TEST_ASSERT_EQ(54321, tcp.src_port, "Source port is 54321");
    TEST_ASSERT_EQ(80, tcp.dst_port, "Destination port is 80 (HTTP)");
    TEST_ASSERT_EQ(1000, tcp.seq_num, "Sequence number is 1000");
    TEST_ASSERT_EQ(0, tcp.ack_num, "ACK number is 0");
    TEST_ASSERT_EQ(TCP_FLAG_SYN, tcp.flags, "Flags is SYN");
    TEST_ASSERT_EQ(20, tcp.data_offset, "Header length is 20 bytes");
}

void test_udp_parsing(void) {
    TEST_CASE("UDP Datagram Parsing");
    
    udp_info_t udp;
    const uint8_t *udp_data = test_udp_dns + 14 + 20;
    
    int result = parse_udp(udp_data, 26, &udp);
    
    TEST_ASSERT_EQ(0, result, "UDP parsing succeeded");
    TEST_ASSERT_EQ(49152, udp.src_port, "Source port is 49152");
    TEST_ASSERT_EQ(53, udp.dst_port, "Destination port is 53 (DNS)");
    TEST_ASSERT_EQ(26, udp.length, "UDP length is 26");
    TEST_ASSERT_EQ(18, udp.payload_len, "Payload length is 18");
}

void test_edge_cases(void) {
    TEST_CASE("Edge Cases");
    
    ethernet_header_t eth;
    ipv4_info_t ipv4;
    ipv6_info_t ipv6;
    tcp_info_t tcp;
    
    TEST_ASSERT_EQ(-1, parse_ethernet(NULL, 0, &eth, NULL, NULL), 
                   "NULL data returns -1");
    TEST_ASSERT_EQ(-1, parse_ipv4(NULL, 0, &ipv4),
                   "NULL data returns -1 for IPv4");
    TEST_ASSERT_EQ(-1, parse_ipv6(NULL, 0, &ipv6),
                   "NULL data returns -1 for IPv6");
    TEST_ASSERT_EQ(-1, parse_tcp(NULL, 0, &tcp),
                   "NULL data returns -1 for TCP");
    
    uint8_t short_data[] = {0x00, 0x01, 0x02};
    TEST_ASSERT_EQ(-1, parse_ethernet(short_data, 3, &eth, NULL, NULL),
                   "Short Ethernet frame returns -1");
    TEST_ASSERT_EQ(-1, parse_ipv4(short_data, 3, &ipv4),
                   "Short IPv4 packet returns -1");
    TEST_ASSERT_EQ(-1, parse_ipv6(short_data, 3, &ipv6),
                   "Short IPv6 packet returns -1");
    TEST_ASSERT_EQ(-1, parse_tcp(short_data, 3, &tcp),
                   "Short TCP segment returns -1");
}

void test_struct_sizes(void) {
    TEST_CASE("Protocol Structure Sizes");
    
    TEST_ASSERT_EQ(14, sizeof(ethernet_header_t), 
                   "Ethernet header is 14 bytes");
    TEST_ASSERT_EQ(28, sizeof(arp_header_t),
                   "ARP header is 28 bytes");
    TEST_ASSERT_EQ(20, sizeof(ipv4_header_t),
                   "IPv4 header is 20 bytes");
    TEST_ASSERT_EQ(40, sizeof(ipv6_header_t),
                   "IPv6 header is 40 bytes");
    TEST_ASSERT_EQ(8, sizeof(icmp_header_t),
                   "ICMP header is 8 bytes");
    TEST_ASSERT_EQ(8, sizeof(icmpv6_header_t),
                   "ICMPv6 header is 8 bytes");
    TEST_ASSERT_EQ(20, sizeof(tcp_header_t),
                   "TCP header is 20 bytes");
    TEST_ASSERT_EQ(8, sizeof(udp_header_t),
                   "UDP header is 8 bytes");
}

void test_protocol_names(void) {
    TEST_CASE("Protocol Name Functions");
    
    TEST_ASSERT_TRUE(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REQUEST), "Echo Request") == 0,
                     "ICMP Echo Request name correct");
    TEST_ASSERT_TRUE(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REPLY), "Echo Reply") == 0,
                     "ICMP Echo Reply name correct");
    TEST_ASSERT_TRUE(strcmp(icmpv6_type_name(ICMPV6_TYPE_ECHO_REQUEST), "Echo Request") == 0,
                     "ICMPv6 Echo Request name correct");
    TEST_ASSERT_TRUE(strcmp(checksum_status_name(CHECKSUM_OK), "OK") == 0,
                     "Checksum OK name correct");
}

/* ======================= 主函数 ======================= */

int main(void) {
    log_init(LOG_LEVEL_ERROR, NULL);  /* 测试时只显示错误 */
    
    printf(TEST_COLOR_BOLD TEST_COLOR_YELLOW
           "\n╔════════════════════════════════════════════════════════════════╗\n"
           "║            Packet Parser Unit Tests v3.0                       ║\n"
           "╚════════════════════════════════════════════════════════════════╝\n"
           TEST_COLOR_RESET);
    
    TEST_SUITE_BEGIN("Utility Functions");
    test_byte_order();
    test_checksum();
    TEST_SUITE_END();
    
    TEST_SUITE_BEGIN("Protocol Parsing - Layer 2/3");
    test_ethernet_parsing();
    test_arp_parsing();
    test_ipv4_parsing();
    test_ipv6_parsing();
    TEST_SUITE_END();
    
    TEST_SUITE_BEGIN("Protocol Parsing - Layer 4");
    test_icmp_parsing();
    test_tcp_parsing();
    test_udp_parsing();
    TEST_SUITE_END();
    
    TEST_SUITE_BEGIN("Validation & Edge Cases");
    test_edge_cases();
    test_struct_sizes();
    test_protocol_names();
    TEST_SUITE_END();
    
    test_print_summary();
    
    log_shutdown();
    
    return test_get_result();
}
