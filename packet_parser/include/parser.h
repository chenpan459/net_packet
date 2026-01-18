/**
 * @file parser.h
 * @brief 协议解析器接口
 * @description 统一的报文解析接口和回调机制
 * @version 3.0 - 支持IPv6和ICMPv6
 */

#ifndef PARSER_H
#define PARSER_H

#include "protocols.h"
#include "pcap_parser.h"

/* ======================= 校验和验证结果 ======================= */

typedef enum {
    CHECKSUM_OK = 0,        /* 校验和正确 */
    CHECKSUM_ERROR = 1,     /* 校验和错误 */
    CHECKSUM_SKIPPED = 2    /* 未验证 (如校验和为0) */
} checksum_result_t;

/* ======================= 解析结果结构 ======================= */

/**
 * @brief VLAN解析结果
 */
typedef struct {
    uint16_t vlan_id;      /* VLAN ID (0-4095) */
    uint8_t  priority;     /* 优先级 (0-7) */
    uint8_t  dei;          /* 丢弃合格指示 */
    uint16_t ether_type;   /* 内层以太网类型 */
} vlan_info_t;

/**
 * @brief ARP解析结果
 */
typedef struct {
    uint16_t opcode;
    uint8_t  sender_mac[ETH_ADDR_LEN];
    uint8_t  sender_ip[IPV4_ADDR_LEN];
    uint8_t  target_mac[ETH_ADDR_LEN];
    uint8_t  target_ip[IPV4_ADDR_LEN];
} arp_info_t;

/**
 * @brief IPv4分片状态
 */
typedef enum {
    FRAG_NONE = 0,       /* 未分片 */
    FRAG_FIRST,          /* 首片 */
    FRAG_MIDDLE,         /* 中间片 */
    FRAG_LAST            /* 末片 */
} frag_status_t;

/**
 * @brief IPv4解析结果
 */
typedef struct {
    uint8_t  version;
    uint8_t  ihl;              /* 首部长度(字节) */
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint8_t  flags;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    const uint8_t *payload;    /* 载荷指针 */
    uint16_t payload_len;      /* 载荷长度 */
    checksum_result_t checksum_status;
    
    /* 分片信息 */
    frag_status_t frag_status;
    int is_fragmented;         /* 是否为分片包 */
} ipv4_info_t;

/**
 * @brief IPv6解析结果
 */
typedef struct {
    uint8_t  version;
    uint8_t  traffic_class;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t  next_header;      /* 最终的下一个头协议 */
    uint8_t  hop_limit;
    uint8_t  src_ip[IPV6_ADDR_LEN];
    uint8_t  dst_ip[IPV6_ADDR_LEN];
    const uint8_t *payload;    /* 载荷指针 (跳过扩展头) */
    uint16_t payload_len;      /* 载荷长度 */
    uint8_t  ext_headers_count;/* 扩展头数量 */
} ipv6_info_t;

/**
 * @brief ICMP解析结果
 */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t identifier;
    uint16_t sequence;
    const uint8_t *data;
    uint16_t data_len;
    checksum_result_t checksum_status;
} icmp_info_t;

/**
 * @brief ICMPv6解析结果
 */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t identifier;       /* Echo only */
    uint16_t sequence;         /* Echo only */
    uint32_t mtu;              /* Packet Too Big */
    const uint8_t *data;
    uint16_t data_len;
    checksum_result_t checksum_status;
} icmpv6_info_t;

/**
 * @brief TCP选项信息
 */
#define MAX_TCP_OPTIONS 10
#define MAX_SACK_BLOCKS 4

typedef struct {
    /* MSS选项 (Maximum Segment Size) */
    int has_mss;
    uint16_t mss;
    
    /* Window Scale选项 */
    int has_wscale;
    uint8_t wscale;
    
    /* SACK Permitted选项 */
    int has_sack_perm;
    
    /* SACK选项 */
    int has_sack;
    uint8_t sack_block_count;
    struct {
        uint32_t left_edge;
        uint32_t right_edge;
    } sack_blocks[MAX_SACK_BLOCKS];
    
    /* Timestamp选项 */
    int has_timestamp;
    uint32_t ts_val;       /* 发送方时间戳 */
    uint32_t ts_ecr;       /* 回显时间戳 */
    
    /* 选项总长度 */
    uint8_t options_len;
} tcp_options_t;

/**
 * @brief TCP解析结果
 */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    const uint8_t *payload;
    uint16_t payload_len;
    checksum_result_t checksum_status;
    
    /* TCP选项 */
    tcp_options_t options;
} tcp_info_t;

/**
 * @brief UDP解析结果
 */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    const uint8_t *payload;
    uint16_t payload_len;
    checksum_result_t checksum_status;
} udp_info_t;

/* ======================= 解析函数 ======================= */

/* 以太网 */
int parse_ethernet(const uint8_t *data, size_t len,
                   ethernet_header_t *eth_hdr,
                   const uint8_t **payload, size_t *payload_len);

/* VLAN */
int parse_vlan(const uint8_t *data, size_t len, vlan_info_t *info,
               const uint8_t **payload, size_t *payload_len);

/* 以太网 (含VLAN处理) */
int parse_ethernet_vlan(const uint8_t *data, size_t len,
                        ethernet_header_t *eth_hdr,
                        vlan_info_t *vlan_info, int *has_vlan,
                        const uint8_t **payload, size_t *payload_len);

/* ARP */
int parse_arp(const uint8_t *data, size_t len, arp_info_t *info);

/* IPv4 */
int parse_ipv4(const uint8_t *data, size_t len, ipv4_info_t *info);

/* IPv6 */
int parse_ipv6(const uint8_t *data, size_t len, ipv6_info_t *info);

/* ICMP */
int parse_icmp(const uint8_t *data, size_t len, icmp_info_t *info);

/* ICMPv6 */
int parse_icmpv6(const uint8_t *data, size_t len, icmpv6_info_t *info);
int parse_icmpv6_with_checksum(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                icmpv6_info_t *info);

/* TCP */
int parse_tcp(const uint8_t *data, size_t len, tcp_info_t *info);
int parse_tcp_with_checksum(const uint8_t *data, size_t len,
                            uint32_t src_ip, uint32_t dst_ip,
                            tcp_info_t *info);
int parse_tcp_with_checksum_v6(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                tcp_info_t *info);

/* TCP选项解析 */
int parse_tcp_options(const uint8_t *options, size_t len, tcp_options_t *opts);

/* UDP */
int parse_udp(const uint8_t *data, size_t len, udp_info_t *info);
int parse_udp_with_checksum(const uint8_t *data, size_t len,
                            uint32_t src_ip, uint32_t dst_ip,
                            udp_info_t *info);
int parse_udp_with_checksum_v6(const uint8_t *data, size_t len,
                                const uint8_t *src_ip, const uint8_t *dst_ip,
                                udp_info_t *info);

/* ======================= 打印函数 ======================= */

void print_mac_addr(const uint8_t *mac);
void print_ipv4_addr(uint32_t ip);
void print_ipv4_addr_array(const uint8_t *ip);
void print_ipv6_addr(const uint8_t *ip);

void print_ethernet_info(const ethernet_header_t *eth);
void print_vlan_info(const vlan_info_t *info);
void print_arp_info(const arp_info_t *info);
void print_ipv4_info(const ipv4_info_t *info);
void print_ipv6_info(const ipv6_info_t *info);
void print_icmp_info(const icmp_info_t *info);
void print_icmpv6_info(const icmpv6_info_t *info);
void print_tcp_info(const tcp_info_t *info);
void print_tcp_options(const tcp_options_t *opts);
void print_udp_info(const udp_info_t *info);

/* 辅助函数 */
const char* icmp_type_name(uint8_t type);
const char* icmpv6_type_name(uint8_t type);
void tcp_flags_to_string(uint8_t flags, char *buf, size_t buf_len);
const char* checksum_status_name(checksum_result_t status);
const char* ip_protocol_name(uint8_t proto);
const char* frag_status_name(frag_status_t status);
const char* vlan_priority_name(uint8_t pcp);

/* ======================= 统一解析入口 ======================= */

/**
 * @brief 解析完整数据包
 */
void parse_packet(const packet_info_t *pkt);

#endif /* PARSER_H */
