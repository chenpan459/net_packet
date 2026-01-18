/**
 * @file protocols.h
 * @brief 网络协议头结构定义
 * @description 定义以太网、ARP、IPv4、IPv6、ICMP、ICMPv6、TCP、UDP等协议头结构
 * @version 3.0 - 企业级版本，支持IPv6
 * 
 * 跨编译器兼容：支持 GCC、Clang、MSVC
 */

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdint.h>

/* ======================= 跨编译器 Pack 宏 ======================= */

#if defined(__GNUC__) || defined(__clang__)
    #define PACKED_STRUCT_BEGIN
    #define PACKED_STRUCT_END __attribute__((packed))
#elif defined(_MSC_VER)
    #define PACKED_STRUCT_BEGIN __pragma(pack(push, 1))
    #define PACKED_STRUCT_END __pragma(pack(pop))
#else
    #warning "Unknown compiler, struct packing may not work correctly"
    #define PACKED_STRUCT_BEGIN
    #define PACKED_STRUCT_END
#endif

/* ======================= 常量定义 ======================= */

/* 以太网类型 */
#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IPV6      0x86DD
#define ETHERTYPE_VLAN      0x8100

/* IP协议号 (IPv4 和 IPv6 共用) */
#define IP_PROTO_HOPOPT     0       /* IPv6 逐跳选项 */
#define IP_PROTO_ICMP       1
#define IP_PROTO_TCP        6
#define IP_PROTO_UDP        17
#define IP_PROTO_IPV6       41      /* IPv6 封装 */
#define IP_PROTO_ROUTING    43      /* IPv6 路由头 */
#define IP_PROTO_FRAGMENT   44      /* IPv6 分片头 */
#define IP_PROTO_ICMPV6     58      /* ICMPv6 */
#define IP_PROTO_NONE       59      /* IPv6 无下一头 */
#define IP_PROTO_DSTOPTS    60      /* IPv6 目的选项 */

/* ARP操作码 */
#define ARP_OP_REQUEST      1
#define ARP_OP_REPLY        2

/* ICMP类型 (IPv4) */
#define ICMP_TYPE_ECHO_REPLY    0
#define ICMP_TYPE_DEST_UNREACH  3
#define ICMP_TYPE_ECHO_REQUEST  8
#define ICMP_TYPE_TIME_EXCEEDED 11

/* ICMPv6类型 */
#define ICMPV6_TYPE_DEST_UNREACH    1
#define ICMPV6_TYPE_PKT_TOO_BIG     2
#define ICMPV6_TYPE_TIME_EXCEEDED   3
#define ICMPV6_TYPE_PARAM_PROBLEM   4
#define ICMPV6_TYPE_ECHO_REQUEST    128
#define ICMPV6_TYPE_ECHO_REPLY      129
#define ICMPV6_TYPE_ROUTER_SOL      133
#define ICMPV6_TYPE_ROUTER_ADV      134
#define ICMPV6_TYPE_NEIGHBOR_SOL    135
#define ICMPV6_TYPE_NEIGHBOR_ADV    136

/* 长度定义 */
#define ETH_ADDR_LEN        6
#define IPV4_ADDR_LEN       4
#define IPV6_ADDR_LEN       16
#define ETH_HDR_LEN         14
#define ARP_HDR_LEN         28
#define IPV4_HDR_MIN_LEN    20
#define IPV6_HDR_LEN        40
#define ICMP_HDR_LEN        8
#define ICMPV6_HDR_LEN      8
#define TCP_HDR_MIN_LEN     20
#define UDP_HDR_LEN         8

/* ======================= 结构体定义 ======================= */

/**
 * @brief 以太网帧头 (14字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  dst_mac[ETH_ADDR_LEN];   /* 目的MAC地址 */
    uint8_t  src_mac[ETH_ADDR_LEN];   /* 源MAC地址 */
    uint16_t ether_type;               /* 以太网类型 */
} PACKED_STRUCT_END ethernet_header_t;

/**
 * @brief 802.1Q VLAN标签 (4字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint16_t tpid;                     /* 标签协议标识符 (0x8100) */
    uint16_t tci;                      /* 标签控制信息: PCP(3) + DEI(1) + VID(12) */
} PACKED_STRUCT_END vlan_tag_t;

/* VLAN TCI 字段提取宏 */
#define VLAN_PCP(tci) (((tci) >> 13) & 0x07)    /* 优先级代码点 */
#define VLAN_DEI(tci) (((tci) >> 12) & 0x01)    /* 丢弃合格指示 */
#define VLAN_VID(tci) ((tci) & 0x0FFF)          /* VLAN标识符 */

/**
 * @brief ARP报文头 (28字节 for IPv4/Ethernet)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint16_t hw_type;                  /* 硬件类型 (1=Ethernet) */
    uint16_t proto_type;               /* 协议类型 (0x0800=IPv4) */
    uint8_t  hw_addr_len;              /* 硬件地址长度 */
    uint8_t  proto_addr_len;           /* 协议地址长度 */
    uint16_t opcode;                   /* 操作码 */
    uint8_t  sender_mac[ETH_ADDR_LEN]; /* 发送方MAC */
    uint8_t  sender_ip[IPV4_ADDR_LEN]; /* 发送方IP */
    uint8_t  target_mac[ETH_ADDR_LEN]; /* 目标MAC */
    uint8_t  target_ip[IPV4_ADDR_LEN]; /* 目标IP */
} PACKED_STRUCT_END arp_header_t;

/**
 * @brief IPv4报文头 (20-60字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  version_ihl;              /* 版本(4bit) + 首部长度(4bit) */
    uint8_t  tos;                      /* 服务类型 */
    uint16_t total_length;             /* 总长度 */
    uint16_t identification;           /* 标识 */
    uint16_t flags_fragment;           /* 标志(3bit) + 片偏移(13bit) */
    uint8_t  ttl;                      /* 生存时间 */
    uint8_t  protocol;                 /* 协议 */
    uint16_t checksum;                 /* 首部校验和 */
    uint32_t src_ip;                   /* 源IP地址 */
    uint32_t dst_ip;                   /* 目的IP地址 */
} PACKED_STRUCT_END ipv4_header_t;

/**
 * @brief IPv6报文头 (40字节，固定长度)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint32_t version_tc_fl;            /* 版本(4) + 流量类(8) + 流标签(20) */
    uint16_t payload_length;           /* 载荷长度 */
    uint8_t  next_header;              /* 下一个头 */
    uint8_t  hop_limit;                /* 跳数限制 */
    uint8_t  src_ip[IPV6_ADDR_LEN];    /* 源IPv6地址 */
    uint8_t  dst_ip[IPV6_ADDR_LEN];    /* 目的IPv6地址 */
} PACKED_STRUCT_END ipv6_header_t;

/**
 * @brief IPv6扩展头通用格式
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  next_header;              /* 下一个头 */
    uint8_t  hdr_ext_len;              /* 扩展头长度(8字节为单位,不含前8字节) */
} PACKED_STRUCT_END ipv6_ext_header_t;

/**
 * @brief IPv6分片头 (8字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  next_header;              /* 下一个头 */
    uint8_t  reserved;                 /* 保留 */
    uint16_t frag_offset_flags;        /* 片偏移(13bit) + 保留(2bit) + M标志(1bit) */
    uint32_t identification;           /* 标识 */
} PACKED_STRUCT_END ipv6_frag_header_t;

/**
 * @brief ICMP报文头 (8字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  type;                     /* 类型 */
    uint8_t  code;                     /* 代码 */
    uint16_t checksum;                 /* 校验和 */
    uint16_t identifier;               /* 标识符 */
    uint16_t sequence;                 /* 序列号 */
} PACKED_STRUCT_END icmp_header_t;

/**
 * @brief ICMPv6报文头 (8字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  type;                     /* 类型 */
    uint8_t  code;                     /* 代码 */
    uint16_t checksum;                 /* 校验和 */
    union {
        struct {
            uint16_t identifier;       /* Echo 标识符 */
            uint16_t sequence;         /* Echo 序列号 */
        } echo;
        uint32_t mtu;                  /* Packet Too Big MTU */
        uint32_t pointer;              /* Parameter Problem 指针 */
        uint32_t reserved;             /* 其他类型保留字段 */
    } data;
} PACKED_STRUCT_END icmpv6_header_t;

/**
 * @brief TCP报文头 (20-60字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint16_t src_port;                 /* 源端口 */
    uint16_t dst_port;                 /* 目的端口 */
    uint32_t seq_num;                  /* 序列号 */
    uint32_t ack_num;                  /* 确认号 */
    uint8_t  data_offset;              /* 数据偏移(4bit) + 保留(4bit) */
    uint8_t  flags;                    /* 标志位 */
    uint16_t window;                   /* 窗口大小 */
    uint16_t checksum;                 /* 校验和 */
    uint16_t urgent_ptr;               /* 紧急指针 */
} PACKED_STRUCT_END tcp_header_t;

/**
 * @brief UDP报文头 (8字节)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint16_t src_port;                 /* 源端口 */
    uint16_t dst_port;                 /* 目的端口 */
    uint16_t length;                   /* UDP长度 (头+数据) */
    uint16_t checksum;                 /* 校验和 */
} PACKED_STRUCT_END udp_header_t;

/**
 * @brief IPv4伪首部 (用于TCP/UDP校验和计算)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t length;
} PACKED_STRUCT_END pseudo_header_t;

/**
 * @brief IPv6伪首部 (用于TCP/UDP/ICMPv6校验和计算)
 */
PACKED_STRUCT_BEGIN
typedef struct {
    uint8_t  src_ip[IPV6_ADDR_LEN];
    uint8_t  dst_ip[IPV6_ADDR_LEN];
    uint32_t length;
    uint8_t  zero[3];
    uint8_t  next_header;
} PACKED_STRUCT_END pseudo_header_v6_t;

/* TCP标志位 */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

/* TCP选项类型 */
#define TCP_OPT_END         0   /* 选项结束 */
#define TCP_OPT_NOP         1   /* 无操作 (填充) */
#define TCP_OPT_MSS         2   /* 最大报文段大小 (4字节) */
#define TCP_OPT_WSCALE      3   /* 窗口缩放因子 (3字节) */
#define TCP_OPT_SACK_PERM   4   /* SACK允许 (2字节) */
#define TCP_OPT_SACK        5   /* SACK数据块 (可变长) */
#define TCP_OPT_TIMESTAMP   8   /* 时间戳 (10字节) */

/* VLAN长度 */
#define VLAN_TAG_LEN        4

/* IPv4分片标志 */
#define IPV4_FLAG_RESERVED  0x04  /* 保留位 */
#define IPV4_FLAG_DF        0x02  /* 禁止分片 */
#define IPV4_FLAG_MF        0x01  /* 更多分片 */

/* ======================= 辅助宏 ======================= */

/* 获取IPv4首部长度 (字节) */
#define IPV4_HDR_LEN(hdr) (((hdr)->version_ihl & 0x0F) * 4)

/* 获取IPv4版本号 */
#define IPV4_VERSION(hdr) (((hdr)->version_ihl >> 4) & 0x0F)

/* 获取TCP数据偏移 (字节) */
#define TCP_DATA_OFFSET(hdr) ((((hdr)->data_offset >> 4) & 0x0F) * 4)

/* 
 * 内部字节序转换函数 (仅供本头文件中的宏使用)
 * 
 * 注意: 应用代码请使用 utils.h 中的 net_to_host16/net_to_host32
 * 此函数仅用于避免头文件循环依赖，不应在外部直接调用
 */
#ifndef _PROTO_BYTE_SWAP_INTERNAL
#define _PROTO_BYTE_SWAP_INTERNAL
static inline uint16_t _proto_ntohs_internal(uint16_t net) {
    return ((net >> 8) & 0xFF) | ((net << 8) & 0xFF00);
}
static inline uint32_t _proto_ntohl_internal(uint32_t net) {
    return ((net >> 24) & 0x000000FF) |
           ((net >> 8)  & 0x0000FF00) |
           ((net << 8)  & 0x00FF0000) |
           ((net << 24) & 0xFF000000);
}
#endif

/* 获取IP分片标志 */
#define IPV4_FLAGS(hdr) ((_proto_ntohs_internal((hdr)->flags_fragment) >> 13) & 0x07)
#define IPV4_FRAG_OFFSET(hdr) (_proto_ntohs_internal((hdr)->flags_fragment) & 0x1FFF)

/* IPv6相关宏 */
#define IPV6_VERSION(hdr) ((_proto_ntohl_internal((hdr)->version_tc_fl) >> 28) & 0x0F)
#define IPV6_TRAFFIC_CLASS(hdr) ((_proto_ntohl_internal((hdr)->version_tc_fl) >> 20) & 0xFF)
#define IPV6_FLOW_LABEL(hdr) (_proto_ntohl_internal((hdr)->version_tc_fl) & 0xFFFFF)

#endif /* PROTOCOLS_H */
