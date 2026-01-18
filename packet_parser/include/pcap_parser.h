/**
 * @file pcap_parser.h
 * @brief PCAP/PCAPNG文件解析模块
 * @description 支持标准PCAP和PCAPNG格式，流式解析大文件
 * @version 3.2 - 支持PCAPNG格式
 */

#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include <stdint.h>
#include <stdio.h>

/* PCAP魔数 */
#define PCAP_MAGIC_NATIVE       0xA1B2C3D4  /* 小端序 */
#define PCAP_MAGIC_SWAPPED      0xD4C3B2A1  /* 大端序 */
#define PCAP_MAGIC_NSEC         0xA1B23C4D  /* 纳秒精度 */
#define PCAP_MAGIC_NSEC_SWAPPED 0x4D3CB2A1  /* 纳秒精度大端 */

/* PCAPNG魔数和块类型 */
#define PCAPNG_MAGIC            0x0A0D0D0A  /* Section Header Block */
#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D  /* 字节序标识 */
#define PCAPNG_BT_SHB           0x0A0D0D0A  /* Section Header Block */
#define PCAPNG_BT_IDB           0x00000001  /* Interface Description Block */
#define PCAPNG_BT_EPB           0x00000006  /* Enhanced Packet Block */
#define PCAPNG_BT_SPB           0x00000003  /* Simple Packet Block */
#define PCAPNG_BT_PB            0x00000002  /* Packet Block (obsolete) */
#define PCAPNG_BT_NRB           0x00000004  /* Name Resolution Block */
#define PCAPNG_BT_ISB           0x00000005  /* Interface Statistics Block */

/* 文件格式类型 */
typedef enum {
    FILE_FORMAT_UNKNOWN = 0,
    FILE_FORMAT_PCAP,           /* 经典PCAP格式 */
    FILE_FORMAT_PCAPNG          /* PCAPNG格式 */
} file_format_t;

/* 解析模式 */
typedef enum {
    PCAP_MODE_MEMORY = 0,       /* 内存模式：小文件整体加载 */
    PCAP_MODE_STREAM = 1        /* 流式模式：大文件逐包读取 */
} pcap_mode_t;

/* 内存模式最大文件大小 (50KB) */
#define PCAP_MEMORY_MAX_SIZE    (50 * 1024)

/* 流式模式缓冲区大小 */
#define PCAP_STREAM_BUFFER_SIZE (64 * 1024)

/* 最大单包大小 */
#define PCAP_MAX_PACKET_SIZE    65535

/* 链路类型 */
#define LINKTYPE_NULL           0
#define LINKTYPE_ETHERNET       1
#define LINKTYPE_RAW            12
#define LINKTYPE_LINUX_SLL      113

/* 跨编译器 Pack 宏 */
#if defined(__GNUC__) || defined(__clang__)
    #define PCAP_PACKED __attribute__((packed))
#elif defined(_MSC_VER)
    #define PCAP_PACKED
    #pragma pack(push, 1)
#else
    #define PCAP_PACKED
#endif

/**
 * @brief PCAP文件头 (24字节)
 */
typedef struct PCAP_PACKED {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

/**
 * @brief PCAP数据包头 (16字节)
 */
typedef struct PCAP_PACKED {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
} pcap_packet_header_t;

/**
 * @brief PCAPNG通用块头
 */
typedef struct PCAP_PACKED {
    uint32_t block_type;
    uint32_t block_total_length;
} pcapng_block_header_t;

/**
 * @brief PCAPNG Section Header Block (SHB)
 */
typedef struct PCAP_PACKED {
    uint32_t block_type;        /* 0x0A0D0D0A */
    uint32_t block_total_length;
    uint32_t byte_order_magic;  /* 0x1A2B3C4D */
    uint16_t major_version;
    uint16_t minor_version;
    int64_t  section_length;    /* -1 = 未知 */
    /* 后面跟着选项和结束块长度 */
} pcapng_shb_t;

/**
 * @brief PCAPNG Interface Description Block (IDB)
 */
typedef struct PCAP_PACKED {
    uint32_t block_type;        /* 0x00000001 */
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
    /* 后面跟着选项和结束块长度 */
} pcapng_idb_t;

/**
 * @brief PCAPNG Enhanced Packet Block (EPB)
 */
typedef struct PCAP_PACKED {
    uint32_t block_type;        /* 0x00000006 */
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    /* 后面跟着数据包数据、选项和结束块长度 */
} pcapng_epb_t;

#ifdef _MSC_VER
    #pragma pack(pop)
#endif

/**
 * @brief 数据包信息结构
 */
typedef struct {
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t captured_len;
    uint32_t original_len;
    const uint8_t *data;
    uint32_t packet_number;     /* 数据包序号 */
} packet_info_t;

/**
 * @brief PCAPNG接口信息
 */
#define PCAPNG_MAX_INTERFACES 16
typedef struct {
    uint16_t link_type;
    uint32_t snaplen;
    uint8_t  ts_resol;          /* 时间戳分辨率 (默认6=微秒) */
} pcapng_interface_t;

/**
 * @brief PCAP解析上下文
 */
typedef struct {
    /* 通用字段 */
    pcap_mode_t mode;           /* 解析模式 */
    file_format_t format;       /* 文件格式 (PCAP/PCAPNG) */
    uint32_t link_type;         /* 链路类型 */
    int byte_swap;              /* 是否需要字节序转换 */
    int nsec_precision;         /* 是否为纳秒精度 */
    uint32_t packet_count;      /* 已解析数据包数量 */
    uint64_t total_bytes;       /* 已处理的总字节数 */
    
    /* 内存模式字段 */
    uint8_t *buffer;            /* 文件缓冲区 */
    size_t buffer_size;         /* 缓冲区大小 */
    size_t current_offset;      /* 当前解析偏移 */
    
    /* 流式模式字段 */
    FILE *fp;                   /* 文件指针 */
    uint8_t *stream_buffer;     /* 流式读取缓冲区 */
    size_t stream_buffer_size;  /* 流式缓冲区大小 */
    uint64_t file_size;         /* 文件总大小 */
    uint64_t file_offset;       /* 当前文件偏移 */
    
    /* PCAPNG专用字段 */
    pcapng_interface_t interfaces[PCAPNG_MAX_INTERFACES];
    uint32_t interface_count;   /* 接口数量 */
} pcap_context_t;

/**
 * @brief PCAP解析统计
 */
typedef struct {
    uint64_t file_size;
    uint32_t total_packets;
    uint64_t total_bytes;
    double parse_time_ms;
    double packets_per_sec;
    double mbps;
} pcap_stats_t;

/* ======================= API函数 ======================= */

/**
 * @brief 打开PCAP文件 (自动选择模式)
 * @param filename 文件路径
 * @param ctx 解析上下文 (输出)
 * @return 0成功, -1失败
 */
int pcap_open(const char *filename, pcap_context_t *ctx);

/**
 * @brief 以指定模式打开PCAP文件
 * @param filename 文件路径
 * @param ctx 解析上下文 (输出)
 * @param mode 解析模式
 * @return 0成功, -1失败
 */
int pcap_open_ex(const char *filename, pcap_context_t *ctx, pcap_mode_t mode);

/**
 * @brief 读取下一个数据包
 * @param ctx 解析上下文
 * @param pkt 数据包信息 (输出)
 * @return 1成功, 0无更多数据包, -1错误
 */
int pcap_read_packet(pcap_context_t *ctx, packet_info_t *pkt);

/**
 * @brief 关闭并释放资源
 * @param ctx 解析上下文
 */
void pcap_close(pcap_context_t *ctx);

/**
 * @brief 重置到文件开头
 * @param ctx 解析上下文
 * @return 0成功, -1失败
 */
int pcap_reset(pcap_context_t *ctx);

/**
 * @brief 获取解析统计
 * @param ctx 解析上下文
 * @param stats 统计信息 (输出)
 */
void pcap_get_stats(const pcap_context_t *ctx, pcap_stats_t *stats);

/**
 * @brief 获取链路类型描述
 */
const char* pcap_linktype_name(uint32_t link_type);

/**
 * @brief 获取解析进度 (0-100)
 */
int pcap_get_progress(const pcap_context_t *ctx);

/**
 * @brief 获取文件格式名称
 */
const char* pcap_format_name(file_format_t format);

/**
 * @brief 检测文件格式
 */
file_format_t pcap_detect_format(const char *filename);

#endif /* PCAP_PARSER_H */
