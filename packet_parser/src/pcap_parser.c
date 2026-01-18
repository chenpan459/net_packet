/**
 * @file pcap_parser.c
 * @brief PCAP/PCAPNG文件解析实现 (支持流式解析)
 * @version 3.2 - 支持PCAPNG格式
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/pcap_parser.h"
#include "../include/utils.h"
#include "../include/log.h"

/* ======================= 工具函数 ======================= */

/**
 * @brief 获取文件大小
 */
static uint64_t get_file_size(FILE *fp) {
    uint64_t size;
    long current = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size = (uint64_t)ftell(fp);
    fseek(fp, current, SEEK_SET);
    return size;
}

/**
 * @brief 获取文件格式名称
 */
const char* pcap_format_name(file_format_t format) {
    switch (format) {
        case FILE_FORMAT_PCAP:   return "PCAP";
        case FILE_FORMAT_PCAPNG: return "PCAPNG";
        default:                 return "Unknown";
    }
}

/**
 * @brief 检测文件格式
 */
file_format_t pcap_detect_format(const char *filename) {
    FILE *fp;
    uint32_t magic;
    file_format_t format = FILE_FORMAT_UNKNOWN;
    
    fp = fopen(filename, "rb");
    if (!fp) {
        LOG_ERROR("Cannot open file for format detection: %s", filename);
        return FILE_FORMAT_UNKNOWN;
    }
    
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        LOG_ERROR("Failed to read magic number from: %s", filename);
        fclose(fp);
        return FILE_FORMAT_UNKNOWN;
    }
    
    fclose(fp);
    
    switch (magic) {
        case PCAP_MAGIC_NATIVE:
        case PCAP_MAGIC_SWAPPED:
        case PCAP_MAGIC_NSEC:
        case PCAP_MAGIC_NSEC_SWAPPED:
            format = FILE_FORMAT_PCAP;
            LOG_DEBUG("Detected PCAP format (magic=0x%08X)", magic);
            break;
        case PCAPNG_MAGIC:
            format = FILE_FORMAT_PCAPNG;
            LOG_DEBUG("Detected PCAPNG format (magic=0x%08X)", magic);
            break;
        default:
            LOG_ERROR("Unknown file format, magic=0x%08X", magic);
            break;
    }
    
    return format;
}

/* ======================= PCAP 解析 ======================= */

/**
 * @brief 解析PCAP文件头
 */
static int parse_pcap_header(pcap_context_t *ctx, const uint8_t *header_data) {
    pcap_file_header_t *hdr = (pcap_file_header_t *)header_data;
    
    /* 检查魔数并确定字节序和精度 */
    switch (hdr->magic_number) {
        case PCAP_MAGIC_NATIVE:
            ctx->byte_swap = 0;
            ctx->nsec_precision = 0;
            break;
        case PCAP_MAGIC_SWAPPED:
            ctx->byte_swap = 1;
            ctx->nsec_precision = 0;
            break;
        case PCAP_MAGIC_NSEC:
            ctx->byte_swap = 0;
            ctx->nsec_precision = 1;
            break;
        case PCAP_MAGIC_NSEC_SWAPPED:
            ctx->byte_swap = 1;
            ctx->nsec_precision = 1;
            break;
        default:
            LOG_ERROR("Invalid PCAP magic: 0x%08X (expected 0x%08X or 0x%08X)", 
                      hdr->magic_number, PCAP_MAGIC_NATIVE, PCAP_MAGIC_SWAPPED);
            return -1;
    }
    
    ctx->link_type = ctx->byte_swap ? 
                     net_to_host32(hdr->network) : hdr->network;
    ctx->format = FILE_FORMAT_PCAP;
    
    uint16_t ver_major = ctx->byte_swap ? net_to_host16(hdr->version_major) : hdr->version_major;
    uint16_t ver_minor = ctx->byte_swap ? net_to_host16(hdr->version_minor) : hdr->version_minor;
    
    LOG_INFO("PCAP: version=%u.%u, linktype=%s(%u), precision=%s",
             ver_major, ver_minor,
             pcap_linktype_name(ctx->link_type), ctx->link_type,
             ctx->nsec_precision ? "nanosecond" : "microsecond");
    
    return 0;
}

/* ======================= PCAPNG 解析 ======================= */

/**
 * @brief 解析PCAPNG Section Header Block
 */
static int parse_pcapng_shb(pcap_context_t *ctx, const uint8_t *data, size_t len) {
    if (len < sizeof(pcapng_shb_t)) {
        LOG_ERROR("PCAPNG SHB too short: %zu bytes (need %zu)", len, sizeof(pcapng_shb_t));
        return -1;
    }
    
    pcapng_shb_t *shb = (pcapng_shb_t *)data;
    
    /* 检查字节序魔数 */
    if (shb->byte_order_magic == PCAPNG_BYTE_ORDER_MAGIC) {
        ctx->byte_swap = 0;
    } else if (shb->byte_order_magic == net_to_host32(PCAPNG_BYTE_ORDER_MAGIC)) {
        ctx->byte_swap = 1;
    } else {
        LOG_ERROR("Invalid PCAPNG byte order magic: 0x%08X", shb->byte_order_magic);
        return -1;
    }
    
    uint16_t major = ctx->byte_swap ? net_to_host16(shb->major_version) : shb->major_version;
    uint16_t minor = ctx->byte_swap ? net_to_host16(shb->minor_version) : shb->minor_version;
    
    LOG_INFO("PCAPNG: version=%u.%u, byte_swap=%d", major, minor, ctx->byte_swap);
    
    ctx->format = FILE_FORMAT_PCAPNG;
    ctx->interface_count = 0;
    
    return 0;
}

/**
 * @brief 解析PCAPNG Interface Description Block
 */
static int parse_pcapng_idb(pcap_context_t *ctx, const uint8_t *data, size_t len) {
    if (len < sizeof(pcapng_idb_t)) {
        LOG_ERROR("PCAPNG IDB too short: %zu bytes", len);
        return -1;
    }
    
    if (ctx->interface_count >= PCAPNG_MAX_INTERFACES) {
        LOG_WARN("Too many interfaces in PCAPNG file, max=%d", PCAPNG_MAX_INTERFACES);
        return 0;
    }
    
    pcapng_idb_t *idb = (pcapng_idb_t *)data;
    pcapng_interface_t *iface = &ctx->interfaces[ctx->interface_count];
    
    iface->link_type = ctx->byte_swap ? net_to_host16(idb->link_type) : idb->link_type;
    iface->snaplen = ctx->byte_swap ? net_to_host32(idb->snaplen) : idb->snaplen;
    iface->ts_resol = 6;  /* 默认微秒 */
    
    /* 解析选项获取时间戳分辨率 */
    size_t opt_offset = sizeof(pcapng_idb_t);
    uint32_t block_len = ctx->byte_swap ? net_to_host32(idb->block_total_length) : idb->block_total_length;
    
    while (opt_offset + 4 <= block_len - 4) {  /* -4 for trailing length */
        uint16_t opt_code = *(uint16_t *)(data + opt_offset);
        uint16_t opt_len = *(uint16_t *)(data + opt_offset + 2);
        
        if (ctx->byte_swap) {
            opt_code = net_to_host16(opt_code);
            opt_len = net_to_host16(opt_len);
        }
        
        if (opt_code == 0) break;  /* opt_endofopt */
        
        if (opt_code == 9 && opt_len == 1) {  /* if_tsresol */
            iface->ts_resol = data[opt_offset + 4];
        }
        
        opt_offset += 4 + ((opt_len + 3) & ~3);  /* 4字节对齐 */
    }
    
    /* 设置默认链路类型 (使用第一个接口的) */
    if (ctx->interface_count == 0) {
        ctx->link_type = iface->link_type;
        ctx->nsec_precision = (iface->ts_resol == 9);  /* 9 = 纳秒 */
    }
    
    LOG_DEBUG("PCAPNG IDB[%u]: linktype=%s(%u), snaplen=%u, ts_resol=%u",
              ctx->interface_count, pcap_linktype_name(iface->link_type),
              iface->link_type, iface->snaplen, iface->ts_resol);
    
    ctx->interface_count++;
    return 0;
}

/**
 * @brief 从PCAPNG Enhanced Packet Block提取数据包
 */
static int parse_pcapng_epb(pcap_context_t *ctx, const uint8_t *data, 
                            size_t len, packet_info_t *pkt) {
    if (len < sizeof(pcapng_epb_t)) {
        LOG_ERROR("PCAPNG EPB too short: %zu bytes", len);
        return -1;
    }
    
    pcapng_epb_t *epb = (pcapng_epb_t *)data;
    
    uint32_t iface_id = ctx->byte_swap ? net_to_host32(epb->interface_id) : epb->interface_id;
    uint32_t ts_high = ctx->byte_swap ? net_to_host32(epb->timestamp_high) : epb->timestamp_high;
    uint32_t ts_low = ctx->byte_swap ? net_to_host32(epb->timestamp_low) : epb->timestamp_low;
    uint32_t caplen = ctx->byte_swap ? net_to_host32(epb->captured_len) : epb->captured_len;
    uint32_t origlen = ctx->byte_swap ? net_to_host32(epb->original_len) : epb->original_len;
    
    if (iface_id >= ctx->interface_count) {
        LOG_WARN("Invalid interface ID in EPB: %u (max=%u)", iface_id, ctx->interface_count - 1);
        iface_id = 0;
    }
    
    /* 计算时间戳 */
    uint64_t timestamp = ((uint64_t)ts_high << 32) | ts_low;
    uint8_t ts_resol = ctx->interfaces[iface_id].ts_resol;
    
    if (ts_resol == 6) {
        /* 微秒 */
        pkt->timestamp_sec = (uint32_t)(timestamp / 1000000);
        pkt->timestamp_usec = (uint32_t)(timestamp % 1000000);
    } else if (ts_resol == 9) {
        /* 纳秒 */
        pkt->timestamp_sec = (uint32_t)(timestamp / 1000000000);
        pkt->timestamp_usec = (uint32_t)((timestamp % 1000000000) / 1000);
    } else {
        /* 其他分辨率 */
        pkt->timestamp_sec = (uint32_t)(timestamp >> 32);
        pkt->timestamp_usec = (uint32_t)(timestamp & 0xFFFFFFFF);
    }
    
    pkt->captured_len = caplen;
    pkt->original_len = origlen;
    pkt->data = data + sizeof(pcapng_epb_t);
    pkt->packet_number = ctx->packet_count + 1;
    
    /* 验证数据长度 */
    if (sizeof(pcapng_epb_t) + caplen > len) {
        LOG_ERROR("PCAPNG EPB data exceeds block: caplen=%u, available=%zu",
                  caplen, len - sizeof(pcapng_epb_t));
        return -1;
    }
    
    return 0;
}

/* ======================= 流式读取 ======================= */

/**
 * @brief 从流读取PCAPNG块
 */
static int pcapng_read_block_stream(pcap_context_t *ctx, uint32_t *block_type, 
                                    uint32_t *block_len) {
    pcapng_block_header_t hdr;
    
    if (fread(&hdr, 1, sizeof(hdr), ctx->fp) != sizeof(hdr)) {
        if (feof(ctx->fp)) return 0;
        LOG_ERROR("Failed to read PCAPNG block header at offset %lu", 
                  (unsigned long)ctx->file_offset);
        return -1;
    }
    
    *block_type = ctx->byte_swap ? net_to_host32(hdr.block_type) : hdr.block_type;
    *block_len = ctx->byte_swap ? net_to_host32(hdr.block_total_length) : hdr.block_total_length;
    
    if (*block_len < 12 || *block_len > PCAP_MAX_PACKET_SIZE + 100) {
        LOG_ERROR("Invalid PCAPNG block length: %u at offset %lu", 
                  *block_len, (unsigned long)ctx->file_offset);
        return -1;
    }
    
    return 1;
}

/**
 * @brief 读取PCAPNG数据包 (流式)
 */
static int pcap_read_packet_pcapng_stream(pcap_context_t *ctx, packet_info_t *pkt) {
    uint32_t block_type, block_len;
    int ret;
    
    while ((ret = pcapng_read_block_stream(ctx, &block_type, &block_len)) > 0) {
        /* 读取完整块到缓冲区 */
        if (block_len > ctx->stream_buffer_size) {
            LOG_ERROR("PCAPNG block too large: %u > %zu", block_len, ctx->stream_buffer_size);
            return -1;
        }
        
        /* 回退已读取的头部 */
        fseek(ctx->fp, -(long)sizeof(pcapng_block_header_t), SEEK_CUR);
        
        if (fread(ctx->stream_buffer, 1, block_len, ctx->fp) != block_len) {
            LOG_ERROR("Failed to read PCAPNG block data");
            return -1;
        }
        
        ctx->file_offset += block_len;
        
        switch (block_type) {
            case PCAPNG_BT_SHB:
                if (parse_pcapng_shb(ctx, ctx->stream_buffer, block_len) != 0) {
                    return -1;
                }
                break;
                
            case PCAPNG_BT_IDB:
                if (parse_pcapng_idb(ctx, ctx->stream_buffer, block_len) != 0) {
                    return -1;
                }
                break;
                
            case PCAPNG_BT_EPB:
                if (parse_pcapng_epb(ctx, ctx->stream_buffer, block_len, pkt) == 0) {
                    ctx->packet_count++;
                    ctx->total_bytes += pkt->captured_len;
                    return 1;
                }
                break;
                
            case PCAPNG_BT_SPB:
                /* Simple Packet Block - 简化处理 */
                LOG_DEBUG("Skipping Simple Packet Block");
                break;
                
            default:
                LOG_DEBUG("Skipping PCAPNG block type: 0x%08X", block_type);
                break;
        }
    }
    
    return ret;
}

/* ======================= 内存模式 ======================= */

/**
 * @brief 以内存模式打开
 */
static int pcap_open_memory(const char *filename, pcap_context_t *ctx) {
    FILE *fp = NULL;
    long file_size = 0;
    
    fp = fopen(filename, "rb");
    if (!fp) {
        LOG_ERROR("Cannot open file: %s (check path and permissions)", filename);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < (long)sizeof(pcap_file_header_t)) {
        LOG_ERROR("File too small for PCAP header: %ld bytes (need at least %zu)",
                  file_size, sizeof(pcap_file_header_t));
        fclose(fp);
        return -1;
    }
    
    ctx->buffer = (uint8_t *)malloc(file_size);
    if (!ctx->buffer) {
        LOG_ERROR("Memory allocation failed: requested %ld bytes", file_size);
        fclose(fp);
        return -1;
    }
    
    if (fread(ctx->buffer, 1, file_size, fp) != (size_t)file_size) {
        LOG_ERROR("Failed to read file: %s (I/O error)", filename);
        free(ctx->buffer);
        ctx->buffer = NULL;
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    
    ctx->buffer_size = file_size;
    ctx->current_offset = sizeof(pcap_file_header_t);
    ctx->mode = PCAP_MODE_MEMORY;
    ctx->file_size = file_size;
    
    /* 检测格式 */
    uint32_t magic = *(uint32_t *)ctx->buffer;
    if (magic == PCAPNG_MAGIC) {
        /* PCAPNG 内存模式 */
        ctx->current_offset = 0;
        return 0;  /* 稍后解析块 */
    }
    
    return parse_pcap_header(ctx, ctx->buffer);
}

/**
 * @brief 以流式模式打开
 */
static int pcap_open_stream(const char *filename, pcap_context_t *ctx) {
    uint8_t header[sizeof(pcap_file_header_t)];
    uint32_t magic;
    
    ctx->fp = fopen(filename, "rb");
    if (!ctx->fp) {
        LOG_ERROR("Cannot open file: %s (check path and permissions)", filename);
        return -1;
    }
    
    ctx->file_size = get_file_size(ctx->fp);
    
    /* 先读取魔数判断格式 */
    if (fread(&magic, 1, sizeof(magic), ctx->fp) != sizeof(magic)) {
        LOG_ERROR("Failed to read file magic number: %s", filename);
        fclose(ctx->fp);
        ctx->fp = NULL;
        return -1;
    }
    
    fseek(ctx->fp, 0, SEEK_SET);
    
    /* 分配流式缓冲区 */
    ctx->stream_buffer_size = PCAP_MAX_PACKET_SIZE + 256;
    ctx->stream_buffer = (uint8_t *)malloc(ctx->stream_buffer_size);
    if (!ctx->stream_buffer) {
        LOG_ERROR("Failed to allocate stream buffer: %zu bytes", ctx->stream_buffer_size);
        fclose(ctx->fp);
        ctx->fp = NULL;
        return -1;
    }
    
    ctx->mode = PCAP_MODE_STREAM;
    
    if (magic == PCAPNG_MAGIC) {
        /* PCAPNG格式 - 需要先解析SHB和IDB */
        ctx->format = FILE_FORMAT_PCAPNG;
        ctx->file_offset = 0;
        LOG_INFO("PCAPNG opened in stream mode, file size: %lu bytes",
                 (unsigned long)ctx->file_size);
        return 0;
    }
    
    /* PCAP格式 */
    if (fread(header, 1, sizeof(header), ctx->fp) != sizeof(header)) {
        LOG_ERROR("Failed to read PCAP header: %s", filename);
        free(ctx->stream_buffer);
        ctx->stream_buffer = NULL;
        fclose(ctx->fp);
        ctx->fp = NULL;
        return -1;
    }
    
    if (parse_pcap_header(ctx, header) != 0) {
        free(ctx->stream_buffer);
        ctx->stream_buffer = NULL;
        fclose(ctx->fp);
        ctx->fp = NULL;
        return -1;
    }
    
    ctx->file_offset = sizeof(pcap_file_header_t);
    
    LOG_INFO("PCAP opened in stream mode, file size: %lu bytes", 
             (unsigned long)ctx->file_size);
    
    return 0;
}

/**
 * @brief 打开PCAP/PCAPNG文件 (自动选择模式)
 */
int pcap_open(const char *filename, pcap_context_t *ctx) {
    FILE *fp;
    uint64_t file_size;
    pcap_mode_t mode;
    
    if (!filename || !ctx) {
        LOG_ERROR("Invalid parameters: filename=%p, ctx=%p", (void*)filename, (void*)ctx);
        return -1;
    }
    
    memset(ctx, 0, sizeof(pcap_context_t));
    
    /* 检查文件大小决定模式 */
    fp = fopen(filename, "rb");
    if (!fp) {
        LOG_ERROR("Cannot open file: %s (check path and permissions)", filename);
        return -1;
    }
    
    file_size = get_file_size(fp);
    fclose(fp);
    
    /* 小文件用内存模式，大文件用流式模式 */
    if (file_size <= PCAP_MEMORY_MAX_SIZE) {
        mode = PCAP_MODE_MEMORY;
        LOG_INFO("Using memory mode for %lu bytes file", (unsigned long)file_size);
    } else {
        mode = PCAP_MODE_STREAM;
        LOG_INFO("Using stream mode for %lu bytes file", (unsigned long)file_size);
    }
    
    return pcap_open_ex(filename, ctx, mode);
}

/**
 * @brief 以指定模式打开PCAP/PCAPNG文件
 */
int pcap_open_ex(const char *filename, pcap_context_t *ctx, pcap_mode_t mode) {
    if (!filename || !ctx) {
        LOG_ERROR("Invalid parameters");
        return -1;
    }
    
    memset(ctx, 0, sizeof(pcap_context_t));
    
    if (mode == PCAP_MODE_MEMORY) {
        return pcap_open_memory(filename, ctx);
    } else {
        return pcap_open_stream(filename, ctx);
    }
}

/**
 * @brief 从内存读取PCAP数据包
 */
static int pcap_read_packet_memory(pcap_context_t *ctx, packet_info_t *pkt) {
    pcap_packet_header_t *pkt_hdr = NULL;
    uint32_t caplen = 0;
    
    if (ctx->current_offset + sizeof(pcap_packet_header_t) > ctx->buffer_size) {
        return 0;
    }
    
    pkt_hdr = (pcap_packet_header_t *)(ctx->buffer + ctx->current_offset);
    caplen = ctx->byte_swap ? net_to_host32(pkt_hdr->caplen) : pkt_hdr->caplen;
    
    if (ctx->current_offset + sizeof(pcap_packet_header_t) + caplen > ctx->buffer_size) {
        LOG_ERROR("Packet data exceeds file boundary at offset %zu (caplen=%u, remaining=%zu)",
                  ctx->current_offset, caplen, 
                  ctx->buffer_size - ctx->current_offset - sizeof(pcap_packet_header_t));
        return -1;
    }
    
    pkt->timestamp_sec = ctx->byte_swap ? 
                         net_to_host32(pkt_hdr->ts_sec) : pkt_hdr->ts_sec;
    pkt->timestamp_usec = ctx->byte_swap ? 
                          net_to_host32(pkt_hdr->ts_usec) : pkt_hdr->ts_usec;
    pkt->captured_len = caplen;
    pkt->original_len = ctx->byte_swap ? 
                        net_to_host32(pkt_hdr->len) : pkt_hdr->len;
    pkt->data = ctx->buffer + ctx->current_offset + sizeof(pcap_packet_header_t);
    pkt->packet_number = ctx->packet_count + 1;
    
    ctx->current_offset += sizeof(pcap_packet_header_t) + caplen;
    ctx->packet_count++;
    ctx->total_bytes += caplen;
    
    return 1;
}

/**
 * @brief 从流读取PCAP数据包
 */
static int pcap_read_packet_stream(pcap_context_t *ctx, packet_info_t *pkt) {
    pcap_packet_header_t pkt_hdr;
    uint32_t caplen;
    
    /* 读取数据包头 */
    if (fread(&pkt_hdr, 1, sizeof(pkt_hdr), ctx->fp) != sizeof(pkt_hdr)) {
        if (feof(ctx->fp)) {
            return 0;
        }
        LOG_ERROR("Failed to read packet header at offset %lu", (unsigned long)ctx->file_offset);
        return -1;
    }
    
    caplen = ctx->byte_swap ? net_to_host32(pkt_hdr.caplen) : pkt_hdr.caplen;
    
    if (caplen > PCAP_MAX_PACKET_SIZE) {
        LOG_ERROR("Packet too large: %u bytes (max=%u) at offset %lu", 
                  caplen, PCAP_MAX_PACKET_SIZE, (unsigned long)ctx->file_offset);
        return -1;
    }
    
    /* 读取数据包数据 */
    if (fread(ctx->stream_buffer, 1, caplen, ctx->fp) != caplen) {
        LOG_ERROR("Failed to read packet data: expected %u bytes", caplen);
        return -1;
    }
    
    pkt->timestamp_sec = ctx->byte_swap ? 
                         net_to_host32(pkt_hdr.ts_sec) : pkt_hdr.ts_sec;
    pkt->timestamp_usec = ctx->byte_swap ? 
                          net_to_host32(pkt_hdr.ts_usec) : pkt_hdr.ts_usec;
    pkt->captured_len = caplen;
    pkt->original_len = ctx->byte_swap ? 
                        net_to_host32(pkt_hdr.len) : pkt_hdr.len;
    pkt->data = ctx->stream_buffer;
    pkt->packet_number = ctx->packet_count + 1;
    
    ctx->file_offset += sizeof(pkt_hdr) + caplen;
    ctx->packet_count++;
    ctx->total_bytes += caplen;
    
    return 1;
}

/**
 * @brief 读取下一个数据包
 */
int pcap_read_packet(pcap_context_t *ctx, packet_info_t *pkt) {
    if (!ctx || !pkt) {
        LOG_ERROR("Invalid parameters: ctx=%p, pkt=%p", (void*)ctx, (void*)pkt);
        return -1;
    }
    
    memset(pkt, 0, sizeof(packet_info_t));
    
    /* PCAPNG格式 */
    if (ctx->format == FILE_FORMAT_PCAPNG) {
        if (ctx->mode == PCAP_MODE_STREAM) {
            return pcap_read_packet_pcapng_stream(ctx, pkt);
        }
        /* TODO: PCAPNG内存模式 */
        LOG_ERROR("PCAPNG memory mode not yet implemented");
        return -1;
    }
    
    /* PCAP格式 */
    if (ctx->mode == PCAP_MODE_MEMORY) {
        if (!ctx->buffer) {
            LOG_ERROR("No buffer in memory mode");
            return -1;
        }
        return pcap_read_packet_memory(ctx, pkt);
    } else {
        if (!ctx->fp) {
            LOG_ERROR("No file handle in stream mode");
            return -1;
        }
        return pcap_read_packet_stream(ctx, pkt);
    }
}

/**
 * @brief 关闭并释放资源
 */
void pcap_close(pcap_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->buffer) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }
    
    if (ctx->stream_buffer) {
        free(ctx->stream_buffer);
        ctx->stream_buffer = NULL;
    }
    
    if (ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
    
    LOG_DEBUG("%s closed: %u packets, %lu bytes processed",
              pcap_format_name(ctx->format),
              ctx->packet_count, (unsigned long)ctx->total_bytes);
}

/**
 * @brief 重置到文件开头
 */
int pcap_reset(pcap_context_t *ctx) {
    if (!ctx) return -1;
    
    ctx->packet_count = 0;
    ctx->total_bytes = 0;
    
    if (ctx->mode == PCAP_MODE_MEMORY) {
        ctx->current_offset = sizeof(pcap_file_header_t);
    } else {
        if (!ctx->fp) return -1;
        fseek(ctx->fp, sizeof(pcap_file_header_t), SEEK_SET);
        ctx->file_offset = sizeof(pcap_file_header_t);
    }
    
    return 0;
}

/**
 * @brief 获取解析统计
 */
void pcap_get_stats(const pcap_context_t *ctx, pcap_stats_t *stats) {
    if (!ctx || !stats) return;
    
    stats->file_size = ctx->file_size;
    stats->total_packets = ctx->packet_count;
    stats->total_bytes = ctx->total_bytes;
}

/**
 * @brief 获取链路类型描述
 */
const char* pcap_linktype_name(uint32_t link_type) {
    switch (link_type) {
        case LINKTYPE_NULL:
            return "Null/Loopback";
        case LINKTYPE_ETHERNET:
            return "Ethernet";
        case LINKTYPE_RAW:
            return "Raw IP";
        case LINKTYPE_LINUX_SLL:
            return "Linux cooked";
        default:
            return "Unknown";
    }
}

/**
 * @brief 获取解析进度
 */
int pcap_get_progress(const pcap_context_t *ctx) {
    if (!ctx || ctx->file_size == 0) return 0;
    
    uint64_t current;
    if (ctx->mode == PCAP_MODE_MEMORY) {
        current = ctx->current_offset;
    } else {
        current = ctx->file_offset;
    }
    
    return (int)((current * 100) / ctx->file_size);
}
