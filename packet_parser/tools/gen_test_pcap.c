/**
 * @file gen_test_pcap.c
 * @brief 生成测试用的 PCAP 文件 (v2.0)
 * @description 包含 ARP、ICMP、TCP、UDP 测试数据包
 * 
 * 编译: gcc -o gen_test_pcap gen_test_pcap.c
 * 使用: ./gen_test_pcap
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* PCAP文件头 */
typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

/* PCAP数据包头 */
typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
} pcaprec_hdr_t;

/* 以太网头 */
typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} eth_hdr_t;

/* ARP头 */
typedef struct __attribute__((packed)) {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} arp_hdr_t;

/* IPv4头 */
typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_hdr_t;

/* ICMP头 */
typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_hdr_t;

/* TCP头 */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_hdr_t;

/* UDP头 */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_hdr_t;

/* 计算校验和 */
uint16_t calc_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* 网络字节序转换 */
uint16_t htons_local(uint16_t h) {
    return ((h >> 8) & 0xFF) | ((h << 8) & 0xFF00);
}

uint32_t htonl_local(uint32_t h) {
    return ((h >> 24) & 0xFF) | ((h >> 8) & 0xFF00) |
           ((h << 8) & 0xFF0000) | ((h << 24) & 0xFF000000);
}

int main() {
    FILE *fp = fopen("test.pcap", "wb");
    if (!fp) {
        perror("Cannot create file");
        return 1;
    }
    
    printf("Generating test PCAP file...\n\n");
    
    /* 写入PCAP文件头 */
    pcap_hdr_t pcap_hdr = {
        .magic_number = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  /* Ethernet */
    };
    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, fp);
    
    uint32_t timestamp = 1700000000;
    int packet_count = 0;
    
    /* ============ Packet 1: ARP Request ============ */
    {
        uint8_t pkt[42];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        memset(eth->dst_mac, 0xFF, 6);
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0806);
        
        arp_hdr_t *arp = (arp_hdr_t *)(pkt + 14);
        arp->hw_type = htons_local(1);
        arp->proto_type = htons_local(0x0800);
        arp->hw_len = 6;
        arp->proto_len = 4;
        arp->opcode = htons_local(1);
        memcpy(arp->sender_mac, src_mac, 6);
        uint8_t sender_ip[] = {192, 168, 1, 100};
        uint8_t target_ip[] = {192, 168, 1, 1};
        memcpy(arp->sender_ip, sender_ip, 4);
        memset(arp->target_mac, 0, 6);
        memcpy(arp->target_ip, target_ip, 4);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] ARP Request: Who has 192.168.1.1?\n", ++packet_count);
    }
    
    /* ============ Packet 2: ARP Reply ============ */
    {
        uint8_t pkt[42];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        uint8_t src_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0806);
        
        arp_hdr_t *arp = (arp_hdr_t *)(pkt + 14);
        arp->hw_type = htons_local(1);
        arp->proto_type = htons_local(0x0800);
        arp->hw_len = 6;
        arp->proto_len = 4;
        arp->opcode = htons_local(2);
        memcpy(arp->sender_mac, src_mac, 6);
        uint8_t sender_ip[] = {192, 168, 1, 1};
        uint8_t target_ip[] = {192, 168, 1, 100};
        memcpy(arp->sender_ip, sender_ip, 4);
        memcpy(arp->target_mac, dst_mac, 6);
        memcpy(arp->target_ip, target_ip, 4);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] ARP Reply: 192.168.1.1 is at 11:22:33:44:55:66\n", ++packet_count);
    }
    
    /* ============ Packet 3: ICMP Echo Request ============ */
    {
        uint8_t pkt[74];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_len = htons_local(60);
        ip->id = htons_local(0x1234);
        ip->flags_frag = 0;
        ip->ttl = 64;
        ip->protocol = 1;
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0xC0A80101);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        icmp_hdr_t *icmp = (icmp_hdr_t *)(pkt + 34);
        icmp->type = 8;
        icmp->code = 0;
        icmp->id = htons_local(0x0001);
        icmp->seq = htons_local(1);
        uint8_t *data = pkt + 42;
        for (int i = 0; i < 32; i++) {
            data[i] = 'A' + (i % 26);
        }
        icmp->checksum = 0;
        icmp->checksum = calc_checksum((uint8_t *)icmp, 40);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] ICMP Echo Request: 192.168.1.100 -> 192.168.1.1\n", ++packet_count);
    }
    
    /* ============ Packet 4: ICMP Echo Reply ============ */
    {
        uint8_t pkt[74];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        uint8_t src_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(60);
        ip->id = htons_local(0x5678);
        ip->ttl = 64;
        ip->protocol = 1;
        ip->src_ip = htonl_local(0xC0A80101);
        ip->dst_ip = htonl_local(0xC0A80164);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        icmp_hdr_t *icmp = (icmp_hdr_t *)(pkt + 34);
        icmp->type = 0;
        icmp->code = 0;
        icmp->id = htons_local(0x0001);
        icmp->seq = htons_local(1);
        uint8_t *data = pkt + 42;
        for (int i = 0; i < 32; i++) {
            data[i] = 'A' + (i % 26);
        }
        icmp->checksum = 0;
        icmp->checksum = calc_checksum((uint8_t *)icmp, 40);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] ICMP Echo Reply: 192.168.1.1 -> 192.168.1.100\n", ++packet_count);
    }
    
    /* ============ Packet 5: TCP SYN ============ */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(40);
        ip->id = htons_local(0xABCD);
        ip->ttl = 64;
        ip->protocol = 6;
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0x08080808);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        tcp_hdr_t *tcp = (tcp_hdr_t *)(pkt + 34);
        tcp->src_port = htons_local(54321);
        tcp->dst_port = htons_local(80);
        tcp->seq = htonl_local(1000);
        tcp->ack = 0;
        tcp->offset = 0x50;
        tcp->flags = 0x02;
        tcp->window = htons_local(65535);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] TCP SYN: 192.168.1.100:54321 -> 8.8.8.8:80\n", ++packet_count);
    }
    
    /* ============ Packet 6: TCP SYN+ACK ============ */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        uint8_t src_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(40);
        ip->id = htons_local(0x1111);
        ip->ttl = 56;
        ip->protocol = 6;
        ip->src_ip = htonl_local(0x08080808);
        ip->dst_ip = htonl_local(0xC0A80164);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        tcp_hdr_t *tcp = (tcp_hdr_t *)(pkt + 34);
        tcp->src_port = htons_local(80);
        tcp->dst_port = htons_local(54321);
        tcp->seq = htonl_local(5000);
        tcp->ack = htonl_local(1001);
        tcp->offset = 0x50;
        tcp->flags = 0x12;
        tcp->window = htons_local(65535);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] TCP SYN+ACK: 8.8.8.8:80 -> 192.168.1.100:54321\n", ++packet_count);
    }
    
    /* ============ Packet 7: UDP DNS Query ============ */
    {
        uint8_t pkt[72];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(58);  /* 20 + 8 + 30 */
        ip->id = htons_local(0x2222);
        ip->ttl = 64;
        ip->protocol = 17;  /* UDP */
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0x08080808);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        udp_hdr_t *udp = (udp_hdr_t *)(pkt + 34);
        udp->src_port = htons_local(12345);
        udp->dst_port = htons_local(53);  /* DNS */
        udp->length = htons_local(38);     /* 8 + 30 */
        udp->checksum = 0;  /* Optional for UDP over IPv4 */
        
        /* Simple DNS query for example.com */
        uint8_t *dns = pkt + 42;
        dns[0] = 0x00; dns[1] = 0x01;  /* Transaction ID */
        dns[2] = 0x01; dns[3] = 0x00;  /* Flags: Standard query */
        dns[4] = 0x00; dns[5] = 0x01;  /* Questions: 1 */
        dns[6] = 0x00; dns[7] = 0x00;  /* Answers: 0 */
        dns[8] = 0x00; dns[9] = 0x00;  /* Authority: 0 */
        dns[10] = 0x00; dns[11] = 0x00; /* Additional: 0 */
        /* Query: example.com */
        dns[12] = 0x07;  /* Length of "example" */
        memcpy(&dns[13], "example", 7);
        dns[20] = 0x03;  /* Length of "com" */
        memcpy(&dns[21], "com", 3);
        dns[24] = 0x00;  /* Null terminator */
        dns[25] = 0x00; dns[26] = 0x01;  /* Type: A */
        dns[27] = 0x00; dns[28] = 0x01;  /* Class: IN */
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] UDP DNS Query: 192.168.1.100 -> 8.8.8.8 (example.com)\n", ++packet_count);
    }
    
    /* ============ Packet 8: UDP NTP ============ */
    {
        uint8_t pkt[90];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(76);  /* 20 + 8 + 48 */
        ip->id = htons_local(0x3333);
        ip->ttl = 64;
        ip->protocol = 17;
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0xD8EF2002);  /* time.google.com */
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        udp_hdr_t *udp = (udp_hdr_t *)(pkt + 34);
        udp->src_port = htons_local(45678);
        udp->dst_port = htons_local(123);  /* NTP */
        udp->length = htons_local(56);      /* 8 + 48 */
        udp->checksum = 0;
        
        /* NTP packet (simplified) */
        uint8_t *ntp = pkt + 42;
        ntp[0] = 0x1b;  /* LI=0, VN=3, Mode=3 (client) */
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] UDP NTP: 192.168.1.100 -> time.google.com:123\n", ++packet_count);
    }
    
    /* ============ Packet 9: TCP HTTP GET with Data ============ */
    {
        uint8_t pkt[120];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(106);  /* 20 + 20 + 66 */
        ip->id = htons_local(0xCCCC);
        ip->ttl = 64;
        ip->protocol = 6;
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0x08080808);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        tcp_hdr_t *tcp = (tcp_hdr_t *)(pkt + 34);
        tcp->src_port = htons_local(54321);
        tcp->dst_port = htons_local(80);
        tcp->seq = htonl_local(1001);
        tcp->ack = htonl_local(5001);
        tcp->offset = 0x50;
        tcp->flags = 0x18;  /* PSH+ACK */
        tcp->window = htons_local(65535);
        
        /* HTTP GET request */
        const char *http_req = "GET / HTTP/1.1\r\nHost: 8.8.8.8\r\nUser-Agent: test\r\n\r\n";
        size_t http_len = strlen(http_req);
        memcpy(pkt + 54, http_req, http_len);
        
        pcaprec_hdr_t rec = {timestamp++, 0, 54 + http_len, 54 + http_len};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, 54 + http_len, 1, fp);
        printf("[%d] TCP HTTP GET: 192.168.1.100 -> 8.8.8.8:80\n", ++packet_count);
    }
    
    /* ============ Packet 10: TCP FIN ============ */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        uint8_t dst_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        uint8_t src_mac[] = {0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33};
        memcpy(eth->dst_mac, dst_mac, 6);
        memcpy(eth->src_mac, src_mac, 6);
        eth->ether_type = htons_local(0x0800);
        
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(pkt + 14);
        ip->ver_ihl = 0x45;
        ip->total_len = htons_local(40);
        ip->id = htons_local(0xDDDD);
        ip->ttl = 64;
        ip->protocol = 6;
        ip->src_ip = htonl_local(0xC0A80164);
        ip->dst_ip = htonl_local(0x08080808);
        ip->checksum = 0;
        ip->checksum = calc_checksum((uint8_t *)ip, 20);
        
        tcp_hdr_t *tcp = (tcp_hdr_t *)(pkt + 34);
        tcp->src_port = htons_local(54321);
        tcp->dst_port = htons_local(80);
        tcp->seq = htonl_local(1100);
        tcp->ack = htonl_local(5100);
        tcp->offset = 0x50;
        tcp->flags = 0x11;  /* FIN+ACK */
        tcp->window = htons_local(65535);
        
        pcaprec_hdr_t rec = {timestamp++, 0, sizeof(pkt), sizeof(pkt)};
        fwrite(&rec, sizeof(rec), 1, fp);
        fwrite(pkt, sizeof(pkt), 1, fp);
        printf("[%d] TCP FIN+ACK: 192.168.1.100 -> 8.8.8.8:80 (closing)\n", ++packet_count);
    }
    
    fclose(fp);
    
    printf("\n══════════════════════════════════════════════════\n");
    printf("Test PCAP file 'test.pcap' created successfully!\n");
    printf("══════════════════════════════════════════════════\n");
    printf("Contents:\n");
    printf("  - 2 ARP packets (request + reply)\n");
    printf("  - 2 ICMP packets (echo request + reply)\n");
    printf("  - 4 TCP packets (SYN, SYN+ACK, PSH+ACK, FIN+ACK)\n");
    printf("  - 2 UDP packets (DNS query, NTP request)\n");
    printf("  - Total: %d packets\n", packet_count);
    
    return 0;
}
