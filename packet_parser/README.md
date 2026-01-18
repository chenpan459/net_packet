# Packet Parser Framework v3.2 Enterprise

企业级高性能网络报文解析框架，支持 PCAP/PCAPNG 双格式、IPv4/IPv6 双栈、多种输出格式。

## ✨ 功能特性

### 协议支持
| 层级 | 协议 | 功能 |
|------|------|------|
| L2 | Ethernet | 完整解析 |
| L2 | **802.1Q VLAN** | VLAN标签解析 |
| L3 | ARP | 请求/响应 |
| L3 | IPv4 | 完整解析 + 校验和 + **分片检测** |
| L3 | IPv6 | 完整解析 + 扩展头 |
| L4 | ICMP | 多类型支持 + 校验和 |
| L4 | ICMPv6 | 邻居发现等 + 校验和 |
| L4 | TCP | 完整标志位 + 校验和 + **选项解析** |
| L4 | UDP | 服务识别 + 校验和 |

### TCP 选项解析
| 选项 | 说明 |
|------|------|
| MSS | 最大报文段大小 |
| Window Scale | 窗口缩放因子 |
| SACK Permitted | 允许选择确认 |
| SACK | 选择确认数据块 |
| Timestamps | 时间戳 (RTT计算) |

### 文件格式支持
| 格式 | 说明 |
|------|------|
| **PCAP** | 经典格式 (tcpdump, 旧版Wireshark) |
| **PCAPNG** | 现代格式 (Wireshark默认, 支持多接口) |

### 输出格式支持
| 格式 | 说明 | 用途 |
|------|------|------|
| text | 人类可读文本 | 调试、手动分析 |
| json | JSON格式 | API集成、前端展示 |
| jsonl | JSON Lines | 流式处理、日志分析 |
| csv | CSV格式 | Excel、数据分析 |

### 企业级特性
- 🚀 **流式解析**: 支持任意大小 PCAP/PCAPNG 文件
- 📊 **性能基准**: 内置 benchmark 工具
- 📝 **日志系统**: 6 级日志 + 文件输出
- ✅ **校验和验证**: IPv4/IPv6 全协议支持
- 🔧 **跨编译器**: GCC / Clang / MSVC 兼容
- 🧪 **单元测试**: 完整测试覆盖
- 🔍 **模糊测试**: 边界条件和随机数据测试
- 📤 **多格式输出**: TEXT / JSON / JSONL / CSV

## 📋 系统要求

- Ubuntu 22.04 LTS / Linux
- GCC 11+ / Clang 14+
- GNU Make

## 🚀 快速开始

### 编译
```bash
make            # 标准编译
make debug      # 调试版本 (含 AddressSanitizer)
make release    # 发布版本 (优化)
```

### 运行
```bash
# 基本用法 (支持PCAP和PCAPNG)
./bin/packet_parser capture.pcap
./bin/packet_parser capture.pcapng

# 仅显示统计
./bin/packet_parser -s capture.pcap

# 流式解析大文件
./bin/packet_parser -m stream -p large.pcap

# 调整日志级别
./bin/packet_parser -l debug capture.pcap

# JSON输出
./bin/packet_parser -f json capture.pcap > output.json

# CSV输出
./bin/packet_parser -f csv capture.pcap > output.csv

# JSON Lines (流式处理)
./bin/packet_parser -f jsonl capture.pcap | jq .
```

### 测试
```bash
make test       # 单元测试
make bench      # 性能基准测试
make fuzz       # 模糊测试/边界测试
make demo       # 生成测试数据并演示
```

## 📁 项目结构

```
packet_parser/
├── include/
│   ├── protocols.h      # 协议结构 (IPv4/IPv6/ICMPv6...)
│   ├── pcap_parser.h    # PCAP 解析 (内存/流式)
│   ├── parser.h         # 协议解析接口
│   ├── utils.h          # 工具函数
│   └── log.h            # 日志系统
├── src/
│   ├── pcap_parser.c    # PCAP 解析实现
│   ├── ethernet.c       # 以太网
│   ├── arp.c            # ARP
│   ├── ipv4.c           # IPv4
│   ├── ipv6.c           # IPv6 + ICMPv6
│   ├── icmp.c           # ICMP
│   ├── tcp.c            # TCP
│   ├── udp.c            # UDP
│   ├── utils.c          # 工具函数
│   ├── log.c            # 日志实现
│   └── main.c           # 主程序
├── tests/
│   ├── test_framework.h # 测试框架
│   ├── test_parser.c    # 单元测试
│   └── benchmark.c      # 性能测试
├── tools/
│   └── gen_test_pcap.c  # PCAP 生成器
├── Makefile
└── README.md
```

## 🔧 命令行选项

```
Usage: packet_parser [options] <pcap_file>

Options:
  -f, --format <format>    输出格式 (text,json,jsonl,csv)
  -o, --output <file>      输出到文件
  -l, --log-level <level>  日志级别 (trace,debug,info,warn,error,off)
  -L, --log-file <file>    日志输出到文件
  -s, --stats-only         仅显示统计信息
  -q, --quiet              静默模式
  -p, --progress           显示解析进度
  -m, --mode <mode>        解析模式 (memory,stream)
  -v, --verbose            详细输出
  -h, --help               显示帮助
```

## 📊 性能指标

基准测试结果 (Intel i7-10700):

| 操作 | 平均耗时 | 吞吐量 |
|------|---------|--------|
| 以太网解析 | ~0.02 µs | ~50M ops/s |
| IPv4 解析 | ~0.05 µs | ~20M ops/s |
| TCP 解析 | ~0.03 µs | ~30M ops/s |
| 完整包解析 | ~0.15 µs | ~6.5M pps |

运行基准测试:
```bash
make bench
./bin/benchmark large_capture.pcap
```

## 📝 日志系统

6 级日志控制:
```c
LOG_TRACE("Detailed trace info");
LOG_DEBUG("Debug information");
LOG_INFO("General information");
LOG_WARN("Warning message");
LOG_ERROR("Error occurred");
LOG_FATAL("Fatal error");
```

配置示例:
```bash
# 运行时设置
./bin/packet_parser -l debug -L parser.log capture.pcap

# 代码中设置
log_init(LOG_LEVEL_DEBUG, "parser.log");
log_set_color(1);
log_set_timestamp(1);
```

## ✅ 校验和验证

完整的校验和支持:
- IPv4 头部校验和
- ICMP / ICMPv6 校验和  
- TCP / UDP 伪首部校验和

### ⚠️ Checksum Offload 说明

如果您在解析本地捕获的流量时发现 TCP/UDP 校验和显示为 ERROR，这通常是正常现象！

**原因**: 现代网卡启用了 **Checksum Offload** 功能，将校验和计算卸载到网卡硬件。当使用 tcpdump/Wireshark 等工具捕获**发送方向**的流量时，软件层的校验和字段可能尚未填充或为占位值。

**验证方法**:
```bash
# 检查网卡 checksum offload 状态
ethtool -k eth0 | grep checksum

# 临时禁用 (测试用)
sudo ethtool -K eth0 tx off rx off
```

**注意**: 接收方向的流量校验和通常是正确的。

## 🌐 IPv6 支持

完整的 IPv6 协议栈:
- IPv6 基本头解析
- 扩展头跳过 (逐跳、路由、分片、目的选项)
- ICMPv6 解析 (Echo、邻居发现等)
- TCP/UDP over IPv6 校验和验证

## 📈 流式解析

支持任意大小 PCAP 文件:
```bash
# 自动选择模式 (≤50KB 内存模式，>50KB 流式模式)
./bin/packet_parser huge_capture.pcap

# 强制流式模式
./bin/packet_parser -m stream -p huge_capture.pcap
```

## 🧪 单元测试

测试覆盖:
- 字节序转换
- 校验和计算
- 各协议解析
- 边界条件
- 结构体大小

```bash
$ make test

╔════════════════════════════════════════════════╗
║      Packet Parser Unit Tests                  ║
╚════════════════════════════════════════════════╝

[TEST SUITE] Protocol Parsing
  [PASS] Ethernet parsing succeeded
  [PASS] IPv4 parsing succeeded
  [PASS] IPv4 checksum is valid
  ...

═══════════════════════════════════════════════
                Test Summary                    
═══════════════════════════════════════════════
Total:  28
Passed: 28
Failed: 0
═══════════════════════════════════════════════
✓ All tests passed!
```

## 🔄 版本历史

| 版本 | 特性 |
|------|------|
| v1.0 | 基础协议解析 |
| v2.0 | UDP 支持、校验和验证、单元测试 |
| v3.0 | IPv6、流式解析、日志系统、性能基准 |
| v3.1 | TCP选项解析、802.1Q VLAN、IPv4分片检测、Fuzz测试 |
| **v3.2** | PCAPNG支持、JSON/CSV输出、MSVC兼容层、错误日志增强 |

## 📄 License

MIT License

---

**Packet Parser Framework** - 企业级网络协议分析工具
