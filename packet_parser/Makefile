# ============================================================
# Packet Parser Framework Makefile
# Version: 3.2 Enterprise
# Target: Ubuntu 22.04 / Linux with GCC (MSVC via CMake)
# ============================================================

# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -O2 -g
CFLAGS += -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE

# 版本信息
VERSION_MAJOR = 3
VERSION_MINOR = 2
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR)

# 目录
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests
TOOLS_DIR = tools

# 目标
TARGET = $(BIN_DIR)/packet_parser
TEST_TARGET = $(BIN_DIR)/test_parser
BENCH_TARGET = $(BIN_DIR)/benchmark
FUZZ_TARGET = $(BIN_DIR)/test_fuzz
TOOLS_TARGET = $(BIN_DIR)/gen_test_pcap

# 源文件
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# 库文件 (不包含 main.c)
LIB_SRCS = $(filter-out $(SRC_DIR)/main.c, $(SRCS))
LIB_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(LIB_SRCS))

# 头文件依赖
DEPS = $(wildcard $(INC_DIR)/*.h)

# 颜色输出
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
RESET = \033[0m

# 默认目标
.PHONY: all
all: directories $(TARGET)
	@echo "$(GREEN)[BUILD] Complete!$(RESET)"

# 创建目录
.PHONY: directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# 链接主程序
$(TARGET): $(OBJS)
	@echo "$(BLUE)[LINK]$(RESET) $@"
	@$(CC) $(CFLAGS) -o $@ $^

# 编译源文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	@echo "$(YELLOW)[CC]$(RESET) $<"
	@$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

# ======================= 测试 =======================

.PHONY: test
test: directories $(TEST_TARGET)
	@echo ""
	@echo "$(BLUE)[RUN]$(RESET) Running unit tests..."
	@./$(TEST_TARGET)

$(TEST_TARGET): $(LIB_OBJS) $(TEST_DIR)/test_parser.c
	@echo "$(BLUE)[LINK]$(RESET) $@"
	@$(CC) $(CFLAGS) -I$(INC_DIR) -o $@ $(LIB_OBJS) $(TEST_DIR)/test_parser.c

# ======================= 基准测试 =======================

.PHONY: bench benchmark
bench benchmark: directories $(BENCH_TARGET)
	@echo ""
	@echo "$(BLUE)[RUN]$(RESET) Running benchmarks..."
	@./$(BENCH_TARGET)

$(BENCH_TARGET): $(LIB_OBJS) $(TEST_DIR)/benchmark.c
	@echo "$(BLUE)[LINK]$(RESET) $@"
	@$(CC) $(CFLAGS) -I$(INC_DIR) -o $@ $(LIB_OBJS) $(TEST_DIR)/benchmark.c

# ======================= 模糊测试 =======================

.PHONY: fuzz
fuzz: directories $(FUZZ_TARGET)
	@echo ""
	@echo "$(BLUE)[RUN]$(RESET) Running fuzz tests..."
	@./$(FUZZ_TARGET)

$(FUZZ_TARGET): $(LIB_OBJS) $(TEST_DIR)/test_fuzz.c
	@echo "$(BLUE)[LINK]$(RESET) $@"
	@$(CC) $(CFLAGS) -I$(INC_DIR) -o $@ $(LIB_OBJS) $(TEST_DIR)/test_fuzz.c

# ======================= 工具 =======================

.PHONY: tools
tools: directories $(TOOLS_TARGET)

$(TOOLS_TARGET): $(TOOLS_DIR)/gen_test_pcap.c
	@echo "$(YELLOW)[CC]$(RESET) $<"
	@$(CC) $(CFLAGS) -o $@ $<

# ======================= Demo =======================

.PHONY: demo
demo: all tools
	@echo ""
	@echo "$(BLUE)[DEMO]$(RESET) Generating test PCAP..."
	@cd $(BIN_DIR) && ./gen_test_pcap
	@echo ""
	@echo "$(BLUE)[DEMO]$(RESET) Running parser..."
	@./$(TARGET) $(BIN_DIR)/test.pcap

# ======================= 清理 =======================

.PHONY: clean
clean:
	@echo "$(RED)[CLEAN]$(RESET) Removing build artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: rebuild
rebuild: clean all

# ======================= 构建变体 =======================

.PHONY: debug
debug: CFLAGS += -DDEBUG -O0 -fsanitize=address
debug: all
	@echo "$(YELLOW)[DEBUG] Built with AddressSanitizer$(RESET)"

.PHONY: release
release: CFLAGS += -DNDEBUG -O3 -march=native -flto
release: all
	@echo "$(GREEN)[RELEASE] Optimized build complete$(RESET)"

.PHONY: profile
profile: CFLAGS += -pg -O2
profile: all
	@echo "$(YELLOW)[PROFILE] Built with profiling support$(RESET)"

# ======================= 静态分析 =======================

.PHONY: analyze
analyze:
	@echo "$(BLUE)[ANALYZE]$(RESET) Running static analysis..."
	@cppcheck --enable=all --std=c11 -I$(INC_DIR) $(SRC_DIR) 2>&1 | head -50

.PHONY: format
format:
	@echo "$(BLUE)[FORMAT]$(RESET) Formatting source files..."
	@find $(SRC_DIR) $(INC_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i

# ======================= 安装 =======================

PREFIX ?= /usr/local

.PHONY: install
install: release
	@echo "$(GREEN)[INSTALL]$(RESET) Installing to $(PREFIX)/bin..."
	@install -d $(PREFIX)/bin
	@install -m 755 $(TARGET) $(PREFIX)/bin/

.PHONY: uninstall
uninstall:
	@echo "$(RED)[UNINSTALL]$(RESET) Removing from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/packet_parser

# ======================= 帮助 =======================

.PHONY: help
help:
	@echo ""
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║      Packet Parser Framework v$(VERSION) - Build System              ║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Build Targets:$(RESET)"
	@echo "  make           - Build the main parser"
	@echo "  make debug     - Build with debug symbols and AddressSanitizer"
	@echo "  make release   - Build optimized release"
	@echo "  make profile   - Build with profiling support"
	@echo ""
	@echo "$(YELLOW)Test Targets:$(RESET)"
	@echo "  make test      - Run unit tests"
	@echo "  make bench     - Run performance benchmarks"
	@echo "  make fuzz      - Run fuzz/boundary tests"
	@echo "  make demo      - Generate test PCAP and run demo"
	@echo ""
	@echo "$(YELLOW)Other Targets:$(RESET)"
	@echo "  make tools     - Build helper tools"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make install   - Install to $(PREFIX)/bin"
	@echo "  make analyze   - Run static analysis (requires cppcheck)"
	@echo "  make format    - Format code (requires clang-format)"
	@echo ""
	@echo "$(YELLOW)Usage:$(RESET)"
	@echo "  ./bin/packet_parser [options] <pcap_file>"
	@echo "  ./bin/packet_parser -h  # Show help"
	@echo ""
	@echo "$(YELLOW)Output Formats:$(RESET)"
	@echo "  -f text    - Human readable (default)"
	@echo "  -f json    - JSON format"
	@echo "  -f jsonl   - JSON Lines (streaming)"
	@echo "  -f csv     - CSV format"
	@echo ""
	@echo "$(YELLOW)Supported File Formats:$(RESET)"
	@echo "  - PCAP  (tcpdump, Wireshark legacy)"
	@echo "  - PCAPNG (Wireshark default)"
	@echo ""

# 显示变量
.PHONY: vars
vars:
	@echo "SRCS = $(SRCS)"
	@echo "OBJS = $(OBJS)"
	@echo "LIB_OBJS = $(LIB_OBJS)"
	@echo "CFLAGS = $(CFLAGS)"
