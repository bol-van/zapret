# Zapret eBPF Makefile
# eBPF implementation for DPI evasion

# Compiler and tools
CC := clang
LLC := llc
OPT := opt
DIS := llvm-dis
OBJDUMP := llvm-objdump
STRIP := llvm-strip

# Directories
SRC_DIR := src
LOADER_DIR := loader
INCLUDE_DIR := include
LIBBPF_DIR := libbpf
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    EBPF_SUPPORTED := yes
    CFLAGS := -O2 -g -Wall -Wextra
    EBPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -D__KERNEL__ -D__ASM_SYSREG_H
    INCLUDES := -I$(INCLUDE_DIR) -I$(LIBBPF_DIR)/src -I/usr/include
    LDFLAGS := -L$(LIBBPF_DIR)/src -lbpf -lelf -lz
else ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    EBPF_SUPPORTED := no
    CFLAGS := -O2 -g -Wall -Wextra -D__APPLE__ -D__MACH__ -DMACOS_BUILD
    EBPF_CFLAGS := -O2 -g -D__APPLE__ -D__MACH__ -DMACOS_BUILD
    INCLUDES := -I$(INCLUDE_DIR) -I/usr/local/include
    LDFLAGS := -L/usr/local/lib
else
    PLATFORM := unknown
    EBPF_SUPPORTED := no
    CFLAGS := -O2 -g -Wall -Wextra
    EBPF_CFLAGS := -O2 -g
    INCLUDES := -I$(INCLUDE_DIR)
    LDFLAGS :=
endif

# Legacy compatibility
LLVM_STRIP ?= $(STRIP)
CLANG ?= $(CC)
LIBBPF_OBJ = $(LIBBPF_DIR)/src/libbpf.a
BPF_CFLAGS = $(EBPF_CFLAGS)

# eBPF program sources
EBPF_SRCS = src/zapret_filter.bpf.c \
            src/tls_fingerprint.bpf.c \
            src/quic_filter.bpf.c \
            src/packet_fragment.bpf.c \
            src/sni_encrypt.bpf.c

# eBPF object files
EBPF_OBJS = $(EBPF_SRCS:.bpf.c=.bpf.o)

# User-space loader sources
LOADER_SRCS = loader/zapret_loader.c \
              loader/ebpf_manager.c \
              loader/performance_monitor.c

# User-space loader objects
LOADER_OBJS = $(LOADER_SRCS:.c=.o)

# Target executables
TARGETS = zapret_ebpf_loader

.PHONY: all clean install libbpf ebpf_programs user_space

ifeq ($(EBPF_SUPPORTED),yes)
all: libbpf $(TARGETS)
	@echo "Build complete for $(PLATFORM) platform with eBPF support"
else
all: user_space
	@echo "Build complete for $(PLATFORM) platform"
endif

# Build libbpf (Linux only)
ifeq ($(EBPF_SUPPORTED),yes)
libbpf: $(LIBBPF_OBJ)

$(LIBBPF_OBJ):
	@if [ ! -d "$(LIBBPF_DIR)" ]; then \
		echo "Cloning libbpf..."; \
		git clone --depth 1 https://github.com/libbpf/libbpf.git $(LIBBPF_DIR); \
	fi
	$(MAKE) -C $(LIBBPF_DIR)/src
else
libbpf:
	@echo "SKIP    libbpf (not supported on $(PLATFORM))"

$(LIBBPF_OBJ):
	@touch $@
endif

# Compile eBPF programs (Linux only)
ifeq ($(EBPF_SUPPORTED),yes)
%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@
else
%.bpf.o: %.bpf.c
	@echo "SKIP    $@ (eBPF not supported on $(PLATFORM))"
	@touch $@
endif

# Compile user-space loader
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link the main loader
ifeq ($(EBPF_SUPPORTED),yes)
zapret_ebpf_loader: $(EBPF_OBJS) $(LOADER_OBJS) $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) $(LOADER_OBJS) $(LIBBPF_OBJ) -lelf -lz -o $@
else
zapret_ebpf_loader: $(LOADER_OBJS)
	$(CC) $(CFLAGS) $(LOADER_OBJS) $(LDFLAGS) -o $@
endif



install: all
	cp $(TARGETS) /usr/local/bin/
	cp $(EBPF_OBJS) /usr/local/share/zapret/ebpf/

clean:
	rm -f $(EBPF_OBJS) $(LOADER_OBJS) $(TARGETS)
	@if [ -d "$(LIBBPF_DIR)" ]; then \
		$(MAKE) -C $(LIBBPF_DIR)/src clean; \
	fi

distclean: clean
	rm -rf $(LIBBPF_DIR)

# Development targets
format:
	@echo "Formatting source code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(LOADER_SRCS) include/*.h src/*.c; \
		echo "Code formatting completed"; \
	else \
		echo "clang-format not found, skipping formatting"; \
	fi

check:
	@echo "Checking eBPF programs and source code..."
	@echo "Checking syntax with clang..."
	@for src in $(LOADER_SRCS); do \
		echo "Checking $$src"; \
		$(CC) $(CFLAGS) $(INCLUDES) -fsyntax-only $$src || exit 1; \
	done
ifeq ($(EBPF_SUPPORTED),yes)
	@echo "Verifying eBPF programs..."
	@for prog in $(EBPF_OBJS); do \
		if [ -f "$$prog" ]; then \
			echo "Verifying $$prog"; \
			if command -v bpftool >/dev/null 2>&1; then \
				bpftool prog load $$prog /sys/fs/bpf/test_$$prog 2>/dev/null && \
				bpftool prog del pinned /sys/fs/bpf/test_$$prog || true; \
			else \
				echo "bpftool not found, skipping eBPF verification"; \
			fi; \
		fi; \
	done
else
	@echo "eBPF verification skipped (not supported on $(PLATFORM))"
endif
	@echo "All checks completed"

# macOS target
mac: user_space
	@echo "macOS build completed"

# Help target
help:
	@echo "Zapret eBPF Build System"
	@echo "========================"
	@echo "Platform: $(PLATFORM)"
	@echo "eBPF Support: $(EBPF_SUPPORTED)"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build all eBPF programs and loader"
	@echo "  mac       - Build for macOS"
	@echo "  libbpf    - Build libbpf dependency (Linux only)"
	@echo "  install   - Install binaries to system directories"
	@echo "  clean     - Clean build artifacts"
	@echo "  distclean - Clean everything including dependencies"
	@echo "  format    - Format source code with clang-format"
	@echo "  check     - Verify eBPF programs and check syntax"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Build Configuration:"
	@echo "  CC        = $(CC)"
	@echo "  CFLAGS    = $(CFLAGS)"
	@echo "  INCLUDES  = $(INCLUDES)"
	@echo "  LDFLAGS   = $(LDFLAGS)"
	@echo ""
	@echo "Source Files:"
	@echo "  eBPF Programs: $(EBPF_SRCS)"
	@echo "  Loader Sources: $(LOADER_SRCS)"
	@echo "  Target: $(TARGETS)"