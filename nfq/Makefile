CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_MACOS = -Wno-address-of-packed-member -DMACOS_DARWIN
LDFLAGS_ANDROID = -llog
LIBS = -lz -lpthread -lnetfilter_queue -lmnl
LIBS_SYSTEMD = -lsystemd
LIBS_MACOS = -lz -lpthread
LIBS_ANDROID = -lz

# MacOS target detection with improved compatibility
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

# Detect MacOS version for better compatibility
MACOS_VERSION ?= $(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo "10.8")

# Set minimum MacOS version based on detected version
MACOS_MIN_VERSION := $(shell echo "$(MACOS_VERSION)" | sed 's/10\.8/10.8/;s/11\./11.0/;s/12\./12.0/;s/13\./13.0/;s/14\./14.0/')

# Check if we're on MacOS (Darwin)
IS_MACOS := $(shell [ "$(shell uname)" = "Darwin" ] && echo "1" || echo "0")

SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_SYSTEMD) -o nfqws $(SRC_FILES) $(LIBS) $(LIBS_SYSTEMD) $(LDFLAGS)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS_ANDROID) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_MACOS) -o dvtws $(SRC_FILES) $(LIBS_MACOS) $(LDFLAGS)

# Single architecture build for MacOS (Darwin) with improved compatibility
mac: $(SRC_FILES)
	@echo "Building dvtws for MacOS (Darwin) target: $(MACOS_TARGET)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	@echo "WARNING: nfq component is not fully supported on MacOS!"
	@echo "         - No NFQUEUE support (Linux-specific)"
	@echo "         - Building dvtws (divert sockets) instead"
	@echo "         - Limited functionality compared to Linux version"
	@echo "         - MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	@echo ""
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o dvtws \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS_MACOS) $(LDFLAGS)
	strip dvtws

# Universal binary build for MacOS (Darwin) (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal dvtws for MacOS (Darwin) (x86_64 + arm64)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	@echo "WARNING: nfq component is not fully supported on MacOS!"
	@echo "         - No NFQUEUE support (Linux-specific)"
	@echo "         - Building dvtws (divert sockets) instead"
	@echo "         - Limited functionality compared to Linux version"
	@echo "         - MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	@echo ""
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o dvtwsa \
		-target arm64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS_MACOS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o dvtwsx \
		-target x86_64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS_MACOS) $(LDFLAGS)
	strip dvtwsa dvtwsx
	lipo -create -output dvtws dvtwsx dvtwsa
	rm -f dvtwsx dvtwsa

# MacOS build with specific version targeting
mac-$(MACOS_VERSION): $(SRC_FILES)
	@echo "Building dvtws for MacOS (Darwin) $(MACOS_VERSION) with target: $(MACOS_TARGET)"
	@echo "WARNING: nfq component is not fully supported on MacOS!"
	@echo "         - No NFQUEUE support (Linux-specific)"
	@echo "         - Building dvtws (divert sockets) instead"
	@echo "         - Limited functionality compared to Linux version"
	@echo "         - MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	@echo ""
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o dvtws \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS_MACOS) $(LDFLAGS)
	strip dvtws

clean:
	rm -f nfqws dvtws *.o dvtwsa dvtwsx

# MacOS specific clean
mac-clean:
	rm -f nfqws dvtws *.o dvtwsa dvtwsx
	@echo "Cleaned MacOS (Darwin) build artifacts"

# Show MacOS build information
mac-info:
	@echo "nfq MacOS (Darwin) Build Information:"
	@echo "====================================="
	@echo "Target: $(MACOS_TARGET)"
	@echo "Version: $(MACOS_VERSION)"
	@echo "Minimum: $(MACOS_MIN_VERSION)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo ""
	@echo "IMPORTANT NOTES:"
	@echo "================="
	@echo "• nfq component is NOT fully supported on MacOS"
	@echo "• No NFQUEUE support (Linux-specific feature)"
	@echo "• Building dvtws (divert sockets) instead"
	@echo "• Limited functionality compared to Linux version"
	@echo "• Consider using tpws for MacOS DPI bypass"
	@echo ""
	@echo "CRITICAL: MacOS is NOT BSD - it's a hybrid system with:"
	@echo "  - XNU kernel (Mach + BSD-like layer + Apple components)"
	@echo "  - Unique networking stack and system calls"
	@echo "  - Apple-specific security features (SIP, code signing)"
	@echo "  - Different firewall (PF) and service management (launchd)"
	@echo "  - Limited support for BSD-style divert sockets"
	@echo ""
	@echo "Available targets:"
	@echo "  make mac           - Build for current architecture"
	@echo "  make mac-universal - Build universal binary"
	@echo "  make mac-$(MACOS_VERSION) - Build for specific version"
	@echo "  make mac-clean     - Clean MacOS builds"
	@echo "  make mac-info      - Show this information"
