CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_MACOS = -Wno-address-of-packed-member -DMACOS_DARWIN
CFLAGS_WIN = -static
LIBS = 
LIBS_WIN = -lws2_32

# MacOS target detection with improved compatibility
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

# Detect MacOS version for better compatibility
MACOS_VERSION ?= $(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo "10.8")

# Set minimum MacOS version based on detected version
MACOS_MIN_VERSION := $(shell echo "$(MACOS_VERSION)" | sed 's/10\.8/10.8/;s/11\./11.0/;s/12\./12.0/;s/13\./13.0/;s/14\./14.0/')

SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: ip2net

android: ip2net

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_MACOS) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

# Single architecture build for MacOS (Darwin) with improved compatibility
mac: $(SRC_FILES)
	@echo "Building ip2net for MacOS (Darwin) target: $(MACOS_TARGET)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	@echo "Note: MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o ip2net \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS) $(LDFLAGS)
	strip ip2net

# Universal binary build for MacOS (Darwin) (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal ip2net for MacOS (Darwin) (x86_64 + arm64)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	@echo "Note: MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o ip2neta \
		-target arm64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o ip2netx \
		-target x86_64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS) $(LDFLAGS)
	strip ip2neta ip2netx
	lipo -create -output ip2net ip2netx ip2neta
	rm -f ip2netx ip2neta

# MacOS build with specific version targeting
mac-$(MACOS_VERSION): $(SRC_FILES)
	@echo "Building ip2net for MacOS (Darwin) $(MACOS_VERSION) with target: $(MACOS_TARGET)"
	@echo "Note: MacOS is NOT BSD - it's a hybrid system with unique characteristics"
	$(CC) $(CFLAGS) $(CFLAGS_MACOS) -o ip2net \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_VERSION) \
		-DMACOS_DARWIN \
		$(SRC_FILES) $(LIBS) $(LDFLAGS)
	strip ip2net

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o ip2net $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f ip2net *.o ip2neta ip2netx

# MacOS specific clean
mac-clean:
	rm -f ip2net *.o ip2neta ip2netx
	@echo "Cleaned MacOS (Darwin) build artifacts"

# Show MacOS build information
mac-info:
	@echo "ip2net MacOS (Darwin) Build Information:"
	@echo "========================================"
	@echo "Target: $(MACOS_TARGET)"
	@echo "Version: $(MACOS_VERSION)"
	@echo "Minimum: $(MACOS_MIN_VERSION)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo ""
	@echo "IMPORTANT: MacOS is NOT BSD - it's a hybrid system with:"
	@echo "  - XNU kernel (Mach + BSD-like layer + Apple components)"
	@echo "  - Unique networking stack and system calls"
	@echo "  - Apple-specific security features (SIP, code signing)"
	@echo "  - Different firewall (PF) and service management (launchd)"
	@echo ""
	@echo "Available targets:"
	@echo "  make mac           - Build for current architecture"
	@echo "  make mac-universal - Build universal binary"
	@echo "  make mac-$(MACOS_VERSION) - Build for specific version"
	@echo "  make mac-clean     - Clean MacOS builds"
	@echo "  make mac-info      - Show this information"
