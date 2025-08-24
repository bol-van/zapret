CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = 
LIBS_BSD = 
LIBS_WIN = -lws2_32

# MacOS target detection with improved compatibility
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

# Detect MacOS version for better compatibility
MACOS_VERSION ?= $(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo "10.8")

# Set minimum MacOS version based on detected version
MACOS_MIN_VERSION := $(shell echo "$(MACOS_VERSION)" | sed 's/10\.8/10.8/;s/11\./11.0/;s/12\./12.0/;s/13\./13.0/;s/14\./14.0/')

SRC_FILES = mdig.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: mdig

android: mdig

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)

# Single architecture build for MacOS with improved compatibility
mac: $(SRC_FILES)
	@echo "Building mdig for MacOS target: $(MACOS_TARGET)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdig \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		$(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	strip mdig

# Universal binary build for MacOS (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal mdig for MacOS (x86_64 + arm64)"
	@echo "MacOS version: $(MACOS_VERSION), minimum: $(MACOS_MIN_VERSION)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdiga \
		-target arm64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		$(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdigx \
		-target x86_64-apple-macos$(MACOS_MIN_VERSION) \
		-mmacosx-version-min=$(MACOS_MIN_VERSION) \
		$(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	strip mdiga mdigx
	lipo -create -output mdig mdigx mdiga
	rm -f mdigx mdiga

# MacOS build with specific version targeting
mac-$(MACOS_VERSION): $(SRC_FILES)
	@echo "Building mdig for MacOS $(MACOS_VERSION) with target: $(MACOS_TARGET)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdig \
		-target $(MACOS_TARGET) \
		-mmacosx-version-min=$(MACOS_VERSION) \
		$(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	strip mdig

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o mdig $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f mdig *.o mdiga mdigx

# MacOS specific clean
mac-clean:
	rm -f mdig *.o mdiga mdigx
	@echo "Cleaned MacOS build artifacts"

# Show MacOS build information
mac-info:
	@echo "mdig MacOS Build Information:"
	@echo "============================="
	@echo "Target: $(MACOS_TARGET)"
	@echo "Version: $(MACOS_VERSION)"
	@echo "Minimum: $(MACOS_MIN_VERSION)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "Available targets:"
	@echo "  make mac           - Build for current architecture"
	@echo "  make mac-universal - Build universal binary"
	@echo "  make mac-$(MACOS_VERSION) - Build for specific version"
	@echo "  make mac-clean     - Clean MacOS builds"
	@echo "  make mac-info      - Show this information"
