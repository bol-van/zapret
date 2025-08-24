CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = 
LIBS_BSD = 
LIBS_WIN = -lws2_32

# MacOS target detection
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

SRC_FILES = mdig.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: mdig

android: mdig

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)

# Single architecture build for MacOS
mac: $(SRC_FILES)
	@echo "Building mdig for MacOS target: $(MACOS_TARGET)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdig -target $(MACOS_TARGET) $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	strip mdig

# Universal binary build for MacOS (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal mdig for MacOS (x86_64 + arm64)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdiga $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdigx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	strip mdiga mdigx
	lipo -create -output mdig mdigx mdiga
	rm -f mdigx mdiga

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o mdig $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f mdig *.o mdiga mdigx
