CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = 
LIBS_WIN = -lws2_32

# MacOS target detection
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: ip2net

android: ip2net

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

# Single architecture build for MacOS
mac: $(SRC_FILES)
	@echo "Building ip2net for MacOS target: $(MACOS_TARGET)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2net -target $(MACOS_TARGET) $(SRC_FILES) $(LIBS) $(LDFLAGS)
	strip ip2net

# Universal binary build for MacOS (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal ip2net for MacOS (x86_64 + arm64)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2neta $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2netx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS) $(LDFLAGS)
	strip ip2neta ip2netx
	lipo -create -output ip2net ip2netx ip2neta
	rm -f ip2netx ip2neta

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o ip2net $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f ip2net *.o ip2neta ip2netx
