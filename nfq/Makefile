CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_BSD = -Wno-address-of-packed-member
LDFLAGS_ANDROID = -llog
LIBS = -lz -lpthread -lnetfilter_queue -lmnl
LIBS_SYSTEMD = -lsystemd
LIBS_BSD = -lz -lpthread
LIBS_ANDROID = -lz

# MacOS target detection
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_SYSTEMD) -o nfqws $(SRC_FILES) $(LIBS) $(LIBS_SYSTEMD) $(LDFLAGS)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS_ANDROID) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o dvtws $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)

# Single architecture build for MacOS
mac: $(SRC_FILES)
	@echo "Building dvtws for MacOS target: $(MACOS_TARGET)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtws -target $(MACOS_TARGET) $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)
	strip dvtws

# Universal binary build for MacOS (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal dvtws for MacOS (x86_64 + arm64)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsa $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	strip dvtwsa dvtwsx
	lipo -create -output dvtws dvtwsx dvtwsa
	rm -f dvtwsx dvtwsa

clean:
	rm -f nfqws dvtws *.o dvtwsa dvtwsx
