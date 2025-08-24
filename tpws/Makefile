CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_BSD = -Wno-address-of-packed-member
LDFLAGS_ANDROID = -llog
LIBS = -lz -lpthread
LIBS_SYSTEMD = -lsystemd
LIBS_ANDROID = -lz

# MacOS target detection
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

SRC_FILES = *.c
SRC_FILES_ANDROID = $(SRC_FILES) andr/*.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_SYSTEMD) -o tpws $(SRC_FILES) $(LIBS) $(LIBS_SYSTEMD) $(LDFLAGS)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES_ANDROID) $(LIBS_ANDROID) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)

# Single architecture build for MacOS
mac: $(SRC_FILES)
	@echo "Building tpws for MacOS target: $(MACOS_TARGET)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpws -target $(MACOS_TARGET) $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)
	strip tpws

# Universal binary build for MacOS (both architectures)
mac-universal: $(SRC_FILES)
	@echo "Building universal tpws for MacOS (x86_64 + arm64)"
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsa -target arm64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsx -target x86_64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)
	strip tpwsa tpwsx
	lipo -create -output tpws tpwsx tpwsa
	rm -f tpwsx tpwsa

clean:
	rm -f tpws *.o tpwsa tpwsx
