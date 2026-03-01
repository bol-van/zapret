CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto -ffunction-sections -fdata-sections
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_BSD = -Wno-address-of-packed-member
LDFLAGS += -flto=auto
LDFLAGS_ANDROID = -Wl,--gc-sections -llog
LDFLAGS_BSD = -Wl,--gc-sections
LDFLAGS_LINUX = -Wl,--gc-sections
LDFLAGS_MAC = -Wl,-dead_strip
LIBS = -lz -lpthread
LIBS_SYSTEMD = -lsystemd
LIBS_ANDROID = -lz
SRC_FILES = *.c
SRC_FILES_ANDROID = $(SRC_FILES) andr/*.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES) $(LIBS) $(LDFLAGS) $(LDFLAGS_LINUX)

systemd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_SYSTEMD) -o tpws $(SRC_FILES) $(LIBS) $(LIBS_SYSTEMD) $(LDFLAGS) $(LDFLAGS_LINUX)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES_ANDROID) $(LIBS_ANDROID) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS) $(LDFLAGS_BSD)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsa -target arm64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS) $(LDFLAGS_MAC)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsx -target x86_64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS) $(LDFLAGS_MAC)
	strip tpwsa tpwsx
	lipo -create -output tpws tpwsx tpwsa
	rm -f tpwsx tpwsa

clean:
	rm -f tpws *.o
