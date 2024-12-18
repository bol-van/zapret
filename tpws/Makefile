CC ?= gcc
CFLAGS += -std=gnu99 -Os -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
LIBS = -lz -lpthread
LIBS_ANDROID = -lz
SRC_FILES = *.c
SRC_FILES_ANDROID = $(SRC_FILES) andr/*.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES) $(LIBS) $(LDFLAGS)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o tpws $(SRC_FILES_ANDROID) $(LIBS_ANDROID) $(LDFLAGS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsa -target arm64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsx -target x86_64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)
	strip tpwsa tpwsx
	lipo -create -output tpws tpwsx tpwsa
	rm -f tpwsx tpwsa

clean:
	rm -f tpws *.o
