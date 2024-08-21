CC ?= gcc
CFLAGS += -std=gnu99 -O3
CFLAGS_BSD = -Wno-address-of-packed-member
LIBS = -lz -lpthread
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsa -target arm64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -Imacos -o tpwsx -target x86_64-apple-macos10.8 $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)
	strip tpwsa tpwsx
	lipo -create -output tpws tpwsx tpwsa
	rm -f tpwsx tpwsa

clean:
	rm -f tpws *.o
