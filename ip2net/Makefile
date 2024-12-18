CC ?= gcc
CFLAGS += -std=gnu99 -Os -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = 
LIBS_WIN = -lws2_32
SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

android: ip2net

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2neta $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2netx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS) $(LDFLAGS)
	strip ip2neta ip2netx
	lipo -create -output ip2net ip2netx ip2neta
	rm -f ip2netx ip2neta

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o ip2net $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f ip2net *.o
