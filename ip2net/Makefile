CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_WIN = -static
LIBS = 
LIBS_WIN = -lws2_32
SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2neta $(SRC_FILES) $(LDFLAGS) -target arm64-apple-macos10.8 $(LIBS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2netx $(SRC_FILES) $(LDFLAGS) -target x86_64-apple-macos10.8 $(LIBS)
	strip ip2neta ip2netx
	lipo -create -output ip2net ip2netx ip2neta
	rm -f ip2netx ip2neta

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS_WIN)

clean:
	rm -f ip2net *.o
