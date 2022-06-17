CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
LIBS = 
LIBS_WIN = -lws2_32
SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)
	strip ip2net

win: $(SRC_FILES)
	$(CC) $(CFLAGS) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS_WIN)

clean:
	rm -f ip2net *.o
