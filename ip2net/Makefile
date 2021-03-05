CC ?= gcc
CFLAGS += -std=gnu99 -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-logical-op-parentheses -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
STRIP = -s
LIBS = 
SRC_FILES = *.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) $(STRIP) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) $(STRIP) $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)

clean:
	rm -f ip2net *.o
