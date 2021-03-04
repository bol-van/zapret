CC ?= gcc
CFLAGS += -std=gnu99 -s -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-logical-op-parentheses -Wno-switch
LIBS = 
SRC_FILES = *.c

all: ip2net
mac: bsd

ip2net: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LDFLAGS) $(LIBS)

clean:
	rm -f ip2net *.o
