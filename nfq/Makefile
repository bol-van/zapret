CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
LIBS = -lnetfilter_queue -lnfnetlink -lz
LIBS_BSD = -lz
SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o dvtws $(SRC_FILES) $(LDFLAGS) $(LIBS_BSD)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o dvtws $(SRC_FILES) $(LDFLAGS) $(LIBS_BSD)
	strip dvtws

clean:
	rm -f nfqws dvtws *.o
