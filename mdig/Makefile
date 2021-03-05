CC ?= gcc
CFLAGS += -std=gnu99 -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-logical-op-parentheses -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
LIBS = -lpthread
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)
	strip mdig

clean:
	rm -f mdig *.o
