CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
LIBS = -lpthread
LIBS_WIN = -lws2_32
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)
	strip mdig

win: $(SRC_FILES)
	$(CC) $(CFLAGS) -o mdig -static $(SRC_FILES) $(LDFLAGS) $(LIBS_WIN)

clean:
	rm -f mdig *.o
