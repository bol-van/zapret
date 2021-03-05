CC ?= gcc
CFLAGS += -std=gnu99 -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-logical-op-parentheses -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
STRIP = -s
LIBS = -lz
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(STRIP) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) $(STRIP) $(CFLAGS) $(CFLAGS_BSD) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) $(CFLAGS_MAC) -Iepoll-shim/include -Imacos -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)
	strip tpws

clean:
	rm -f tpws *.o
