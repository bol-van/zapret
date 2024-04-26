CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_WIN = -static
LIBS = -lpthread
LIBS_WIN = -lws2_32
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdiga $(SRC_FILES) $(LDFLAGS) -target arm64-apple-macos10.8 $(LIBS_BSD)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdigx $(SRC_FILES) $(LDFLAGS) -target x86_64-apple-macos10.8 $(LIBS_BSD)
	strip mdiga mdigx
	lipo -create -output mdig mdigx mdiga
	rm -f mdigx mdiga

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS_WIN)

clean:
	rm -f mdig *.o
