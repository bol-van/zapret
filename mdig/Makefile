CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE)
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = -lpthread
LIBS_ANDROID =
LIBS_WIN = -lws2_32
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS)

systemd: mdig

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LIBS_ANDROID) $(LDFLAGS)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdiga $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o mdigx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	strip mdiga mdigx
	lipo -create -output mdig mdigx mdiga
	rm -f mdigx mdiga

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o mdig $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f mdig *.o
