CC ?= gcc
CFLAGS += -std=gnu99 -Os
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LIBS = -lpthread
LIBS_ANDROID =
LIBS_WIN = -lws2_32
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o mdig $(SRC_FILES) $(LDFLAGS) $(LIBS_ANDROID)

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
