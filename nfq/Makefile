CC ?= gcc
CFLAGS += -std=gnu99 -Wno-logical-op-parentheses -O3
CFLAGS_BSD = -Wno-address-of-packed-member -Wno-switch
CFLAGS_MAC = -mmacosx-version-min=10.8
CFLAGS_CYGWIN = -Wno-address-of-packed-member -static
LIBS_LINUX = -lnetfilter_queue -lnfnetlink -lz
LIBS_BSD = -lz
LIBS_CYGWIN = -lz -Lwindivert -lwindivert -lwlanapi -lole32 -loleaut32 -luuid
SRC_FILES = *.c crypto/*.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS_LINUX)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o dvtws $(SRC_FILES) $(LDFLAGS) $(LIBS_BSD)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsa $(SRC_FILES) $(LDFLAGS) -target arm64-apple-macos10.8 $(LIBS_BSD)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsx $(SRC_FILES) $(LDFLAGS) -target x86_64-apple-macos10.8 $(LIBS_BSD)
	strip dvtwsa dvtwsx
	lipo -create -output dvtws dvtwsx dvtwsa
	rm -f dvtwsx dvtwsa

cygwin:
	$(CC) -s $(CFLAGS) $(CFLAGS_CYGWIN) -o winws $(SRC_FILES) $(LDFLAGS) $(LIBS_CYGWIN) winmanifest.o winicon.o

clean:
	rm -f nfqws dvtws winws.exe
