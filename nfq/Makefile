CC ?= gcc
CFLAGS += -std=gnu99 -O3
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_MAC = -mmacosx-version-min=10.8
CFLAGS_CYGWIN = -Wno-address-of-packed-member -static
LIBS_LINUX = -lnetfilter_queue -lnfnetlink -lz
LIBS_BSD = -lz
LIBS_CYGWIN = -lz -Lwindows/windivert -Iwindows -lwlanapi -lole32 -loleaut32 -luuid
LIBS_CYGWIN32 = -lwindivert32
LIBS_CYGWIN64 = -lwindivert64
RES_CYGWIN32 = windows/res/32/winmanifest.o windows/res/32/winicon.o
RES_CYGWIN64 = windows/res/64/winmanifest.o windows/res/64/winicon.o
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

cygwin64:
	$(CC) -s $(CFLAGS) $(CFLAGS_CYGWIN) -o winws $(SRC_FILES) $(LDFLAGS) $(LIBS_CYGWIN) $(LIBS_CYGWIN64) $(RES_CYGWIN64)
cygwin32:
	$(CC) -s $(CFLAGS) $(CFLAGS_CYGWIN) -o winws $(SRC_FILES) $(LDFLAGS) $(LIBS_CYGWIN) $(LIBS_CYGWIN32) $(RES_CYGWIN32)
cygwin: cygwin64

clean:
	rm -f nfqws dvtws winws.exe
