CC ?= gcc
CFLAGS += -std=gnu99 -Os -flto=auto
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_CYGWIN = -Wno-address-of-packed-member -static
LIBS_LINUX = -lnetfilter_queue -lnfnetlink -lz
LIBS_BSD = -lz
LIBS_CYGWIN = -lz -Lwindows/windivert -Iwindows -lwlanapi -lole32 -loleaut32
LIBS_CYGWIN32 = -lwindivert32
LIBS_CYGWIN64 = -lwindivert64
RES_CYGWIN32 = windows/res/32/winmanifest.o windows/res/32/winicon.o
RES_CYGWIN64 = windows/res/64/winmanifest.o windows/res/64/winicon.o
SRC_FILES = *.c crypto/*.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS_LINUX) $(LDFLAGS)

android: nfqws

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o dvtws $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsa $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS)
	strip dvtwsa dvtwsx
	lipo -create -output dvtws dvtwsx dvtwsa
	rm -f dvtwsx dvtwsa

cygwin64:
	$(CC) -s $(CFLAGS) $(CFLAGS_CYGWIN) -o winws $(SRC_FILES) $(LIBS_CYGWIN) $(LIBS_CYGWIN64) $(RES_CYGWIN64) $(LDFLAGS)
cygwin32:
	$(CC) -s $(CFLAGS) $(CFLAGS_CYGWIN) -o winws $(SRC_FILES) $(LIBS_CYGWIN) $(LIBS_CYGWIN32) $(RES_CYGWIN32) $(LDFLAGS)
cygwin: cygwin64

clean:
	rm -f nfqws dvtws winws.exe
