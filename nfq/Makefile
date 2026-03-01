CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 $(OPTIMIZE) -flto=auto -ffunction-sections -fdata-sections
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_CYGWIN = -Wno-address-of-packed-member -static
LDFLAGS += -flto=auto
LDFLAGS_ANDROID = -Wl,--gc-sections -llog
LDFLAGS_BSD = -Wl,--gc-sections
LDFLAGS_LINUX = -Wl,--gc-sections
LDFLAGS_MAC = -Wl,-dead_strip
LIBS_LINUX = -lz -lnetfilter_queue -lnfnetlink -lmnl
LIBS_SYSTEMD = -lsystemd
LIBS_BSD = -lz
LIBS_CYGWIN = -lz -Lwindows/windivert -Iwindows -lwlanapi -lole32 -loleaut32
LIBS_CYGWIN32 = -lwindivert32
LIBS_CYGWIN64 = -lwindivert64
RES_CYGWIN32 = windows/res/32/winmanifest.o windows/res/32/winicon.o
RES_CYGWIN64 = windows/res/64/winmanifest.o windows/res/64/winicon.o
SRC_FILES = *.c crypto/*.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS_LINUX) $(LDFLAGS) $(LDFLAGS_LINUX)

systemd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_SYSTEMD) -o nfqws $(SRC_FILES) $(LIBS_LINUX) $(LIBS_SYSTEMD) $(LDFLAGS) $(LDFLAGS_LINUX)

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) -o nfqws $(SRC_FILES) $(LIBS_LINUX) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_BSD) -o dvtws $(SRC_FILES) $(LIBS_BSD) $(LDFLAGS) $(LDFLAGS_BSD)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsa $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS) $(LDFLAGS_MAC)
	$(CC) $(CFLAGS) $(CFLAGS_BSD) -o dvtwsx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS) $(LDFLAGS_MAC)
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
