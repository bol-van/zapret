CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 -s $(OPTIMIZE) -flto=auto -Wno-address-of-packed-member
LIBS = -lz
SRC_FILES = *.c crypto/*.c

all: dvtws

dvtws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o dvtws $(SRC_FILES) $(LIBS) $(LDFLAGS)

clean:
	rm -f dvtws
