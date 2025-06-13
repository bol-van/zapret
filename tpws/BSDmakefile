CC ?= cc
OPTIMIZE ?= -Os
CFLAGS += -std=gnu99 -s $(OPTIMIZE) -flto=auto
LIBS = -lz -lpthread
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LIBS) $(LDFLAGS)

clean:
	rm -f tpws *.o
