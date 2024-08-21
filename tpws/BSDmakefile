CC ?= cc
CFLAGS += -std=gnu99 -s -O3
LIBS = -lz -lpthread
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -Iepoll-shim/include -o $@ $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)

clean:
	rm -f tpws *.o
