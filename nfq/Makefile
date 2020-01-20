CC ?= gcc
CFLAGS += -std=c99 -s -O3
LIBS = -lnetfilter_queue -lnfnetlink -lcap -lz
SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f nfqws *.o
