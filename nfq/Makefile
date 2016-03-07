CC = gcc
CFLAGS = -s
LIBS = -lnetfilter_queue -lnfnetlink
SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f nfqws *.o
