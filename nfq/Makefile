CFLAGS=-Wall
LIBS=-lnetfilter_queue -lnfnetlink

all: nfqws

nfqws: nfqws.o
	$(CC) $(CFLAGS) -o "$@" $< $(LIBS) 

nfqws.o: nfqws.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o nfqws
