CC ?= gcc
CFLAGS += -s -O3
LIBS = 
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f mdig *.o
