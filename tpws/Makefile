CC ?= gcc
CFLAGS += -std=c99 -s -O3
LIBS = -lz -lcap
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f tpws *.o
