CC ?= gcc
CFLAGS += -s -O3
LIBS = 
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f tpws *.o
