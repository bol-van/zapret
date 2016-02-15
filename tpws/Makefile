CC = gcc
CFLAGS = 
LIBS = 
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f tpws *.o

.PHONY: clean
