CC ?= gcc
CFLAGS += -s
LIBS = 
SRC_FILES = *.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f ip2net *.o
