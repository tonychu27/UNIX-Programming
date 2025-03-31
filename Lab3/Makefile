CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -dynamiclib

all: libgotoku.so

libgotoku.so: libgotoku_dummy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f libgotoku.so gotoku.local 