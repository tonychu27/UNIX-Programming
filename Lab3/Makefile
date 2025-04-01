CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS = -shared

all: libgotoku.so gotoku.local

libgotoku.so: libgotoku_dummy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

gotoku.local: gotoku.c
	$(CC) $(CFLAGS) -o $@ $< -L. -lgotoku -Wl,-rpath=.

clean:
	rm -f libgotoku.so gotoku.local