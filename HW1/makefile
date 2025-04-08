CC = gcc
CFLAGS = -shared -fPIC -g
TARGET = libzpoline.so.1
SRC = libzpoline.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)