CC = gcc
CFLAGS = -shared -fPIC -g
TARGET = libzpoline.so
SRC = libzpoline.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)