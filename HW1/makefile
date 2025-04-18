CC = gcc
CFLAGS = -shared -fPIC -g -pipe -fno-stack-protector
LDFLAGS = -lopcodes -ldl 
TARGET = libzpoline.so
SRC = libzpoline.c

LOGGER_TARGET = logger.so
LOGGER_SRC = logger.c

all: $(TARGET) $(LOGGER_TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(LOGGER_TARGET): $(LOGGER_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) $(LOGGER_TARGET)