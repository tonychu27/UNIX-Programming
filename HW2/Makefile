CC=g++
CFLAGS=-g -Wall
TARGET=sdb

$(TARGET): main.cpp
	$(CC) $(CFLAGS) main.cpp -o $(TARGET) -lcapstone 

all: $(TARGET)

clean:
	rm -f $(TARGET)