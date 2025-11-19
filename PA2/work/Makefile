CC=gcc
CFLAGS = -g -Wall -std=gnu17
TARGET=proxy

all: $(TARGET)

proxy: proxy.o
	$(CC) $(CFLAGS) -o $@ $^

proxy.o: proxy.c
	$(CC) $(CFLAGS) -c -o $@ $^
	
clean:
	rm -f *.o $(TARGET)
