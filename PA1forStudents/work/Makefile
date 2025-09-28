CC=gcc
CFLAGS = -g -Wall -std=gnu17
TARGET=client server

all: $(TARGET)

client: client.o
	$(CC) $(CFLAGS) -o $@ $^

# -lrt 라이브러리 링크 추가
server:	server.o
	$(CC) $(CFLAGS) -o $@ $^ -pthread -lrt


client.o: client.c
	$(CC) $(CFLAGS) -c -o $@ $^

server.o: server.c
	$(CC) $(CFLAGS) -c -o $@ $^ -pthread

clean:
	rm -f *.o $(TARGET)
