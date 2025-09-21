CC=gcc
CFLAGS = -g -Wall -std=gnu17
TARGET=client server

# 'make' 명령어를 입력하면 실행될 기본 규칙

all: $(TARGET)

client:	client.o
	$(CC) $(CFLAGS) -o $@ $^
server:	server.o
	$(CC) $(CFLAGS) -o $@ $^

# 실행 파일을 만드는 규칙
client.o:	client.c
	$(CC) $(CFLAGS) -c -o $@ $^

server.o:	server.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f *.o $(TARGET)