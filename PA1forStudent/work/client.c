/*
** client.c -- a stream socket client demo
*/

// https://reakwon.tistory.com/107 getopt

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h> // 엔디안 바꾸는거 정의되어 있음. ntohs(), ntohl(), htons(), htonl()
#include <stdbool.h>

#include <arpa/inet.h>

// #define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 10000000 // max number of bytes we can get at once

int send_byte(int sockfd, char *buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent_now = send(sockfd, buf + total_sent, len - total_sent, 0);
        total_sent += sent_now;
    }
    return 0;
}

int recv_byte(int sockfd, char *buf, size_t len) {
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received_now = recv(sockfd, buf + total_received, len - total_received, 0);
        total_received += received_now;
    }
    return 0;
}


void parse_msg(char* msg, char* op, uint16_t* key_length, uint32_t* data_length, char** key, char** txt) {
    char* ptr = msg;

    *op = *ptr;
    ptr += 2;

    memcpy(key_length, ptr, 2);
    *key_length = ntohs(*key_length);
    ptr += 2;

    // 3. data_length (4 bytes) 파싱
    memcpy(data_length, ptr, sizeof(uint32_t));
    *data_length = ntohl(*data_length);
    ptr += 4;

    *key = (char*)ptr;
    *txt = (char*)ptr + *key_length;
}

size_t create_msg(char op, u_int16_t keylen, u_int32_t datalen, char* to, char* key, char* txt){
	size_t i=0;
	uint16_t* key_length;
	uint32_t* data_length;
	memset(to, 0, MAXDATASIZE);
	
	to[i]= op; // op 1byte
	i+=2;

	key_length = (uint16_t*)(to+i);
	*(key_length) = htons(keylen);
	i+=2;

	data_length = (uint32_t*)(to+i);
	*(data_length) = datalen;
	*(data_length) = htonl(datalen);
	i+=4;

	memcpy( to+i ,key,keylen);
	i+=keylen;


	memcpy(to+i ,txt, datalen);
	i+=datalen;
	return i;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    // 파싱된 인자를 저장할 변수들
    char *host = NULL;
    char* port = 0;
    int operation = -1; // 유효하지 않은 값으로 초기화하여 인자가 들어왔는지 확인
    char *key = NULL;
	uint16_t key_len=0;

    int opt;

    // getopt 루프: 더 이상 처리할 옵션이 없을 때까지 (-1을 반환할 때까지) 반복
    // "h:p:o:k:" -> h, p, o, k 옵션을 받으며, 각 옵션은 값을 필요로 함 (:)
    while ((opt = getopt(argc, argv, "h:p:o:k:")) != -1) {
        switch (opt) {
            case 'h':
                host = optarg; // -h 옵션의 값을 host 변수에 저장
                break;
            case 'p':
                port = optarg; // -p 옵션의 값을 정수로 변환하여 port에 저장
                break;
            case 'o':
                operation = atoi(optarg); // -o 옵션의 값을 정수로 변환
                break;
            case 'k':
                key = optarg; // -k 옵션의 값을 key 변수에 저장
                break;
            default: // '?' 문자가 반환됨: 알 수 없는 옵션 또는 옵션 값 누락
                // 사용법을 stderr(표준 에러)로 출력
                fprintf(stderr, "Usage: %s -h <host> -p <port> -o <operation> -k <key>\n", argv[0]);
                exit(EXIT_FAILURE); // 오류와 함께 프로그램 종료
        }
    }

    // 필수 인자가 모두 입력되었는지 확인
    if (host == NULL || port == 0 || operation == -1 || key == NULL) {
        fprintf(stderr, "Error: All arguments (-h, -p, -o, -k) are required.\n");
        fprintf(stderr, "Usage: %s -h <host> -p <port> -o <operation> -k <key>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 파싱된 결과 출력
    printf("Connection Details:\n");
    printf("  Host: %s\n", host);
    printf("  Port: %s\n", port);
    printf("  Operation: %d\n", operation);
    printf("  Key: %s\n", key);

	key_len = strlen(key);
	char* PORT = port;
// ------------------------------------------------------ 파싱 끝




	int sockfd, numbytes;
	char *buf = (char*) malloc(MAXDATASIZE);
	char *msg = (char*) malloc(MAXDATASIZE);
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	// if (argc != 2) {
	//     fprintf(stderr,"usage: client hostname\n");
	//     exit(1);
	// }

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(host, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

        inet_ntop(p->ai_family,
            get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
        printf("client: attempting connection to %s\n", s);

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family,
			get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connected to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure


	size_t len_read;

	while( (len_read = fread(buf, 1, MAXDATASIZE, stdin)) > 0 ){ //주의 recv 로 한번에 다 안받을 수도 있어서 여러번 반복해야함.
		size_t msg_len;
		msg_len = create_msg(operation, key_len,len_read, msg, key,buf);
		printf("keylen : %hu\n", key_len);

		if ((numbytes = send(sockfd, msg, msg_len, 0)) == -1) { //보내는건 상관 x
			perror("send");
			exit(1);
		}

		// 받을때는 헤더 먼저 받고
		char op;
		uint16_t key_length;
		uint32_t data_length;
		// char* key;
		char* txt;

		size_t total_received = 0;
		size_t received = 0;
		
		recv_byte(sockfd, buf, 8);

		memcpy(&op, buf, 1);
		memcpy(&key_length, buf+2, 2);
		memcpy(&data_length, buf+4, 4);

		key_length = ntohs(key_length);
		data_length = ntohl(data_length);

		recv_byte(sockfd, buf, key_length + data_length);
		fwrite(buf + key_length, 1, data_length, stdout);
	}

	close(sockfd);

	return 0;
}