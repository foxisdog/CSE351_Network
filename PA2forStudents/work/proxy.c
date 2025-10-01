/*
** server.c -- a stream socket server demo
from https://beej.us/guide/bgnet/
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#define MAXDATASIZE 10000000

int send_byte(int sockfd, char *buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent_now = send(sockfd, buf + total_sent, len - total_sent, 0);
        if (sent_now == -1) {
            perror("send");
            return -1;
        }
        total_sent += sent_now;
    }
    return 0;
}

int recv_byte(int sockfd, char *buf, size_t len) {
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received_now = recv(sockfd, buf + total_received, len - total_received, 0);
        if (received_now <= 0) {
            if (received_now == 0) {} 
            else { perror("recv"); }
            return -1;
        }
        total_received += received_now;
    }
    return 0;
}

#define BACKLOG 50   // how many pending connections queue will hold

size_t create_msg(char op, u_int16_t keylen, u_int32_t datalen, char* to, char* key, char* txt){
	size_t i=0;
	uint16_t* key_length;
	uint32_t* data_length;
	
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


void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
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
	char* PORT;
	if( argc != 2 ){
		exit(1);
	}
	PORT = argv[1];

	// listen on sock_fd, new connection on new_fd
	int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address info
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;


	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) { //? 이거 뭔데?
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop\
		
// crlf 올때까지 읽어야함 -> strstr 로 검색해서 있으면 그만 읽어도 되고 아니면 계속 읽어오는 방식으로 읽기

// 그다음에 읽어왔으면 파싱해서, 유효한지 검증해야함.

// 그다음에 요청해서 데이터 가져오고

// 그 데이터 보내주기.

// 1. 목표는 일단 request 읽어오는거. 그리고 request 를 다시 클라이언트에게 보내주는것 까지.
// 2. 그다음에는 request 유효한지 검증하는거.
// 3. 데이터 요청해서 실제로 받아오는거
// 4. 그다음 나머지.

		// 아래는 더미
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
            &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }
		
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
			char* buffer = (char*) malloc(MAXDATASIZE);
			size_t total_read = 0;
			size_t byte_read;

			while( (byte_read = recv(new_fd, buffer+total_read, MAXDATASIZE - total_read, 0) ) > 0 ){
				total_read += byte_read;
				if (strstr(buffer + total_read - 4, "\r\n\r\n") != NULL) {
					break;
			    }
				printf("total read : %zu\n", total_read);
			}

            if (send(new_fd, buffer, total_read, 0) == -1)
                perror("send");
			free(buffer);
            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

	return 0;
}