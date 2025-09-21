/*
** server.c -- a stream socket server demo
from https://beej.us/guide/bgnet/
*/

// 비즈네르 암호 https://www.geeksforgeeks.org/dsa/vigenere-cipher/

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

// #define PORT "3490"  // the port users will be connecting to

#define BACKLOG 50   // how many pending connections queue will hold

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

void encrypt(char* text, size_t text_len ,const char* original_key, uint16_t key_len) {
    int original_key_len = key_len;
    char* valid_key = malloc(original_key_len + 1);
    if (!valid_key) return;

    int valid_key_len = 0;
    for (int i = 0; i < original_key_len; i++) {
        if (isalpha(original_key[i])) {
            valid_key[valid_key_len++] = tolower(original_key[i]);
        }
    }
    valid_key[valid_key_len] = '\0';

    if (valid_key_len == 0) {
        free(valid_key);
        return;
    }

    for (int i = 0, j = 0; i < text_len; i++) {
        if (isalpha(text[i])) {
            char lower_char = tolower(text[i]);
            
            int p_val = lower_char - 'a';
            int k_val = valid_key[j % valid_key_len] - 'a';

            int c_val = (p_val + k_val) % 26;
            
            text[i] = c_val + 'a';
            j++;
        }
    }

    free(valid_key);
}

void decrypt(char* text,size_t text_len,  const char* original_key,uint16_t key_len) {
    // 1. 키 정제 (기존과 동일)
    int original_key_len = key_len;
    char* valid_key = malloc(original_key_len + 1);
    if (!valid_key) return;

    int valid_key_len = 0;
    for (int i = 0; i < original_key_len; i++) {
        if (isalpha(original_key[i])) {
            valid_key[valid_key_len++] = tolower(original_key[i]);
        }
    }
    valid_key[valid_key_len] = '\0';

    if (valid_key_len == 0) {
        free(valid_key);
        return;
    }

    for (int i = 0, j = 0; i < text_len; i++) {
        if (isalpha(text[i])) {
            char lower_char = tolower(text[i]);

            int p_val = lower_char - 'a';
            int k_val = valid_key[j % valid_key_len] - 'a';

            int c_val = (p_val - k_val + 26) % 26;
            
            // [수정] 결과는 항상 소문자가 됩니다.
            text[i] = c_val + 'a';
            j++;
        }
    }

    free(valid_key);
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
    char* port = 0;
    int opt;

    // getopt 루프: 더 이상 처리할 옵션이 없을 때까지 (-1을 반환할 때까지) 반복
    // "h:p:o:k:" -> h, p, o, k 옵션을 받으며, 각 옵션은 값을 필요로 함 (:)
    while ((opt = getopt(argc, argv, "h:p:o:k:")) != -1) {
        switch (opt) {
            case 'p':
                port = optarg; // -p 옵션의 값을 정수로 변환하여 port에 저장
                break;

            default:
                fprintf(stderr, "Usage: %s -h <host> -p <port> -o <operation> -k <key>\n", argv[0]);
                exit(EXIT_FAILURE); // 오류와 함께 프로그램 종료
        }
    }

    // 파싱된 결과 출력
    printf("Connection Details:\n");
    printf("  Port: %s\n", port);
	char* PORT = port;
	char* msg = (char*) malloc(MAXDATASIZE);




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

	while(1) {  // main accept() loop
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
			//자식은 무조건 new fd 만 사용해야지 나랑 연결된 놈이랑 통신할 수 가 있음

			//자식 프로세스만을 위한 버퍼 만들자
			char* buf = (char*)calloc(MAXDATASIZE, 1);

			//메인 코드


			size_t lenbuf;
			
			while( recv(new_fd, buf, MAXDATASIZE, 0) > 0 ){

				char op;
				uint16_t key_length;
				uint32_t data_length;
				char* key;
				char* txt;
				
				// printf("recv: '%s'\n",buf);

				parse_msg(buf, &op, &key_length, &data_length, &key, &txt);
				fwrite(txt, 1, data_length, stdout);

				if( op ){ // decryption
					decrypt(txt,data_length,key,key_length);
				}else{ //encryption
					encrypt(txt,data_length,key,key_length);
				}

				size_t msg_len;
				msg_len = create_msg(op, key_length, data_length, msg, key, txt);

				if (send(new_fd, msg, msg_len, 0) == -1)
					perror("send");

			}

			// if( (lenbuf = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1){
			// 	perror("recv");
			// }

			//다 끝나서 소켓 지우고 나가기
			free(buf);
			close(new_fd);
			exit(0);
		}

		close(new_fd);  // parent doesn't need this
	}
	free(msg);

	return 0;
}

//  while (recv ) 이렇게하면 클라이언트가 종료했을떄 알아서 종료.