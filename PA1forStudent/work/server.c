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
#include <semaphore.h>

#include <fcntl.h>
#include <sys/mman.h> 
#include <fcntl.h>
#include <sys/mman.h>

const char* SHM_NAME = "/my_shm_server";


#define MAXDATASIZE 10000000

struct shared_data { // 50 개인지 확인하는 친구 동기화문제 떄문에 세마포어 사용.
    sem_t mutex;
    int active_clients;
};

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

/* 
connect()
핸드쉐이크
연결 큐에 들어가고 이게 backlog 값인거고
accept() 함수는 fd 를 할당하고
지금 fork 하고 있는 상황
-> accept() 하고 그냥 죽여버리면 된다.
*/

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

// #define PORT "3490"  // the port users will be connecting to

#define BACKLOG 50   // how many pending connections queue will hold

// void parse_msg(char* msg, char* op, uint16_t* key_length, uint32_t* data_length, char** key, char** txt) {
//     char* ptr = msg;

//     *op = *ptr;
//     ptr += 2;

//     memcpy(key_length, ptr, 2);
//     *key_length = ntohs(*key_length);
//     ptr += 2;

//     memcpy(data_length, ptr, sizeof(uint32_t));
//     *data_length = ntohl(*data_length);
//     ptr += 4;

//     *key = (char*)ptr;
//     *txt = (char*)ptr + *key_length;
// }


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

    while ((opt = getopt(argc, argv, "p:")) != -1) {
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
    // printf("Connection Details:\n");
    // printf("  Port: %s\n", port);
	char* PORT = port;




	// listen on sock_fd, new connection on new_fd
	int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address info
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;




	// --- POSIX 공유 메모리 및 세마포어 설정으로 변경 ---
    int shm_fd;
    struct shared_data *shm_ptr;

    // 1. 공유 메모리 객체 생성
    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(1);
    }

    // 2. 공유 메모리 크기 설정
    if (ftruncate(shm_fd, sizeof(struct shared_data)) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // 3. 메모리 맵핑
    shm_ptr = mmap(0, sizeof(struct shared_data), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    
    // 4. 세마포어 초기화 (프로세스 간 공유: 두 번째 인자 '1')
    if (sem_init(&shm_ptr->mutex, 1, 1) == -1) {
        perror("sem_init");
        exit(1);
    }
    shm_ptr->active_clients = 0;
    // --- 설정 끝 ---





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

		//accept 한  다음에 자식 개수 세어가지고 50 넘으면 튕겨내기
		sem_wait(&shm_ptr->mutex);
		if (shm_ptr->active_clients >= 50) {
			sem_post(&shm_ptr->mutex);
			close(new_fd);
			continue;
		}
		shm_ptr->active_clients++;
		sem_post(&shm_ptr->mutex);


		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			//자식은 무조건 new fd 만 사용해야지 나랑 연결된 놈이랑 통신할 수 가 있음

			//자식 프로세스만을 위한 버퍼 만들자
			char* buf = (char*)calloc(MAXDATASIZE, 1);
			char* msg = (char*) malloc(MAXDATASIZE);
			//메인 코드


			while( 1 ){

				if( recv_byte(new_fd, buf, 8) == -1 ){
					break;
				}

				char op;
				uint16_t key_length;
				uint32_t data_length;
				char* key;
				char* txt;

				
				memcpy(&op, buf, 1);
				memcpy(&key_length, buf+2, 2);
				memcpy(&data_length, buf+4, 4);

				key_length = ntohs(key_length);
				data_length = ntohl(data_length);

				//메세지 유효한지 검증
				if(8 + key_length + data_length > MAXDATASIZE){
					break;
				}

				if (recv_byte(new_fd, buf, key_length + data_length) == -1){
					break;
				}

				key = buf;
				txt = buf+key_length;

				if( op ){ // decryption
					decrypt(txt,data_length,key,key_length);
				}else{ //encryption
					encrypt(txt,data_length,key,key_length);
				}

				size_t msg_len;
				msg_len = create_msg(op, key_length, data_length, msg, key, txt);

				if (send_byte(new_fd, msg, msg_len) == -1) {
					break;
				}
			}

			// if( (lenbuf = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1){
			// 	perror("recv");
			// }

			//다 끝나서 소켓 지우고 나가기
			free(buf);

			sem_wait(&shm_ptr->mutex);
			shm_ptr->active_clients--;
			sem_post(&shm_ptr->mutex);

			close(new_fd);
			free(msg);
			exit(0);
		}

		close(new_fd);  // parent doesn't need this
	}
	munmap(shm_ptr, sizeof(struct shared_data));
    shm_unlink(SHM_NAME);


	return 0;
}