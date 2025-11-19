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
#include <strings.h> // For strcasecmp, strcasestr
#include <sys/stat.h> // For mkdir
#include <time.h>     // For time_t

#include <netdb.h>

// Thundering Herd Problem
// https://velog.io/@gkdbssla97/Thundering-Herd-Problem%EC%9D%84-%EB%A7%88%EC%A3%BC%EC%B3%A4%EB%8B%A4

// double-checked locking pattern
//https://velog.io/@hmcck27/Double-Checked-Locking

//https://speardragon.github.io/system/system%20programming/System-Programming-6%EC%9E%A5.-%ED%8C%8C%EC%9D%BC-%EB%B0%8F-%EB%A0%88%EC%BD%94%EB%93%9C-%EC%9E%A0%EA%B8%88/
// 파일에 동시에 접근하면 race condition 생겨서 상호배제를 위한
#include <sys/file.h> // For flock.    

#define MAXDATASIZE 10000000
#define RESPONSE_BUF_SIZE 8192
#define BACKLOG 50   // how many pending connections queue will hold

// parsing 을 위한 구조체
typedef struct {
    char host[1024];
    int port;
    char path[4096];
} ParsedRequest;

// https://zoosso.tistory.com/948.  djb2 hash functino
unsigned long hash_str(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

// parsing 하는 함수
// HTTP 요청을 파싱하는 함수
// 성공 시 0, 실패(잘못된 요청) 시 -1 반환
int parse_request(char *buffer, size_t buffer_len, ParsedRequest *req) {
    char method[16], url[4096], version[16];

    // parse request line "GET http://example.com/ HTTP/1.0"
    int sscanf_res = sscanf(buffer, "%s %s %s", method, url, version);
    if (sscanf_res != 3) {
        // fprintf(stderr, "Malformed request line\n");
        return -1;
    }

    // check method, version
    if (strcmp(method, "GET") != 0) {
        // fprintf(stderr, "Invalid method: %s\n", method);
        return -1;
    }
    if (strstr(version, "HTTP/1.0") == NULL) {
        // fprintf(stderr, "Invalid HTTP version: %s\n", version);
        return -1;
    }

    // 3. URL에서 host, port, path 추출
    if (strncmp(url, "http://", 7) != 0) {
        // http:// 로 시작안하면 잘못된 요청
        return -1;
    }
    char *host_ptr = url + 7;

    char *path_ptr = strchr(host_ptr, '/');
    if (path_ptr == NULL) {
        strcpy(req->path, "/");
    } else {
        strncpy(req->path, path_ptr, sizeof(req->path) - 1);
        req->path[sizeof(req->path) - 1] = '\0';
    }

    char *port_ptr = strchr(host_ptr, ':'); // port 가 있을 수도 있으니까
    if (port_ptr != NULL && (path_ptr == NULL || port_ptr < path_ptr)) {
        req->port = atoi(port_ptr + 1);
        strncpy(req->host, host_ptr, port_ptr - host_ptr);
        req->host[port_ptr - host_ptr] = '\0';
    } else { // 없으면 기본포트 80 사용
        req->port = 80; 
        if (path_ptr != NULL) {
            strncpy(req->host, host_ptr, path_ptr - host_ptr);
            req->host[path_ptr - host_ptr] = '\0';
        } else {
            strcpy(req->host, host_ptr);
        }
    }

    // Host 와 URL의 호스트가 일치하는지 확인 다르면 안됌
    char *host_header_start = strcasestr(buffer, "Host:"); //대소문자 무시하고 비교
    if (host_header_start == NULL) {
        // fprintf(stderr, "Host header is missing\n");
        return -1;
    }
    host_header_start += 5; // "Host:" 5개 건너뛰고
    while (*host_header_start == ' ') host_header_start++; // 공백 건너뛰기

    char *host_header_end = strstr(host_header_start, "\r\n");
    if (host_header_end == NULL) host_header_end = strstr(host_header_start, "\n");
    if (host_header_end == NULL) {
        // fprintf(stderr, "Malformed Host header\n");
        return -1;
    }

    char header_host[1024];
    int len = host_header_end - host_header_start;
    if (len >= sizeof(header_host)) {
        // fprintf(stderr, "Host header value too long\n");
        return -1;
    }
    strncpy(header_host, host_header_start, len);
    header_host[len] = '\0';

    char *port_in_header = strchr(header_host, ':');
    if (port_in_header != NULL) {
        *port_in_header = '\0';
    }

    if (strcasecmp(req->host, header_host) != 0) {
        // fprintf(stderr, "Host header does not match URL host\n");
        // fprintf(stderr, "URL host: '%s', Header host: '%s'\n", req->host, header_host);
        return -1;
    }

    if (gethostbyname(req->host) == NULL) { // 호스트 없는거면 잘못된 요청
        // fprintf(stderr, "DNS lookup FAILED for host '%s': %s\n", req->host, hstrerror(h_errno));
        return -1;
    }

    return 0;
}

int send_byte(int sockfd, char *buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent_now = send(sockfd, buf + total_sent, len - total_sent, 0);
        if (sent_now == -1) {
            // perror("send");
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
            else { /* perror("recv"); */ }
            return -1;
        }
        total_received += received_now;
    }
    return 0;
}

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

	// sockfd에서 리슨, new_fd는 새로운 연결용
	int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // 클라이언트의 주소 정보
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

    // 캐시 파일을 저장할 디렉토리 생성
    mkdir("cache", 0755);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // 내 IP 사용

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		// fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// 모든 결과를 순회하며 가능한 첫 번째 주소에 바인드
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				 p->ai_protocol)) == -1) {
			// perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				 sizeof(int)) == -1) {
			// perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			// perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // 이 구조체 사용이 끝났으므로 메모리 해제

	if (p == NULL)  {
		// fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		// perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // 모든 죽은 자식 프로세스 정리
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		// perror("sigaction");
		exit(1);
	}

	// printf("server: waiting for connections...\n");

    while(1) {  // 메인 accept() 루프
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
            &sin_size);
        if (new_fd == -1) {
            // perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        // printf("server: got connection from %s\n", s);

        if (!fork()) { // 자식 프로세스
            close(sockfd); // 자식 프로세스는 리스너 소켓이 필요 없음
			char* buffer = (char*) malloc(MAXDATASIZE + 1);
			size_t total_read = 0;
			ssize_t byte_read;

            //clrf 올때까지 쭉 읽어들임
			while (total_read < MAXDATASIZE) {
				byte_read = recv(new_fd, buffer + total_read, MAXDATASIZE - total_read, 0);
				if (byte_read > 0) {
					total_read += byte_read;
					buffer[total_read] = '\0';

					if (strstr(buffer, "\r\n\r\n")) { 
                        // printf("End of headers reached.\n");
						break;
					}
				} else {
					break;
				}
			}

            //잘 읽었나 확인
			if (byte_read < 0) {
                // perror("recv");
                free(buffer);
                close(new_fd);
                exit(1);
            }

			buffer[total_read] = '\0';
            // request 파싱하기
			ParsedRequest req;
            memset(&req, 0, sizeof(ParsedRequest));

			if (parse_request(buffer, total_read, &req) == 0) {
                // 캐시된 응답이 있는지 확인 cache/{해시값} 형식으로 저장
                // -> expires unix time 확인하고 있으면 있던거 다 쭉 보내기
                // -> 아니면 miss 로 원래 로직으로 하고,
                // 받은거 보고 private 아니고 time 0 아니면 저장
                // printf("Parsed Request: Host=%s, Port=%d, Path=%s\n", req.host, req.port, req.path);
                char full_url[sizeof(req.host) + sizeof(req.path)]; // 1024 + 4096 = 5120
                snprintf(full_url, sizeof(full_url), "%s%s", req.host, req.path); //전체 url 을 구성 -> 나중에 캐싱 된거 있나 확인하는 용도.

                char cache_filepath[1024];
                snprintf(cache_filepath, sizeof(cache_filepath), "cache/%lu", hash_str(full_url)); // cache_filepath 구성

                FILE *cache_file = fopen(cache_filepath, "r"); //파일 열어서
                if (cache_file) {
                    int fd = fileno(cache_file);
                    if (flock(fd, LOCK_SH) == 0) { // 읽기를 위한 shared lock 설정 ( Exclusive Lock 을 얻지 못하는 상태, 읽기는 가능) exclusive lock 에서는 쓰기가능하게
                        time_t expires_at;
                        if (fscanf(cache_file, "%ld\n", &expires_at) == 1 && time(NULL) < expires_at) {
                            // cache hit && 유효한 캐시 인 경우
                            // printf("Cache hit for %s\n", full_url);

                            fseek(cache_file, 0, SEEK_END);
                            long file_size = ftell(cache_file);
                            rewind(cache_file);

                            char *file_content = malloc(file_size + 1);
                            if (file_content) {
                                fread(file_content, 1, file_size, cache_file);
                                file_content[file_size] = '\0';

                                char *response_start = strchr(file_content, '\n');
                                if (response_start) {
                                    response_start++;
                                    long header_len = response_start - file_content;
                                    long response_len = file_size - header_len;
                                    send(new_fd, response_start, response_len, 0);
                                }
                                free(file_content);
                            }
                            flock(fd, LOCK_UN); // 잠금 해제
                            fclose(cache_file);
                            free(buffer);
                            close(new_fd);
                            exit(0);
                        }
                        flock(fd, LOCK_UN); // 잠금 해제
                    }
                    fclose(cache_file);
                }
                // printf("Cache miss for %s\n", full_url);

                // cache miss 원격 서버에 연결
                int remote_sockfd;
                struct hostent *server;
                struct sockaddr_in serv_addr;

                server = gethostbyname(req.host);
                if (server == NULL) {
                    // fprintf(stderr, "ERROR, no such host: %s\n", req.host);
                } else {
                    remote_sockfd = socket(AF_INET, SOCK_STREAM, 0);
                    if (remote_sockfd < 0) {
                        // perror("ERROR opening remote socket");
                    } else {
                        memset(&serv_addr, 0, sizeof(serv_addr));
                        serv_addr.sin_family = AF_INET;
                        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
                        serv_addr.sin_port = htons(req.port);

                        if (connect(remote_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                            // perror("ERROR connecting to remote server");
                        } else {
                            // 원격 서버로 요청 전송
                            char forward_request_buffer[RESPONSE_BUF_SIZE];
                            int new_request_len = snprintf(forward_request_buffer, sizeof(forward_request_buffer),
                                                           "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",
                                                           req.path, req.host);


                            if (send_byte(remote_sockfd, forward_request_buffer, new_request_len) < 0) {
                                // perror("ERROR writing to remote socket");
                            } else {
                                // 원격 서버로부터의 전체 응답을 버퍼에 저장
                                char *response_buffer = malloc(MAXDATASIZE);
                                size_t response_size = 0;
                                ssize_t bytes_received;

                                if (response_buffer) {
                                    while (response_size < MAXDATASIZE && (bytes_received = recv(remote_sockfd, response_buffer + response_size, MAXDATASIZE - response_size, 0)) > 0) {
                                        response_size += bytes_received;
                                    }

                                    if (response_size > 0) {
                                        // 응답이 캐시 가능한지 확인하고 저장
                                        char *cc_header = strcasestr(response_buffer, "Cache-Control:"); // Cache-control 찾기
                                        if (cc_header) {
                                            char *max_age_str = strcasestr(cc_header, "max-age=");
                                            int is_private = (strcasestr(cc_header, "private") != NULL);

                                            if (max_age_str && !is_private) {
                                                int max_age = atoi(max_age_str + 8);
                                                if (max_age > 0) { // age > 0 유효하면 저장
                                                    time_t expires_at = time(NULL) + max_age;
                                                    FILE *cache_write = fopen(cache_filepath, "a+"); // 쓰기용으로 열기 원래 데이터 지우지 않아야함.
                                                    if (cache_write) {
                                                        int fd = fileno(cache_write);

                                                        // fseek(cache_file, 0, SEEK_END); // 파일 끝으로 이동
                                                        // long file_size = ftell(cache_file);
                                                        // rewind(cache_file); // 다시 처음으로

                                                        // int need_fetch = 1;
                                                        // if ( file_size > 0 ) {
                                                        //     //파일내용 있는경우
                                                        //     // 다시 유효한지 확인
                                                        //     time_t expires_at;
                                                        //     if ( fscanf(cache_file, "%ld\n", &expires_at) == 1 && time(NULL) < expires_at ) {
                                                        //         // 유효한 캐시인 경우
                                                        //         need_fetch = 0;
                                                        //     }
                                                        // }


                                                        if( flock(fd, LOCK_EX) == 0 ){
                                                            // printf("Caching response for %s\n", full_url);
                                                            // 파일이 써져있는지 확인해야함
                                                            fseek(cache_write, 0, SEEK_END); // 파일 끝으로 이동
                                                            int file_size = ftell(cache_write);
                                                            rewind(cache_write); // 다시 처음으로

                                                            int need_fetch = 1;

                                                            if( file_size > 0 ){
                                                                time_t expires_at;
                                                                if ( fscanf(cache_write, "%ld\n", &expires_at) == 1 && time(NULL) < expires_at ) {
                                                                    need_fetch = 0;
                                                                }
                                                            }

                                                            if( need_fetch ){
                                                                ftruncate(fd, 0);
                                                                fprintf(cache_write, "%ld\n", expires_at);
                                                                fwrite(response_buffer, 1, response_size, cache_write);
                                                            }
                                                            flock(fd, LOCK_UN);
                                                        }
                                                        fclose(cache_write);
                                                    }
                                                }
                                            }
                                        }
                                        // 받은 응답을 클라이언트에 전송
                                        send_byte(new_fd, response_buffer, response_size);
                                    }
                                    free(response_buffer);
                                }
                            }
                        }
                        close(remote_sockfd);
                    }
                }

            } else {
                // 파싱 실패
                char *error_msg = "HTTP/1.0 400 Bad Request\r\n\r\n";
                send_byte(new_fd, error_msg, strlen(error_msg));
            }

			free(buffer);
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
	return 0;
}