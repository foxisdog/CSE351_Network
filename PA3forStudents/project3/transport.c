/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"



enum {
    CSTATE_LISTEN, // passive open
    CSTATE_SYN_SENT, // active open
    CSTATE_SYN_RCVD, // SYN received
    CSTATE_ESTABLISHED, // connection established
    CSTATE_FIN_WAIT_1, // active close
    CSTATE_FIN_WAIT_2, // wait for FIN from peer
    CSTATE_CLOSE_WAIT, // passive close
    CSTATE_CLOSING, // simultaneous close
    CSTATE_LAST_ACK, // wait for ACK of FIN
    CSTATE_CLOSED, // connection closed
    CSTATE_TIME_WAIT // wait for 2* maximum segment lifetime
};    /* obviously you should have more states 여기에 state 추가해야함 /


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    tcp_seq myseqnum; // 다음에 사용할 시퀀스 번호
    tcp_seq peerseqnum; // 상대방이 보낸 시퀀스 번호 state 를 저장하는게 더 좋음.

    tcp_seq last_peer_ack; // 마지막으로 상대방이 ack 보낸 번호
    
    bool_t ack_pending; // ack 보낸지 말지
    int packets_since_ack; // ack 보낸 이후로 받은 패킷 수
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void init_tcphdr(
    struct tcphdr* hdr,
    // uint16_t src_port, uint16_t dst_port,
    tcp_seq seq_num,
    tcp_seq ack_num,
    uint8_t th_flags
);

//ref http://www.ktword.co.kr/test/view/view.php?m_temp1=1889
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
// typedef struct{ // flag 는 비트필드로 하는게 좋겠다.
//     uint16_t src_port;
//     uint16_t dst_port;
//     uint32_t seq_num;
//     uint32_t ack_num;
    
//     uint16_t data_offset;
//     uint16_t th_flags;
//     uint16_t window_size;
// } packet;

#define WINDOWSIZE 3072

//act 전송 함수
static void send_ack(mysocket_t sd, context_t *ctx){
    char send_buf[sizeof(struct tcphdr)];
    struct tcphdr* send_hdr = (struct tcphdr*) send_buf;

    init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_ACK);
    stcp_network_send( sd, send_hdr, sizeof(struct tcphdr), NULL );
}

static void init_tcphdr(
    struct tcphdr* hdr,
    // uint16_t src_port, uint16_t dst_port,
    tcp_seq seq_num,
    tcp_seq ack_num,
    uint8_t th_flags
){
    memset(hdr, 0, sizeof(struct tcphdr));

    // hdr->th_sport = htons(src_port); 이거는 stcp_network_send()
    // hdr->th_dport = htons(dst_port);
    hdr->th_seq = htonl(seq_num);
    hdr->th_ack = htonl(ack_num);
    hdr->th_off = 5; // Data Offset 데이터 시작하는 위치 : 헤더 크기
    hdr->th_flags = th_flags;
    hdr->th_win = htons(WINDOWSIZE);
}

// acknum의 역할은 당신이 보낸 데이터를 여기까지 잘 받았으니, 이제 이 번호부터 시작하는 데이터를 보내주세요라고 상대방에게 알려주는 것
// vs peerseqnum : 

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active) // active : client, passive : server
{
    context_t *ctx; // transport layer 에서 사용하는 전역 변수 담고 있는 구조체

    ctx = (context_t *) calloc(1, sizeof(context_t)); // 동적할당 나중에 해제 필요함.
    assert(ctx);

    generate_initial_seq_num(ctx); // initial_sequence num 을 1 로 바꿈.
    ctx->myseqnum = ctx->initial_sequence_num; // 내 시퀀스 번호 설정
    ctx->peerseqnum = 0; // 상대방 시퀀스 번호 설정

    // 여기에는 TCP 3-way handshake 구현 필요함.
    // 3-way handshake 구조 
    // 클라이언트 : SYN -> 서버 / 보내는 정보 : seq num / seq num = initial_sequence num / 클라이언트 state : SYN_SENT
    // 서버 : SYN + ACK -> 클라이언트 / 보내는 정보 : seq num, ack num / ack num = 클라이언트가 보낸 seq num + 1 / 서버 state : SYN_RCVD
    // 클라이언트 : ACK -> 서버 / 보내는 정보 : seq num, ack num / ack num = 서버가 보낸 seq num + 1 / 클라이언트 state : ESTABLISHED / 서버 state : ESTABLISHED

    // tcphdr 구조체가 tcp 헤더 구조체임.
    size_t maxlen = ( sizeof( struct tcphdr ) + STCP_MSS);
    size_t recv_len;
    char recv_buff[maxlen]; // 패킷 받을 버퍼
    struct tcphdr* recv_hdr = ( struct tcphdr* ) recv_buff;

    size_t send_len;
    char send_buff[maxlen]; // 패킷 받을 버퍼
    struct tcphdr* send_hdr = ( struct tcphdr* ) send_buff;


    if (is_active){ // active open : client
        ctx->connection_state = CSTATE_SYN_SENT; // state 변경 SYS_SENT 로 변경하고

        init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_SYN); // SYN 패킷 초기화
        stcp_network_send(sd, send_hdr, sizeof(struct tcphdr), NULL); // 서버에 SYN 패킷 보냄       stcp_network_send(mysd, buf1, len1, buf2, len2, NULL); 이런식으로 끝에 NULL 붙여서 호출, 여러개 가능
        ctx->myseqnum++; // 내 시퀀스 번호 업데이트 

        recv_len = stcp_network_recv(sd, recv_buff, maxlen ); // 서버로 부터 SYN + ACK 패킷 받음
        
        if (recv_len >= sizeof(struct tcphdr) &&
        (recv_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && // SYN, ACK 플래그 확인
        ntohl(recv_hdr->th_ack) == ctx->myseqnum){
            ctx->connection_state = CSTATE_ESTABLISHED; // state 변경 ESTABLISHED 로 변경

            ctx->peerseqnum = ntohl(recv_hdr->th_seq) + 1; // 상대방 seq num 저장

            init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_ACK); // ACK 패킷 초기화
            stcp_network_send( sd, send_hdr, sizeof(struct tcphdr), NULL ); // 서버에 ACK 패킷 보냄

            ctx->last_peer_ack = ctx->myseqnum;
            ctx->ack_pending = FALSE;
            ctx->packets_since_ack = 0;
        }else{
            // 3-way handshake 실패 처리 필요하지만 일단 패스
        }
    }else{ // passive open : server
        ctx->connection_state = CSTATE_LISTEN; // state 변경 LISTEN

        recv_len = stcp_network_recv(sd, recv_buff, maxlen); // 클라이언트로 부터 SYN 패킷 받음
        
        if( recv_len >= sizeof(struct tcphdr) &&
            (recv_hdr->th_flags & TH_SYN) == TH_SYN ){
                ctx->peerseqnum = ntohl(recv_hdr->th_seq) + 1;
                ctx->connection_state = CSTATE_SYN_RCVD; // state 변경 SYN_RCVD
        }


        init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_SYN | TH_ACK ); // SYN + ACK 패킷 초기화
        stcp_network_send( sd, send_hdr, sizeof(struct tcphdr), NULL ); // 클라이언트에 SYN + ACK 패킷 보냄
        ctx->myseqnum++; // 내 시퀀스 번호 업데이트
        

        recv_len = stcp_network_recv( sd, recv_buff, maxlen); // 클라이언트로 부터 ACK 패킷 받음
        if( recv_len >= sizeof(struct tcphdr) &&
            (recv_hdr->th_flags & TH_ACK) == TH_ACK &&
            ntohl(recv_hdr->th_ack) == ctx->myseqnum &&
            ntohl(recv_hdr->th_seq) == ctx->peerseqnum
        ){
            // ctx->peerseqnum = ntohl(recv_hdr->th_seq); // 상대방 seq num 저장
            ctx->connection_state = CSTATE_ESTABLISHED; // state 변경 ESTABLISHED

            ctx->last_peer_ack = ctx->myseqnum;
            ctx->ack_pending = FALSE;
            ctx->packets_since_ack = 0;
        }
    }

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx); // ctx 해제
}


/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx) // transport_init 에서 호출됨 // 데이터 전송
{
    assert(ctx);

    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000;

    while (!ctx->done)
    {
        unsigned int event;
        
        //보내고 받을 때 쓸 버퍼 선언
        char send_buff[sizeof(struct tcphdr) + STCP_MSS];
        struct tcphdr* send_hdr = (struct tcphdr*) send_buff;
        char* send_payload = send_buff + sizeof(struct tcphdr);

        char recv_buff[sizeof(struct tcphdr) + STCP_MSS];
        struct tcphdr* recv_hdr = (struct tcphdr*) recv_buff;
        char* recv_payload = recv_buff + sizeof(struct tcphdr);


        

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(
            sd,
            ANY_EVENT,
            ( ctx->ack_pending ) ? &timeout : NULL
        ); // 0의미 : 아무 이벤트도 기다리지 않음, ANYEVENT 의미 : 모든 이벤트 기다림 // 나중에 timeout 필요하면 바꾸기
        // 구조 보면 안에서 queue 로 head 체크해서 이벤트 있다 없다 알려줌.

        // 여기 아래에는 이벤트 처리 코드 작성함.
        // active close, passive close, 데이터 수신, 데이터 전송
        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA) // 이벤트가 application layer 로 부터 온 데이터인 경우 -> data 를 보내야함
        {
            tcp_seq unacked_data = ctx->myseqnum - ctx->last_peer_ack;
            if ( unacked_data > WINDOWSIZE ) continue; // 윈도우 사이즈 초과하면 데이터 못 보냄
            uint32_t available_window = WINDOWSIZE - unacked_data;
            if (available_window == 0) continue; // 윈도우 사이즈가 0 이면 데이터 못 보냄

            size_t bytes_to_send = MIN( STCP_MSS, available_window); // 보낼 수 있는 최대 데이터 크기

            char app_buff[STCP_MSS]; //application layer 로 부터 받을 버퍼 준비해서

            ssize_t bytes_read = stcp_app_recv(sd, app_buff, bytes_to_send); // app 에서 데이터 받아옴. // queue 에서 데이터 뽑아오는거임.

            if ( bytes_read <= 0 ) continue; // 데이터 못읽어오면 패스

            char send_buff[sizeof(struct tcphdr)];
            struct tcphdr* send_hdr = (struct tcphdr*) send_buff;

            init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_ACK); // ack 플래그 설정
            stcp_network_send( sd, send_hdr, sizeof( struct tcphdr), app_buff, bytes_read, NULL );

            ctx->myseqnum += bytes_read; // 내 시퀀스 번호 업데이트
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            // stcp_app_recv(sd, NULL, 0); // app layer 로 부터 데이터를받아옴?

        }

        if ( event & NETWORK_DATA) // 이벤트가 network layer 로 부터 온 데이터인 경우 -> data 를 받아야함
        {
            char recv_buf[sizeof(struct tcphdr) + STCP_MSS];
            struct tcphdr* recv_hdr = (struct tcphdr*) recv_buf;
            ssize_t recv_len = stcp_network_recv(sd, recv_buf, sizeof(recv_buf)); // network layer 로 부터 데이터를받아옴
            
            if(recv_len < sizeof(struct tcphdr)) continue; // 헤더 크기보다 작으면 패스

            //헤더 파싱
            size_t header_len = recv_hdr->th_off * 4; // 헤더 길이
            size_t payload_len = recv_len - header_len; // 페이로드 길이

            char* payload = recv_buf + header_len; // 페이로드 시작 위치

            tcp_seq recv_seqnum = ntohl(recv_hdr->th_seq); // 상대방 시퀀스 번호
            tcp_seq recv_acknum = ntohl(recv_hdr->th_ack); // 상대방 ack 번호
            uint8_t recv_flags = recv_hdr->th_flags; // 플래그


            if ( recv_flags & TH_FIN ){ // passive close + 그외 여러 귀찮은 경우 다 있음
                stcp_fin_received( sd ); // app layer 에 fin 도착 알림
                ctx->peerseqnum++;
                
                if( ctx->connection_state == CSTATE_ESTABLISHED ){ //server 가 fin 받은 경우
                    send_ack( sd, ctx ); // ack 전송
                    ctx->connection_state = CSTATE_CLOSE_WAIT; // state 변경
                }
                if( ctx->connection_state == CSTATE_FIN_WAIT_1 ){ // 클라이언트에서 fin 받은거임  이러면 둘다 보낼거 다보낸거니까 TIME_WAIT 로 바로 감.
                    send_ack( sd, ctx ); // ack 전송
                    ctx->connection_state = CSTATE_CLOSING; // state 변경
                    ctx->connection_state = CSTATE_TIME_WAIT; // state 변경
                    ctx->done = TRUE; // 루프 탈출
                }
                if( ctx->connection_state == CSTATE_FIN_WAIT_2 ){
                    send_ack( sd, ctx ); // ack 전송
                    ctx->connection_state = CSTATE_TIME_WAIT; // state 변경
                    ctx->done = TRUE; // 루프 탈출
                }

            }

            if ( recv_flags & TH_ACK ){
                if ( recv_acknum > ctx->last_peer_ack ){ // 새로운 ack 이면 그걸로 갱신
                    ctx->last_peer_ack = recv_acknum;
                }
                if ( ctx->connection_state == CSTATE_LAST_ACK ){ // server 가 fin 보낸 후에 ack 받은 경우
                    ctx->connection_state = CSTATE_CLOSED; // state 변경
                    ctx->done = TRUE; // 루프 탈출
                }
            }

            if ( payload_len > 0 ){ // data 인 경우
                if ( recv_seqnum == ctx->peerseqnum ){
                    stcp_app_send( sd, payload, payload_len); // app layer 로 데이터 보내고
                    ctx->peerseqnum += payload_len; // 상대 seq num 업데이트

                    // delayed ack
                    ctx->ack_pending = TRUE;
                    ctx->packets_since_ack++;
                    if (ctx->packets_since_ack >= 2){ // 2개 이상 패킷 받았으면 바로 ack 보냄 하나 더 받은 경우임.
                        send_ack( sd, ctx );
                        ctx->ack_pending = FALSE;
                        ctx->packets_since_ack = 0;
                    }
                }
            }
        }

        if ( event & APP_CLOSE_REQUESTED ){ // active close
            init_tcphdr( send_hdr, ctx->myseqnum, ctx->peerseqnum, TH_FIN | TH_ACK ); // FIN + ACK 플래그 설정
            stcp_network_send( sd, send_hdr, sizeof( struct tcphdr), NULL); // FIN + ACK 패킷 전송
            ctx->myseqnum++; // 내 시퀀스 번호 업데이트

            if( ctx->connection_state == CSTATE_ESTABLISHED ){
                ctx->connection_state = CSTATE_FIN_WAIT_1; // state 변경
            }
            if( ctx->connection_state == CSTATE_CLOSE_WAIT ){
                ctx->connection_state = CSTATE_LAST_ACK; // state 변경
            }
        }

        if ( event & TIMEOUT ){ // 타임 아웃 -> ack 슛
            send_ack( sd, ctx );
            ctx->ack_pending = FALSE;
            ctx->packets_since_ack = 0;
        }

    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...) // flush 포함임 
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout); // flush 있는거 기억하기
}