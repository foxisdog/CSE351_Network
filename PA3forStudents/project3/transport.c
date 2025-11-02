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

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


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


    // 여기에는 TCP 3-way handshake 구현 필요함.
    // 3-way handshake 구조 
    // 클라이언트 : SYN -> 서버 / 보내는 정보 : seq num / seq num = initial_sequence num / 클라이언트 state : SYN_SENT
    // 서버 : SYN + ACK -> 클라이언트 / 보내는 정보 : seq num, ack num / ack num = 클라이언트가 보낸 seq num + 1 / 서버 state : SYN_RCVD
    // 클라이언트 : ACK -> 서버 / 보내는 정보 : seq num, ack num / ack num = 서버가 보낸 seq num + 1 / 클라이언트 state : ESTABLISHED / 서버 state : ESTABLISHED

    if (is_active){ // active open : client
        ctx->connection_state = CSTATE_SYN_SENT; // state 변경 SYS_SENT 로 변경하고
        stcp_network_send(); // 서버에 SYN 패킷 보냄
        stcp_network_recv(); // 서버로 부터 SYN + ACK 패킷 받음
        ctx->connection_state = CSTATE_ESTABLISHED; // state 변경 ESTABLISHED 로 변경
        stcp_network_send(); // 서버에 ACK 패킷 보냄 

    }else{ // passive open : server
        stcp_network_recv(); // 클라이언트로 부터 SYN 패킷 받음
        ctx->connection_state = CSTATE_SYN_RCVD; // state 변경 SYN_RCVD
        stcp_network_send(); // 클라이언트에 SYN + ACK 패킷 보냄
        stcp_network_recv(); // 클라이언트로 부터 ACK 패킷 받음
        ctx->connection_state = CSTATE_ESTABLISHED; // state 변경 ESTABLISHED
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

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL); // 0의미 : 아무 이벤트도 기다리지 않음, ANYEVENT 의미 : 모든 이벤트 기다림

        // 여기 아래에는 이벤트 처리 코드 작성함.
        // active close, passive close, 데이터 수신, 데이터 전송
        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        /* etc. */
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