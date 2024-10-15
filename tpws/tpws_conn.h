#pragma once

#include <stdbool.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <time.h>
#include "tamper.h"
#include "params.h"
#include "resolver.h"

#define BACKLOG 10
#define MAX_EPOLL_EVENTS 64
#define IP_TRANSPARENT 19 //So that application compiles on OpenWRT
#define SPLICE_LEN 65536
#define DEFAULT_MAX_CONN	512
#define DEFAULT_MAX_ORPHAN_TIME	5
#define DEFAULT_TCP_USER_TIMEOUT_LOCAL	10
#define DEFAULT_TCP_USER_TIMEOUT_REMOTE	20

int event_loop(const int *listen_fd, size_t listen_fd_ct);

//Three different states of a connection
enum{
	CONN_UNAVAILABLE=0, // connecting
	CONN_AVAILABLE, // operational
	CONN_RDHUP, // received RDHUP, only sending unsent buffers. more RDHUPs are blocked
	CONN_CLOSED // will be deleted soon
};
typedef uint8_t conn_state_t;

// data in a send_buffer can be sent in several stages
// pos indicates size of already sent data
// when pos==len its time to free buffer
struct send_buffer
{
	uint8_t *data;
	size_t len,pos;
	int ttl, flags;
};
typedef struct send_buffer send_buffer_t;

enum{
	CONN_TYPE_TRANSPARENT=0,
	CONN_TYPE_SOCKS
};
typedef uint8_t conn_type_t;

struct tproxy_conn
{
	bool listener; // true - listening socket. false = connecion socket
	bool remote; // false - accepted, true - connected
	int efd; // epoll fd
	int fd;
	int splice_pipe[2];
	conn_state_t state;
	conn_type_t conn_type;
	sockaddr_in46 client, dest; // ip:port of client, ip:port of target

	struct tproxy_conn *partner; // other leg
	time_t orphan_since;

	// socks5 state machine
	enum {
		S_WAIT_HANDSHAKE=0,
		S_WAIT_REQUEST,
		S_WAIT_RESOLVE,
		S_WAIT_CONNECTION,
		S_TCP
	} socks_state;
	uint8_t socks_ver;
	struct resolve_item *socks_ri;

	// these value are used in flow control. we do not use ET (edge triggered) polling
	// if we dont disable notifications they will come endlessly until condition becomes false and will eat all cpu time
	bool bFlowIn,bFlowOut, bShutdown, bFlowInPrev,bFlowOutPrev, bPrevRdhup;

	// total read,write
	uint64_t trd,twr, tnrd;
	// number of epoll_wait events
	unsigned int event_count;

	// connection is either spliced or send/recv
	// spliced connection have pipe buffering but also can have send_buffer's
	// pipe buffer comes first, then send_buffer's from 0 to countof(wr_buf)-1
	// send/recv connection do not have pipe and wr_unsent is meaningless, always 0
	ssize_t wr_unsent; // unsent bytes in the pipe
	// buffer 0 : send before split_pos
	// buffer 1 : send after split_pos
	// buffer 2 : after RDHUP read all and buffer to the partner
	// buffer 3 : after HUP read all and buffer to the partner
	// (2 and 3 should not be filled simultaneously, but who knows what can happen. if we have to refill non-empty buffer its FATAL)
	// all buffers are sent strictly from 0 to countof(wr_buf)-1
	// buffer cannot be sent if there is unsent data in a lower buffer
	struct send_buffer wr_buf[4];

	t_ctrack track;

	//Create the struct which contains ptrs to next/prev element
	TAILQ_ENTRY(tproxy_conn) conn_ptrs;
};
typedef struct tproxy_conn tproxy_conn_t;

//Define the struct tailhead (code in sys/queue.h is quite intuitive)
//Use tail queue for efficient delete
TAILQ_HEAD(tailhead, tproxy_conn);


bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);
