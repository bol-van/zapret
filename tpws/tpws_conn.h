#pragma once

#include <stdbool.h>
#include <sys/queue.h>

#define BACKLOG 10
#define MAX_EPOLL_EVENTS BACKLOG
#define IP_TRANSPARENT 19 //So that application compiles on OpenWRT
#define SPLICE_LEN 16384
#define DEFAULT_MAX_CONN	512

int event_loop(int listen_fd);

//Three different states of a connection
enum{
	CONN_UNAVAILABLE=0, // connecting
	CONN_AVAILABLE, // operational
	CONN_RDHUP, // received RDHUP, only sending unsent buffers. more RDHUPs are blocked
	CONN_CLOSED // will be deleted soon
};
typedef uint8_t conn_state_t;

struct send_buffer
{
	char *data;
	size_t len,pos;
};
typedef struct send_buffer send_buffer_t;

struct tproxy_conn
{
	bool remote; // false - accepted, true - connected
	int efd; // epoll fd
	int fd;
	int splice_pipe[2];
	conn_state_t state;
	
	struct tproxy_conn *partner; // other leg
	//Create the struct which contains ptrs to next/prev element
	TAILQ_ENTRY(tproxy_conn) conn_ptrs;
	
	bool bFlowIn,bFlowOut, bFlowInPrev,bFlowOutPrev, bPrevRdhup;
	
	// total read,write
	size_t trd,twr;
	// number of epoll_wait events
	unsigned int event_count;

	// connection is either spliced or send/recv
	// spliced connection have pipe buffering but also can have send_buffer's
	// pipe buffer comes first, then send_buffer's from 0 to countof(wr_buf)-1
	// send/recv connection do not have pipe and wr_unsent is meaningless
	ssize_t wr_unsent; // unsent bytes in the pipe
	// buffer 1 : send before split_pos
	// buffer 2 : send after split_pos
	// buffer 3 : after RDHUP read all and buffer to the partner
	struct send_buffer wr_buf[3];
};
typedef struct tproxy_conn tproxy_conn_t;

//Define the struct tailhead (code in sys/queue.h is quite intuitive)
//Use tail queue for efficient delete
TAILQ_HEAD(tailhead, tproxy_conn);
