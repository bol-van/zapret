#pragma once

// this conntrack is not bullet-proof
// its designed to satisfy dpi desync needs only

#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

//#define HASH_BLOOM 20
#define HASH_NONFATAL_OOM 1
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

typedef struct
{
	struct in_addr adr;
	uint16_t port;
} t_endpoint4;
typedef struct
{
	struct in6_addr adr;
	uint16_t port;
} t_endpoint6;
// e1 - initiator. the one who have sent SYN
// e2 - acceptor
typedef struct
{
	t_endpoint4 e1,e2;
} t_conn4;
typedef struct
{
	t_endpoint6 e1,e2;
} t_conn6;

// SYN - SYN or SYN/ACK received
// ESTABLISHED - any except SYN or SYN/ACK received
// FIN - FIN or RST received
typedef enum {SYN=0, ESTABLISHED, FIN} t_connstate;
typedef struct
{
	t_connstate state;
	time_t t_start, t_last;
	uint32_t seq0, ack0;			// starting seq and ack
	uint32_t seq_last, ack_last;		// current seq and ack
	uint64_t pcounter_orig, pcounter_reply;	// packet counter
	uint16_t winsize_orig, winsize_reply;	// last seen window size
	uint8_t scale_orig, scale_reply;	// last seen window scale factor. SCALE_NONE if none

	bool b_cutoff;				// mark for deletion
} t_ctrack;

// use separate pools for ipv4 and ipv6 to save RAM. otherwise could use union key
typedef struct
{
	t_ctrack track;
	UT_hash_handle hh;	// makes this structure hashable
	t_conn4 conn;		// key
} t_conntrack4;
typedef struct
{
	t_ctrack track;
	UT_hash_handle hh;	// makes this structure hashable
	t_conn6 conn;		// key
} t_conntrack6;
typedef struct
{
	// inactivity time to purge an entry in each connection state
	uint32_t timeout_syn,timeout_established,timeout_fin;
	time_t t_purge_interval, t_last_purge;
	t_conntrack4 *pool4;
	t_conntrack6 *pool6;
} t_conntrack;

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin);
void ConntrackPoolDestroy(t_conntrack *p);
bool ConntrackPoolFeed(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, size_t len_payload, t_ctrack **ctrack, bool *bReverse);
bool ConntrackPoolDrop(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr);

void ConntrackExtractConn4(t_conn4 *c, bool bReverse, const struct ip *ip, const struct tcphdr *tcphdr);
void ConntrackExtractConn6(t_conn6 *c, bool bReverse, const struct ip6_hdr *ip, const struct tcphdr *tcphdr);

void ConntrackPoolDump4(t_conntrack4 *p);
void ConntrackPoolDump6(t_conntrack6 *p);
void ConntrackPoolDump(t_conntrack *p);

void ConntrackPoolPurge(t_conntrack *p);
