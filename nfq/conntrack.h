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
#include <netinet/udp.h>

//#define HASH_BLOOM 20
#define HASH_NONFATAL_OOM 1
#undef HASH_FUNCTION
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

#define RETRANS_COUNTER_STOP ((uint8_t)-1)

typedef union {
	struct in_addr ip;
	struct in6_addr ip6;
} t_addr;
typedef struct
{
	t_addr src, dst;
	uint16_t sport,dport;
	uint8_t	l3proto; // IPPROTO_IP, IPPROTO_IPV6
	uint8_t l4proto; // IPPROTO_TCP, IPPROTO_UDP
} t_conn;

// SYN - SYN or SYN/ACK received
// ESTABLISHED - any except SYN or SYN/ACK received
// FIN - FIN or RST received
typedef enum {SYN=0, ESTABLISHED, FIN} t_connstate;
typedef enum {UNKNOWN=0, HTTP, TLS, QUIC, WIREGUARD, DHT} t_l7proto;
typedef struct
{
	// common state
	time_t t_start, t_last;
	uint64_t pcounter_orig, pcounter_reply;	// packet counter
	uint64_t pdcounter_orig, pdcounter_reply; // data packet counter (with payload)
	uint32_t pos_orig, pos_reply;		// TCP: seq_last+payload, ack_last+payload  UDP: sum of all seen payload lenghts including current
	uint32_t seq_last, ack_last;		// TCP: last seen seq and ack  UDP: sum of all seen payload lenghts NOT including current

	// tcp only state, not used in udp
	t_connstate state;
	uint32_t seq0, ack0;			// starting seq and ack
	uint16_t winsize_orig, winsize_reply;	// last seen window size
	uint8_t scale_orig, scale_reply;	// last seen window scale factor. SCALE_NONE if none
	
	uint8_t req_retrans_counter;		// number of request retransmissions
	uint32_t req_seq;			// sequence number of the request (to track retransmissions)

	bool b_cutoff;				// mark for deletion
	bool b_wssize_cutoff, b_desync_cutoff;

	t_l7proto l7proto;
	char *hostname;
} t_ctrack;

typedef struct
{
	t_ctrack track;
	UT_hash_handle hh;	// makes this structure hashable
	t_conn conn;		// key
} t_conntrack_pool;
typedef struct
{
	// inactivity time to purge an entry in each connection state
	uint32_t timeout_syn,timeout_established,timeout_fin,timeout_udp;
	time_t t_purge_interval, t_last_purge;
	t_conntrack_pool *pool;
} t_conntrack;

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin, uint32_t timeout_udp);
void ConntrackPoolDestroy(t_conntrack *p);
bool ConntrackPoolFeed(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr, size_t len_payload, t_ctrack **ctrack, bool *bReverse);
bool ConntrackPoolDrop(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr);
void CaonntrackExtractConn(t_conn *c, bool bReverse, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, const struct udphdr *udphdr);
void ConntrackPoolDump(const t_conntrack *p);
void ConntrackPoolPurge(t_conntrack *p);
