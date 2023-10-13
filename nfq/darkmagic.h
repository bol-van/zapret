#pragma once

#include "checksum.h"

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>

// returns netorder value
uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment);
uint32_t net16_add(uint16_t netorder_value, uint16_t cpuorder_increment);

#define FOOL_NONE	0x00
#define FOOL_MD5SIG	0x01
#define FOOL_BADSUM	0x02
#define FOOL_TS		0x04
#define FOOL_BADSEQ	0x08
#define FOOL_HOPBYHOP	0x10
#define FOOL_HOPBYHOP2	0x20
#define FOOL_DESTOPT	0x40
#define FOOL_IPFRAG1	0x80

#define SCALE_NONE ((uint8_t)-1)

// seq and wsize have network byte order
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t nseq, uint32_t nack_seq,
	uint16_t nwsize,
	uint8_t scale_factor,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	uint32_t badseq_increment,
	uint32_t badseq_ack_increment,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t nseq, uint32_t nack_seq,
	uint16_t nwsize,
	uint8_t scale_factor,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	uint32_t badseq_increment,
	uint32_t badseq_ack_increment,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t nseq, uint32_t nack_seq,
	uint16_t nwsize,
	uint8_t scale_factor,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	uint32_t badseq_increment,
	uint32_t badseq_ack_increment,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);


bool prepare_udp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_udp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_udp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);

bool ip6_insert_simple_hdr(uint8_t type, uint8_t *data_pkt, size_t len_pkt, uint8_t *buf, size_t *buflen);

// ipv4: ident==-1 - copy ip_id from original ipv4 packet
bool ip_frag4(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size);
bool ip_frag6(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size);
bool ip_frag(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size);


void extract_ports(const struct tcphdr *tcphdr, const struct udphdr *udphdr, uint8_t *proto, uint16_t *sport, uint16_t *dport);
void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr,const struct udphdr *udphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst);
uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind);
uint32_t *tcp_find_timestamps(struct tcphdr *tcp);
uint8_t tcp_find_scale_factor(const struct tcphdr *tcp);

// auto creates internal socket and uses it for subsequent calls
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len);
// should pre-do it if dropping privileges. otherwise its not necessary
bool rawsend_preinit(bool bind_fix4, bool bind_fix6);
// cleans up socket autocreated by rawsend
void rawsend_cleanup(void);

const char *proto_name(uint8_t proto);
uint16_t family_from_proto(uint8_t l3proto);
void print_ip(const struct ip *ip);
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto);
void print_tcphdr(const struct tcphdr *tcphdr);
void print_udphdr(const struct udphdr *udphdr);

bool proto_check_ipv4(const uint8_t *data, size_t len);
void proto_skip_ipv4(uint8_t **data, size_t *len);
bool proto_check_ipv6(const uint8_t *data, size_t len);
void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type, uint8_t **last_header_type);
bool proto_check_tcp(const uint8_t *data, size_t len);
void proto_skip_tcp(uint8_t **data, size_t *len);
bool proto_check_udp(const uint8_t *data, size_t len);
void proto_skip_udp(uint8_t **data, size_t *len);

bool tcp_synack_segment(const struct tcphdr *tcphdr);
bool tcp_syn_segment(const struct tcphdr *tcphdr);
bool tcp_ack_segment(const struct tcphdr *tcphdr);
// scale_factor=SCALE_NONE - do not change
void tcp_rewrite_wscale(struct tcphdr *tcp, uint8_t scale_factor);
void tcp_rewrite_winsize(struct tcphdr *tcp, uint16_t winsize, uint8_t scale_factor);
