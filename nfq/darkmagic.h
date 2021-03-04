#pragma once

#include "checksum.h"

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>

// returns netorder value
uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment);

#define TCP_FOOL_NONE	0
#define TCP_FOOL_MD5SIG	1
#define TCP_FOOL_BADSUM	2
#define TCP_FOOL_TS	4
#define TCP_FOOL_BADSEQ	8

// seq and wsize have network byte order
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);
bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen);

void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst);
uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind);
uint32_t *tcp_find_timestamps(struct tcphdr *tcp);

// auto creates internal socket and uses it for subsequent calls
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len);
// should pre-do it if dropping privileges. otherwise its not necessary
bool rawsend_preinit(uint32_t fwmark);
// cleans up socket autocreated by rawsend
void rawsend_cleanup();

void print_ip(const struct ip *ip);
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto);
void print_tcphdr(const struct tcphdr *tcphdr);


bool proto_check_ipv4(uint8_t *data, size_t len);
void proto_skip_ipv4(uint8_t **data, size_t *len);
bool proto_check_tcp(uint8_t *data, size_t len);
void proto_skip_tcp(uint8_t **data, size_t *len);
bool proto_check_ipv6(uint8_t *data, size_t len);
void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type);
bool tcp_synack_segment(const struct tcphdr *tcphdr);
