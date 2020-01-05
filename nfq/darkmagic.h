#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "checksum.h"

// returns netorder value
uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment);

enum tcp_fooling_mode {
	TCP_FOOL_NONE=0,
	TCP_FOOL_MD5SIG=1,
	TCP_FOOL_BADSUM=2
};
// seq and wsize have network byte order
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen);
bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen);
bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen);

void extract_endpoints(const struct iphdr *iphdr,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst);

// auto creates internal socket and uses it for subsequent calls
bool rawsend(struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len);
// cleans up socket autocreated by rawsend
void rawsend_cleanup();
