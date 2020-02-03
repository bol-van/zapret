#pragma once

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

uint16_t csum_partial(const void *buff, size_t len);
uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr, size_t len, uint8_t proto, uint16_t sum);
uint16_t csum_ipv6_magic(const void *saddr, const void *daddr, size_t len, uint8_t proto, uint16_t sum);
uint16_t ip4_compute_csum(const void *buff, size_t len);
void ip4_fix_checksum(struct iphdr *ip);

void tcp4_fix_checksum(struct tcphdr *tcp,size_t len, in_addr_t src_addr, in_addr_t dest_addr);
void tcp6_fix_checksum(struct tcphdr *tcp,size_t len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr);
void tcp_fix_checksum(struct tcphdr *tcp,size_t len,const struct iphdr *iphdr,const struct ip6_hdr *ip6hdr);
