#define _GNU_SOURCE
#include "darkmagic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint16_t tcp_checksum(const void *buff, int len, in_addr_t src_addr, in_addr_t dest_addr)
{
	const uint16_t *buf=buff;
	uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
	uint32_t sum;
	int length=len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
		
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}
void tcp_fix_checksum(struct tcphdr *tcp,int len, in_addr_t src_addr, in_addr_t dest_addr)
{
	tcp->check = 0;
	tcp->check = tcp_checksum(tcp,len,src_addr,dest_addr);
}
uint16_t tcp6_checksum(const void *buff, int len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr)
{
	const uint16_t *buf=buff;
	const uint16_t *ip_src=(uint16_t *)src_addr, *ip_dst=(uint16_t *)dest_addr;
	uint32_t sum;
	int length=len;
	
	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
	
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}
void tcp6_fix_checksum(struct tcphdr *tcp,int len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr)
{
	tcp->check = 0;
	tcp->check = tcp6_checksum(tcp,len,src_addr,dest_addr);
}



static void fill_tcphdr(struct tcphdr *tcp, uint8_t tcp_flags, uint32_t seq, uint32_t ack_seq, enum tcp_fooling_mode fooling, uint16_t nsport, uint16_t ndport)
{
	char *tcpopt = (char*)(tcp+1);
	memset(tcp,0,sizeof(*tcp));
	tcp->source     = nsport;
	tcp->dest       = ndport;
	tcp->seq        = seq;
	tcp->ack_seq    = ack_seq;
	tcp->doff       = 5;
	*((uint8_t*)tcp+13)= tcp_flags;
	tcp->window     = htons(65535);
	if (fooling==TCP_FOOL_MD5SIG)
	{
		tcp->doff += 5; // +20 bytes
		tcpopt[0] = 19; // kind
		tcpopt[1] = 18; // len
		*(uint32_t*)(tcpopt+2)=random();
		*(uint32_t*)(tcpopt+6)=random();
		*(uint32_t*)(tcpopt+10)=random();
		*(uint32_t*)(tcpopt+14)=random();
		tcpopt[18] = 0; // end
		tcpopt[19] = 0;
	}
}

static int rawsend_sock=-1;
void rawsend_cleanup()
{
	if (rawsend_sock!=-1)
	{
		close(rawsend_sock);
		rawsend_sock=-1;
	}
}
static void rawsend_socket(int family,uint32_t fwmark)
{
	if (rawsend_sock==-1)
	{
		int yes=1,pri=6;
		rawsend_sock = socket(family, SOCK_RAW, IPPROTO_RAW);
		if (rawsend_sock==-1)
			perror("rawsend: socket()");
		else if (setsockopt(rawsend_sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == -1)
		{
			perror("rawsend: setsockopt(SO_MARK)");
			rawsend_cleanup();
		}
		else if (setsockopt(rawsend_sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri)) == -1)
		{
			perror("rawsend: setsockopt(SO_PRIORITY)");
			rawsend_cleanup();
		}
	}
}
bool rawsend(struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len)
{
	rawsend_socket(dst->sa_family,fwmark);
	if (rawsend_sock==-1) return false;

	int salen = dst->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	struct sockaddr_storage dst2;
	memcpy(&dst2,dst,salen);
	if (dst->sa_family==AF_INET6)
		((struct sockaddr_in6 *)&dst2)->sin6_port = 0; // or will be EINVAL

	int bytes = sendto(rawsend_sock, data, len, 0, (struct sockaddr*)&dst2, salen);
	if (bytes==-1)
	{
		perror("rawsend: sendto");
		return false;
	}
	return true;
}
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	uint16_t tcpoptlen = 0;
	if (fooling==TCP_FOOL_MD5SIG) tcpoptlen=20;
	uint16_t pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcpoptlen + len;
	if (pktlen>*buflen)
	{
		fprintf(stderr,"prepare_tcp_segment : packet len cannot exceed %zu\n",*buflen);
		return false;
	}

	struct iphdr *ip = (struct iphdr*) buf;
	struct tcphdr *tcp = (struct tcphdr*) (ip+1);

	ip->frag_off = 0;
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(pktlen);
	ip->id = 0;
	ip->ttl = ttl;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src->sin_addr.s_addr;
	ip->daddr = dst->sin_addr.s_addr;

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin_port,dst->sin_port);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,ip->saddr,ip->daddr);
	if (fooling==TCP_FOOL_BADSUM) tcp->check^=0xBEAF;

	*buflen = pktlen;
	return true;
}


bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	uint16_t tcpoptlen = 0;
	if (fooling==TCP_FOOL_MD5SIG) tcpoptlen=20;
	uint16_t payloadlen = sizeof(struct tcphdr) + tcpoptlen + len;
	uint16_t pktlen = sizeof(struct ip6_hdr) + payloadlen;
	if (pktlen>*buflen)
	{
		fprintf(stderr,"prepare_tcp_segment : packet len cannot exceed %zu\n",*buflen);
		return false;
	}

	struct ip6_hdr *ip6 = (struct ip6_hdr*) buf;
	struct tcphdr *tcp = (struct tcphdr*) (ip6+1);

	ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(payloadlen);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
	ip6->ip6_src = src->sin6_addr;
	ip6->ip6_dst = dst->sin6_addr;

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin6_port,dst->sin6_port);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp6_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,&ip6->ip6_src,&ip6->ip6_dst);
	if (fooling==TCP_FOOL_BADSUM) tcp->check^=0xBEAF;

	*buflen = pktlen;
	return true;
}

bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint8_t ttl,
	enum tcp_fooling_mode fooling,
	const void *data, uint16_t len,
	char *buf, size_t *buflen)
{
	return (src->sa_family==AF_INET && dst->sa_family==AF_INET) ?
		prepare_tcp_segment4((struct sockaddr_in *)src,(struct sockaddr_in *)dst,tcp_flags,seq,ack_seq,ttl,fooling,data,len,buf,buflen) :
		(src->sa_family==AF_INET6 && dst->sa_family==AF_INET6) ?
		prepare_tcp_segment6((struct sockaddr_in6 *)src,(struct sockaddr_in6 *)dst,tcp_flags,seq,ack_seq,ttl,fooling,data,len,buf,buflen) :
		false;
}


void extract_endpoints(const struct iphdr *iphdr,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	if (iphdr)
	{
		struct sockaddr_in *si = (struct sockaddr_in*)dst;
		si->sin_family = AF_INET;
		si->sin_port = tcphdr->dest;
		si->sin_addr.s_addr = iphdr->daddr;

		si = (struct sockaddr_in*)src;
		si->sin_family = AF_INET;
		si->sin_port = tcphdr->source;
		si->sin_addr.s_addr = iphdr->saddr;
	}
	else if (ip6hdr)
	{
		struct sockaddr_in6 *si = (struct sockaddr_in6*)dst;
		si->sin6_family = AF_INET6;
		si->sin6_port = tcphdr->dest;
		si->sin6_addr = ip6hdr->ip6_dst;
		si->sin6_flowinfo = 0;
		si->sin6_scope_id = 0;

		si = (struct sockaddr_in6*)src;
		si->sin6_family = AF_INET6;
		si->sin6_port = tcphdr->source;
		si->sin6_addr = ip6hdr->ip6_src;
		si->sin6_flowinfo = 0;
		si->sin6_scope_id = 0;
	}
}
