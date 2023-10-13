#define _GNU_SOURCE

#include "darkmagic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <errno.h>

#include "helpers.h"


uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment)
{
	return htonl(ntohl(netorder_value)+cpuorder_increment);
}
uint32_t net16_add(uint16_t netorder_value, uint16_t cpuorder_increment)
{
	return htons(ntohs(netorder_value)+cpuorder_increment);
}

uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind)
{
	uint8_t *t = (uint8_t*)(tcp+1);
	uint8_t *end = (uint8_t*)tcp + (tcp->th_off<<2);
	while(t<end)
	{
		switch(*t)
		{
			case 0: // end
				return NULL;
			case 1: // noop
				t++;
				break;
			default: // kind,len,data
				if ((t+1)>=end || t[1]<2 || (t+t[1])>end)
					return NULL;
				if (*t==kind)
					return t;
				t+=t[1];
				break;
		}
	}
	return NULL;
}
uint32_t *tcp_find_timestamps(struct tcphdr *tcp)
{
	uint8_t *t = tcp_find_option(tcp,8);
	return (t && t[1]==10) ? (uint32_t*)(t+2) : NULL;
}
uint8_t tcp_find_scale_factor(const struct tcphdr *tcp)
{
	uint8_t *scale = tcp_find_option((struct tcphdr*)tcp,3); // tcp option 3 - scale factor
	if (scale && scale[1]==3) return scale[2];
	return SCALE_NONE;
}

// n prefix (nsport, nwsize) means network byte order
static void fill_tcphdr(
	struct tcphdr *tcp, uint8_t fooling, uint8_t tcp_flags,
	uint32_t nseq, uint32_t nack_seq,
	uint16_t nsport, uint16_t ndport,
	uint16_t nwsize, uint8_t scale_factor,
	uint32_t *timestamps,
	uint32_t badseq_increment,
	uint32_t badseq_ack_increment)
{
	char *tcpopt = (char*)(tcp+1);
	uint8_t t=0;

	memset(tcp,0,sizeof(*tcp));
	tcp->th_sport = nsport;
	tcp->th_dport = ndport;
	if (fooling & FOOL_BADSEQ)
	{
		tcp->th_seq = net32_add(nseq,badseq_increment);
		tcp->th_ack = net32_add(nack_seq,badseq_ack_increment);
	}
	else
	{
		tcp->th_seq = nseq;
		tcp->th_ack = nack_seq;
	}
	tcp->th_off       = 5;
	*((uint8_t*)tcp+13)= tcp_flags;
	tcp->th_win     = nwsize;
	if (fooling & FOOL_MD5SIG)
	{
		tcpopt[0] = 19; // kind
		tcpopt[1] = 18; // len
		*(uint32_t*)(tcpopt+2)=random();
		*(uint32_t*)(tcpopt+6)=random();
		*(uint32_t*)(tcpopt+10)=random();
		*(uint32_t*)(tcpopt+14)=random();
		t=18;
	}
	if (timestamps || (fooling & FOOL_TS))
	{
		tcpopt[t] = 8; // kind
		tcpopt[t+1] = 10; // len
		// forge only TSecr if orig timestamp is present
		*(uint32_t*)(tcpopt+t+2) = timestamps ? timestamps[0] : -1;
		*(uint32_t*)(tcpopt+t+6) = (timestamps && !(fooling & FOOL_TS)) ? timestamps[1] : -1;
		t+=10;
	}
	if (scale_factor!=SCALE_NONE)
	{
		tcpopt[t++]=3;
		tcpopt[t++]=3;
		tcpopt[t++]=scale_factor;
	}
	while (t&3) tcpopt[t++]=1; // noop
	tcp->th_off += t>>2;
	tcp->th_sum = 0;
}
static uint16_t tcpopt_len(uint8_t fooling, const uint32_t *timestamps, uint8_t scale_factor)
{
	uint16_t t=0;
	if (fooling & FOOL_MD5SIG) t=18;
	if ((fooling & FOOL_TS) || timestamps) t+=10;
	if (scale_factor!=SCALE_NONE) t+=3;
	return (t+3)&~3;
}

// n prefix (nsport, nwsize) means network byte order
static void fill_udphdr(struct udphdr *udp, uint16_t nsport, uint16_t ndport, uint16_t len_payload)
{
	udp->uh_sport = nsport;
	udp->uh_dport = ndport;
	udp->uh_ulen = htons(len_payload+sizeof(struct udphdr));
	udp->uh_sum = 0;
}

static void fill_iphdr(struct ip *ip, const struct in_addr *src, const struct in_addr *dst, uint16_t pktlen, uint8_t proto, uint8_t ttl)
{
	ip->ip_off = 0;
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = htons(pktlen);
	ip->ip_id = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = proto;
	ip->ip_src = *src;
	ip->ip_dst = *dst;
}
static void fill_ip6hdr(struct ip6_hdr *ip6, const struct in6_addr *src, const struct in6_addr *dst, uint16_t payloadlen, uint8_t proto, uint8_t ttl)
{
	ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(payloadlen);
	ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = proto;
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
	ip6->ip6_src = *src;
	ip6->ip6_dst = *dst;
}

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
	uint8_t *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps,scale_factor);
	uint16_t ip_payload_len = sizeof(struct tcphdr) + tcpoptlen + len;
	uint16_t pktlen = sizeof(struct ip) + ip_payload_len;
	if (pktlen>*buflen) return false;

	struct ip *ip = (struct ip*)buf;
	struct tcphdr *tcp = (struct tcphdr*)(ip+1);
	uint8_t *payload = (uint8_t*)(tcp+1)+tcpoptlen;

	fill_iphdr(ip, &src->sin_addr, &dst->sin_addr, pktlen, IPPROTO_TCP, ttl);
	fill_tcphdr(tcp,fooling,tcp_flags,nseq,nack_seq,src->sin_port,dst->sin_port,nwsize,scale_factor,timestamps,badseq_increment,badseq_ack_increment);

	memcpy(payload,data,len);
	tcp4_fix_checksum(tcp,ip_payload_len,&ip->ip_src,&ip->ip_dst);
	if (fooling & FOOL_BADSUM) tcp->th_sum^=htons(0xBEAF);

	*buflen = pktlen;
	return true;
}

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
	uint8_t *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps,scale_factor);
	uint16_t transport_payload_len = sizeof(struct tcphdr) + tcpoptlen + len;
	uint16_t ip_payload_len = transport_payload_len +
		8*!!((fooling & (FOOL_HOPBYHOP|FOOL_HOPBYHOP2))==FOOL_HOPBYHOP) +
		16*!!(fooling & FOOL_HOPBYHOP2) +
		8*!!(fooling & FOOL_DESTOPT) +
		8*!!(fooling & FOOL_IPFRAG1);
	uint16_t pktlen = sizeof(struct ip6_hdr) + ip_payload_len;
	if (pktlen>*buflen) return false;

	struct ip6_hdr *ip6 = (struct ip6_hdr*)buf;
	struct tcphdr *tcp = (struct tcphdr*)(ip6+1);
	uint8_t proto = IPPROTO_TCP, *nexttype = NULL;

	if (fooling & (FOOL_HOPBYHOP|FOOL_HOPBYHOP2))
	{
		struct ip6_hbh *hbh = (struct ip6_hbh*)tcp;
		tcp = (struct tcphdr*)((uint8_t*)tcp+8);
		memset(hbh,0,8);
		// extra HOPBYHOP header. standard violation
		if (fooling & FOOL_HOPBYHOP2)
		{
			hbh = (struct ip6_hbh*)tcp;
			tcp = (struct tcphdr*)((uint8_t*)tcp+8);
			memset(hbh,0,8);
		}
		hbh->ip6h_nxt = IPPROTO_TCP;
		nexttype = &hbh->ip6h_nxt;
		proto = IPPROTO_HOPOPTS;
	}
	if (fooling & FOOL_DESTOPT)
	{
		struct ip6_dest *dest = (struct ip6_dest*)tcp;
		tcp = (struct tcphdr*)((uint8_t*)tcp+8);
		memset(dest,0,8);
		dest->ip6d_nxt = IPPROTO_TCP;
		if (nexttype)
			*nexttype = IPPROTO_DSTOPTS;
		else
			proto = IPPROTO_DSTOPTS;
		nexttype = &dest->ip6d_nxt;
	}
	if (fooling & FOOL_IPFRAG1)
	{
		struct ip6_frag *frag = (struct ip6_frag*)tcp;
		tcp = (struct tcphdr*)((uint8_t*)tcp+sizeof(struct ip6_frag));
		frag->ip6f_nxt = IPPROTO_TCP;
		frag->ip6f_ident = htonl(1+random()%0xFFFFFFFF);
		frag->ip6f_reserved = 0;
		frag->ip6f_offlg = 0;
		if (nexttype)
			*nexttype = IPPROTO_FRAGMENT;
		else
			proto = IPPROTO_FRAGMENT;
	}

	uint8_t *payload = (uint8_t*)(tcp+1)+tcpoptlen;

	fill_ip6hdr(ip6, &src->sin6_addr, &dst->sin6_addr, ip_payload_len, proto, ttl);
	fill_tcphdr(tcp,fooling,tcp_flags,nseq,nack_seq,src->sin6_port,dst->sin6_port,nwsize,scale_factor,timestamps,badseq_increment,badseq_ack_increment);

	memcpy(payload,data,len);
	tcp6_fix_checksum(tcp,transport_payload_len,&ip6->ip6_src,&ip6->ip6_dst);
	if (fooling & FOOL_BADSUM) tcp->th_sum^=htons(0xBEAF);

	*buflen = pktlen;
	return true;
}

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
	uint8_t *buf, size_t *buflen)
{
	return (src->sa_family==AF_INET && dst->sa_family==AF_INET) ?
		prepare_tcp_segment4((struct sockaddr_in *)src,(struct sockaddr_in *)dst,tcp_flags,nseq,nack_seq,nwsize,scale_factor,timestamps,ttl,fooling,badseq_increment,badseq_ack_increment,data,len,buf,buflen) :
		(src->sa_family==AF_INET6 && dst->sa_family==AF_INET6) ?
		prepare_tcp_segment6((struct sockaddr_in6 *)src,(struct sockaddr_in6 *)dst,tcp_flags,nseq,nack_seq,nwsize,scale_factor,timestamps,ttl,fooling,badseq_increment,badseq_ack_increment,data,len,buf,buflen) :
		false;
}


// padlen<0 means payload shrinking
bool prepare_udp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	if ((len+padlen)<=0) padlen=-(int)len+1; // do not allow payload to be less that 1 byte
	if ((len+padlen)>0xFFFF) padlen=0xFFFF-len; // do not allow payload size to exceed u16 range
	if (padlen<0)
	{
		len+=padlen;
		padlen=0;
	}
	uint16_t datalen = (uint16_t)(len + padlen);
	uint16_t ip_payload_len = sizeof(struct udphdr) + datalen;
	uint16_t pktlen = sizeof(struct ip) + ip_payload_len;
	if (pktlen>*buflen) return false;

	struct ip *ip = (struct ip*)buf;
	struct udphdr *udp = (struct udphdr*)(ip+1);
	uint8_t *payload = (uint8_t*)(udp+1);


	fill_iphdr(ip, &src->sin_addr, &dst->sin_addr, pktlen, IPPROTO_UDP, ttl);
	fill_udphdr(udp, src->sin_port, dst->sin_port, datalen);

	memcpy(payload,data,len);
	if (padding)
		fill_pattern(payload+len,padlen,padding,padding_size);
	else
		memset(payload+len,0,padlen);
	udp4_fix_checksum(udp,ip_payload_len,&ip->ip_src,&ip->ip_dst);
	if (fooling & FOOL_BADSUM) udp->uh_sum^=htons(0xBEAF);

	*buflen = pktlen;
	return true;
}
bool prepare_udp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	if ((len+padlen)<=0) padlen=-(int)len+1; // do not allow payload to be less that 1 byte
	if ((len+padlen)>0xFFFF) padlen=0xFFFF-len; // do not allow payload size to exceed u16 range
	if (padlen<0)
	{
		len+=padlen;
		padlen=0;
	}
	uint16_t datalen = (uint16_t)(len + padlen);
	uint16_t transport_payload_len = sizeof(struct udphdr) + datalen;
	uint16_t ip_payload_len = transport_payload_len +
		8*!!((fooling & (FOOL_HOPBYHOP|FOOL_HOPBYHOP2))==FOOL_HOPBYHOP) +
		16*!!(fooling & FOOL_HOPBYHOP2) +
		8*!!(fooling & FOOL_DESTOPT) +
		8*!!(fooling & FOOL_IPFRAG1);
	uint16_t pktlen = sizeof(struct ip6_hdr) + ip_payload_len;
	if (pktlen>*buflen) return false;

	struct ip6_hdr *ip6 = (struct ip6_hdr*)buf;
	struct udphdr *udp = (struct udphdr*)(ip6+1);
	uint8_t proto = IPPROTO_UDP, *nexttype = NULL;

	if (fooling & (FOOL_HOPBYHOP|FOOL_HOPBYHOP2))
	{
		struct ip6_hbh *hbh = (struct ip6_hbh*)udp;
		udp = (struct udphdr*)((uint8_t*)udp+8);
		memset(hbh,0,8);
		// extra HOPBYHOP header. standard violation
		if (fooling & FOOL_HOPBYHOP2)
		{
			hbh = (struct ip6_hbh*)udp;
			udp = (struct udphdr*)((uint8_t*)udp+8);
			memset(hbh,0,8);
		}
		hbh->ip6h_nxt = IPPROTO_UDP;
		nexttype = &hbh->ip6h_nxt;
		proto = IPPROTO_HOPOPTS;
	}
	if (fooling & FOOL_DESTOPT)
	{
		struct ip6_dest *dest = (struct ip6_dest*)udp;
		udp = (struct udphdr*)((uint8_t*)udp+8);
		memset(dest,0,8);
		dest->ip6d_nxt = IPPROTO_UDP;
		if (nexttype)
			*nexttype = IPPROTO_DSTOPTS;
		else
			proto = IPPROTO_DSTOPTS;
		nexttype = &dest->ip6d_nxt;
	}
	if (fooling & FOOL_IPFRAG1)
	{
		struct ip6_frag *frag = (struct ip6_frag*)udp;
		udp = (struct udphdr*)((uint8_t*)udp+sizeof(struct ip6_frag));
		frag->ip6f_nxt = IPPROTO_UDP;
		frag->ip6f_ident = htonl(1+random()%0xFFFFFFFF);
		frag->ip6f_reserved = 0;
		frag->ip6f_offlg = 0;
		if (nexttype)
			*nexttype = IPPROTO_FRAGMENT;
		else
			proto = IPPROTO_FRAGMENT;
	}

	uint8_t *payload = (uint8_t*)(udp+1);

	fill_ip6hdr(ip6, &src->sin6_addr, &dst->sin6_addr, ip_payload_len, proto, ttl);
	fill_udphdr(udp, src->sin6_port, dst->sin6_port, datalen);

	memcpy(payload,data,len);
	if (padding)
		fill_pattern(payload+len,padlen,padding,padding_size);
	else
		memset(payload+len,0,padlen);
	udp6_fix_checksum(udp,transport_payload_len,&ip6->ip6_src,&ip6->ip6_dst);
	if (fooling & FOOL_BADSUM) udp->uh_sum^=htons(0xBEAF);

	*buflen = pktlen;
	return true;
}
bool prepare_udp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t ttl,
	uint8_t fooling,
	const uint8_t *padding, size_t padding_size,
	int padlen,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	return (src->sa_family==AF_INET && dst->sa_family==AF_INET) ?
		prepare_udp_segment4((struct sockaddr_in *)src,(struct sockaddr_in *)dst,ttl,fooling,padding,padding_size,padlen,data,len,buf,buflen) :
		(src->sa_family==AF_INET6 && dst->sa_family==AF_INET6) ?
		prepare_udp_segment6((struct sockaddr_in6 *)src,(struct sockaddr_in6 *)dst,ttl,fooling,padding,padding_size,padlen,data,len,buf,buflen) :
		false;
}

bool ip6_insert_simple_hdr(uint8_t type, uint8_t *data_pkt, size_t len_pkt, uint8_t *buf, size_t *buflen)
{
	if ((len_pkt+8)<=*buflen && len_pkt>=sizeof(struct ip6_hdr))
	{
		struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
		struct ip6_ext *hdr = (struct ip6_ext*)(ip6+1);
		*ip6 = *(struct ip6_hdr*)data_pkt;
		memset(hdr,0,8);
		memcpy((uint8_t*)hdr+8, data_pkt+sizeof(struct ip6_hdr), len_pkt-sizeof(struct ip6_hdr));
		hdr->ip6e_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = type;
		ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = net16_add(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, 8);
		*buflen = len_pkt + 8;
		return true;
	}
	return false;
}

// split ipv4 packet into 2 fragments at data payload position frag_pos
bool ip_frag4(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size)
{
	uint16_t hdrlen, payload_len;
	// frag_pos must be 8-byte aligned
	if (frag_pos & 7 || pkt_size < sizeof(struct ip)) return false;
	payload_len = htons(((struct ip *)pkt)->ip_len);
	hdrlen = ((struct ip *)pkt)->ip_hl<<2;
	if (payload_len>pkt_size || hdrlen>pkt_size || hdrlen>payload_len) return false;
	payload_len -= hdrlen;
	if (frag_pos>=payload_len || *pkt1_size<(hdrlen+frag_pos) || *pkt2_size<(hdrlen+payload_len-frag_pos)) return false;

	memcpy(pkt1, pkt, hdrlen+frag_pos);
	((struct ip*)pkt1)->ip_off = htons(IP_MF);
	((struct ip*)pkt1)->ip_len = htons(hdrlen+frag_pos);
	if (ident!=(uint32_t)-1) ((struct ip*)pkt1)->ip_id = (uint16_t)ident;
	*pkt1_size=hdrlen+frag_pos;
	ip4_fix_checksum((struct ip *)pkt1);

	memcpy(pkt2, pkt, hdrlen);
	memcpy(pkt2+hdrlen, pkt+hdrlen+frag_pos, payload_len-frag_pos);
	((struct ip*)pkt2)->ip_off = htons((uint16_t)frag_pos>>3 & IP_OFFMASK);
	((struct ip*)pkt2)->ip_len = htons(hdrlen+payload_len-frag_pos);
	if (ident!=(uint32_t)-1) ((struct ip*)pkt2)->ip_id = (uint16_t)ident;
	*pkt2_size=hdrlen+payload_len-frag_pos;
	ip4_fix_checksum((struct ip *)pkt2);

	return true;
}
bool ip_frag6(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size)
{
	size_t payload_len, unfragmentable;
	uint8_t *last_header_type;
	uint8_t proto;
	struct ip6_frag *frag;
	const uint8_t *payload;

	if (frag_pos & 7 || pkt_size < sizeof(struct ip6_hdr)) return false;
	payload_len = sizeof(struct ip6_hdr) + htons(((struct ip6_hdr*)pkt)->ip6_ctlun.ip6_un1.ip6_un1_plen);
	if (pkt_size < payload_len) return false;

	payload = pkt;
	proto_skip_ipv6((uint8_t**)&payload, &payload_len, &proto, &last_header_type);
	unfragmentable = payload - pkt;

	//printf("pkt_size=%zu FRAG_POS=%zu payload_len=%zu unfragmentable=%zu dh=%zu\n",pkt_size,frag_pos,payload_len,unfragmentable,last_header_type - pkt);

	if (frag_pos>=payload_len ||
		*pkt1_size<(unfragmentable + sizeof(struct ip6_frag) + frag_pos) ||
		*pkt2_size<(unfragmentable + sizeof(struct ip6_frag) + payload_len - frag_pos))
	{
		return false;
	}

	memcpy(pkt1, pkt, unfragmentable);
	((struct ip6_hdr*)pkt1)->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(unfragmentable - sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + frag_pos);
	pkt1[last_header_type - pkt] = IPPROTO_FRAGMENT;
	frag = (struct ip6_frag*)(pkt1 + unfragmentable);
	frag->ip6f_nxt = proto;
	frag->ip6f_reserved = 0;
	frag->ip6f_offlg = IP6F_MORE_FRAG;
	frag->ip6f_ident = ident;
	memcpy(frag+1, pkt + unfragmentable, frag_pos);
	*pkt1_size = unfragmentable + sizeof(struct ip6_frag) + frag_pos;

	memcpy(pkt2, pkt, sizeof(struct ip6_hdr));
	((struct ip6_hdr*)pkt2)->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(unfragmentable - sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + payload_len - frag_pos);
	pkt2[last_header_type - pkt] = IPPROTO_FRAGMENT;
	frag = (struct ip6_frag*)(pkt2 + unfragmentable);
	frag->ip6f_nxt = proto;
	frag->ip6f_reserved = 0;
	frag->ip6f_offlg = htons(frag_pos);
	frag->ip6f_ident = ident;
	memcpy(frag+1, pkt + unfragmentable + frag_pos, payload_len - frag_pos);
	*pkt2_size = unfragmentable + sizeof(struct ip6_frag) + payload_len - frag_pos;

	return true;
}
bool ip_frag(
	const uint8_t *pkt, size_t pkt_size,
	size_t frag_pos, uint32_t ident,
	uint8_t *pkt1, size_t *pkt1_size,
	uint8_t *pkt2, size_t *pkt2_size)
{
	if (proto_check_ipv4(pkt,pkt_size))
		return ip_frag4(pkt,pkt_size,frag_pos,ident,pkt1,pkt1_size,pkt2,pkt2_size);
	else if (proto_check_ipv6(pkt,pkt_size))
		return ip_frag6(pkt,pkt_size,frag_pos,ident,pkt1,pkt1_size,pkt2,pkt2_size);
	else
		return false;
}


void extract_ports(const struct tcphdr *tcphdr, const struct udphdr *udphdr, uint8_t *proto, uint16_t *sport, uint16_t *dport)
{
	if (sport) *sport  = htons(tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0);
	if (dport) *dport  = htons(tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0);
	if (proto) *proto = tcphdr ? IPPROTO_TCP : udphdr ? IPPROTO_UDP : -1;
}

void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr,const struct udphdr *udphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	if (ip)
	{
		struct sockaddr_in *si;

		if (dst)
		{
			si = (struct sockaddr_in*)dst;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0;
			si->sin_addr = ip->ip_dst;
		}

		if (src)
		{
			si = (struct sockaddr_in*)src;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0;
			si->sin_addr = ip->ip_src;
		}
	}
	else if (ip6hdr)
	{
		struct sockaddr_in6 *si;

		if (dst)
		{
			si = (struct sockaddr_in6*)dst;
			si->sin6_family = AF_INET6;
			si->sin6_port = tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0;
			si->sin6_addr = ip6hdr->ip6_dst;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}

		if (src)
		{
			si = (struct sockaddr_in6*)src;
			si->sin6_family = AF_INET6;
			si->sin6_port = tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0;
			si->sin6_addr = ip6hdr->ip6_src;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}
	}
}

const char *proto_name(uint8_t proto)
{
	switch(proto)
	{
		case IPPROTO_TCP:
			return "tcp";
		case IPPROTO_UDP:
			return "udp";
		case IPPROTO_ICMP:
			return "icmp";
		case IPPROTO_IGMP:
			return "igmp";
		case IPPROTO_ESP:
			return "esp";
		case IPPROTO_AH:
			return "ah";
		case IPPROTO_IPV6:
			return "6in4";
		case IPPROTO_IPIP:
			return "4in4";
		case IPPROTO_GRE:
			return "gre";
#ifdef IPPROTO_SCTP
		case IPPROTO_SCTP:
			return "sctp";
#endif
		default:
			return NULL;
	}
}
static void str_proto_name(char *s, size_t s_len, uint8_t proto)
{
	const char *name = proto_name(proto);
	if (name)
		snprintf(s,s_len,"%s",name);
	else
		snprintf(s,s_len,"%u",proto);
}
uint16_t family_from_proto(uint8_t l3proto)
{
	switch(l3proto)
	{
		case IPPROTO_IP: return AF_INET;
		case IPPROTO_IPV6: return AF_INET6;
		default: return -1;
	}
}

static void str_srcdst_ip(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[16],d_ip[16];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
static void str_ip(char *s, size_t s_len, const struct ip *ip)
{
	char ss[35],s_proto[16];
	str_srcdst_ip(ss,sizeof(ss),&ip->ip_src,&ip->ip_dst);
	str_proto_name(s_proto,sizeof(s_proto),ip->ip_p);
	snprintf(s,s_len,"%s proto=%s",ss,s_proto);
}
void print_ip(const struct ip *ip)
{
	char s[64];
	str_ip(s,sizeof(s),ip);
	printf("%s",s);
}
static void str_srcdst_ip6(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[40],d_ip[40];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET6, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET6, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
static void str_ip6hdr(char *s, size_t s_len, const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char ss[83],s_proto[16];
	str_srcdst_ip6(ss,sizeof(ss),&ip6hdr->ip6_src,&ip6hdr->ip6_dst);
	str_proto_name(s_proto,sizeof(s_proto),proto);
	snprintf(s,s_len,"%s proto=%s",ss,s_proto);
}
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char s[128];
	str_ip6hdr(s,sizeof(s),ip6hdr,proto);
	printf("%s",s);
}
static void str_tcphdr(char *s, size_t s_len, const struct tcphdr *tcphdr)
{
	char flags[7],*f=flags;
	if (tcphdr->th_flags & TH_SYN) *f++='S';
	if (tcphdr->th_flags & TH_ACK) *f++='A';
	if (tcphdr->th_flags & TH_RST) *f++='R';
	if (tcphdr->th_flags & TH_FIN) *f++='F';
	if (tcphdr->th_flags & TH_PUSH) *f++='P';
	if (tcphdr->th_flags & TH_URG) *f++='U';
	*f=0;
	snprintf(s,s_len,"sport=%u dport=%u flags=%s seq=%u ack_seq=%u",htons(tcphdr->th_sport),htons(tcphdr->th_dport),flags,htonl(tcphdr->th_seq),htonl(tcphdr->th_ack));
}
void print_tcphdr(const struct tcphdr *tcphdr)
{
	char s[80];
	str_tcphdr(s,sizeof(s),tcphdr);
	printf("%s",s);
}
static void str_udphdr(char *s, size_t s_len, const struct udphdr *udphdr)
{
	snprintf(s,s_len,"sport=%u dport=%u",htons(udphdr->uh_sport),htons(udphdr->uh_dport));
}
void print_udphdr(const struct udphdr *udphdr)
{
	char s[30];
	str_udphdr(s,sizeof(s),udphdr);
	printf("%s",s);
}




bool proto_check_ipv4(const uint8_t *data, size_t len)
{
	return 	len >= 20 && (data[0] & 0xF0) == 0x40 &&
		len >= ((data[0] & 0x0F) << 2);
}
// move to transport protocol
void proto_skip_ipv4(uint8_t **data, size_t *len)
{
	size_t l;

	l = (**data & 0x0F) << 2;
	*data += l;
	*len -= l;
}
bool proto_check_tcp(const uint8_t *data, size_t len)
{
	return len >= 20 && len >= ((data[12] & 0xF0) >> 2);
}
void proto_skip_tcp(uint8_t **data, size_t *len)
{
	size_t l;
	l = ((*data)[12] & 0xF0) >> 2;
	*data += l;
	*len -= l;
}
bool proto_check_udp(const uint8_t *data, size_t len)
{
	return len >= 8 && len>=(data[4]<<8 | data[5]);
}
void proto_skip_udp(uint8_t **data, size_t *len)
{
	*data += 8;
	*len -= 8;
}

bool proto_check_ipv6(const uint8_t *data, size_t len)
{
	return 	len >= 40 && (data[0] & 0xF0) == 0x60 &&
		(len - 40) >= htons(*(uint16_t*)(data + 4)); // payload length
}
// move to transport protocol
// proto_type = 0 => error
void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type, uint8_t **last_header_type)
{
	size_t hdrlen;
	uint8_t HeaderType;

	if (proto_type) *proto_type = 0; // put error in advance

	HeaderType = (*data)[6]; // NextHeader field
	if (last_header_type) *last_header_type = (*data)+6;
	*data += 40; *len -= 40; // skip ipv6 base header
	while (*len > 0) // need at least one byte for NextHeader field
	{
		switch (HeaderType)
		{
		case 0: // Hop-by-Hop Options
		case 43: // routing
		case 51: // authentication
		case 60: // Destination Options
		case 135: // mobility
		case 139: // Host Identity Protocol Version v2
		case 140: // Shim6
			if (*len < 2) return; // error
			hdrlen = 8 + ((*data)[1] << 3);
			break;
		case 44: // fragment. length fixed to 8, hdrlen field defined as reserved
			hdrlen = 8;
			break;
		case 59: // no next header
			return; // error
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			if (proto_type) *proto_type = HeaderType;
			return;
		}
		if (*len < hdrlen) return; // error
		HeaderType = **data;
		if (last_header_type) *last_header_type = *data;
		// advance to the next header location
		*len -= hdrlen;
		*data += hdrlen;
	}
	// we have garbage
}

bool tcp_synack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return ((tcphdr->th_flags & (TH_URG|TH_ACK|TH_PUSH|TH_RST|TH_SYN|TH_FIN)) == (TH_ACK|TH_SYN));
}
bool tcp_syn_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return ((tcphdr->th_flags & (TH_URG|TH_ACK|TH_PUSH|TH_RST|TH_SYN|TH_FIN)) == TH_SYN);
}
bool tcp_ack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return ((tcphdr->th_flags & (TH_URG|TH_ACK|TH_PUSH|TH_RST|TH_SYN|TH_FIN)) == TH_ACK);
}

void tcp_rewrite_wscale(struct tcphdr *tcp, uint8_t scale_factor)
{
	uint8_t *scale,scale_factor_old;

	if (scale_factor!=SCALE_NONE)
	{
		scale = tcp_find_option(tcp,3); // tcp option 3 - scale factor
		if (scale && scale[1]==3) // length should be 3
		{
			scale_factor_old=scale[2];
			// do not allow increasing scale factor
			if (scale_factor>=scale_factor_old)
				DLOG("Scale factor %u unchanged\n", scale_factor_old)
			else
			{
				scale[2]=scale_factor;
				DLOG("Scale factor change %u => %u\n", scale_factor_old, scale_factor)
			}
		}
	}
}
// scale_factor=SCALE_NONE - do not change
void tcp_rewrite_winsize(struct tcphdr *tcp, uint16_t winsize, uint8_t scale_factor)
{
	uint16_t winsize_old;

	winsize_old = htons(tcp->th_win); // << scale_factor;
	tcp->th_win = htons(winsize);
	DLOG("Window size change %u => %u\n", winsize_old, winsize)

	tcp_rewrite_wscale(tcp, scale_factor);
}





static int rawsend_sock4=-1, rawsend_sock6=-1;
static bool b_bind_fix4=false, b_bind_fix6=false;
static void rawsend_clean_sock(int *sock)
{
	if (sock && *sock!=-1)
	{
		close(*sock);
		*sock=-1;
	}
}
void rawsend_cleanup(void)
{
	rawsend_clean_sock(&rawsend_sock4);
	rawsend_clean_sock(&rawsend_sock6);
}
static int *rawsend_family_sock(sa_family_t family)
{
	switch(family)
	{
		case AF_INET: return &rawsend_sock4;
		case AF_INET6: return &rawsend_sock6;
		default: return NULL;
	}
}

#ifdef BSD
static int rawsend_socket_divert(sa_family_t family)
{
	// HACK HACK HACK HACK HACK HACK HACK HACK
	// FreeBSD doesnt allow IP_HDRINCL for IPV6
	// OpenBSD doesnt allow rawsending tcp frames
	// we either have to go to the link layer (its hard, possible problems arise, compat testing, ...) or use some HACKING
	// from my point of view disabling direct ability to send ip frames is not security. its SHIT

	int fd = socket(family, SOCK_RAW, IPPROTO_DIVERT);
	if (fd!=-1 && !set_socket_buffers(fd,4096,RAW_SNDBUF))
	{
		close(fd);
		return -1;
	}
	return fd;
}
static int rawsend_sendto_divert(sa_family_t family, int sock, const void *buf, size_t len)
{
	struct sockaddr_storage sa;
	socklen_t slen;

#ifdef __FreeBSD__
	// since FreeBSD 14 it requires hardcoded ipv4 values, although can also send ipv6 frames
	family = AF_INET;
	slen = sizeof(struct sockaddr_in);
#else
	// OpenBSD requires correct family and size
	switch(family)
	{
		case AF_INET:
			slen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			slen = sizeof(struct sockaddr_in6);
			break;
		default:
			return -1;
	}
#endif
	memset(&sa,0,slen);
	sa.ss_family = family;
	return sendto(sock, buf, len, 0, (struct sockaddr*)&sa, slen);
}
#endif

static int rawsend_socket_raw(int domain, int proto)
{
	int fd = socket(domain, SOCK_RAW, proto);
	if (fd!=-1)
	{
		#ifdef __linux__
		int s=RAW_SNDBUF/2;
		int r=2048;
		#else
		int s=RAW_SNDBUF;
		int r=4096;
		#endif
		if (!set_socket_buffers(fd,r,s))
		{
			close(fd);
			return -1;
		}
	}
	return fd;
}

static bool set_socket_fwmark(int sock, uint32_t fwmark)
{
#ifdef BSD
#ifdef SO_USER_COOKIE
	if (setsockopt(sock, SOL_SOCKET, SO_USER_COOKIE, &fwmark, sizeof(fwmark)) == -1)
	{
		perror("rawsend: setsockopt(SO_USER_COOKIE)");
		return false;
	}
#endif
#elif defined(__linux__)
	if (setsockopt(sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == -1)
	{
		perror("rawsend: setsockopt(SO_MARK)");
		return false;
	}

#endif
	return true;
}

static int rawsend_socket(sa_family_t family)
{
	int yes=1;
	int *sock = rawsend_family_sock(family);
	if (!sock) return -1;
	
	if (*sock==-1)
	{
		int yes=1,pri=6;
		//printf("rawsend_socket: family %d",family);

#ifdef __FreeBSD__
		// IPPROTO_RAW with ipv6 in FreeBSD always returns EACCES on sendto.
		// must use IPPROTO_TCP for ipv6. IPPROTO_RAW works for ipv4
		// divert sockets are always v4 but accept both v4 and v6
		*sock = (family==AF_INET) ? rawsend_socket_raw(family, IPPROTO_TCP) : rawsend_socket_divert(AF_INET);
#elif defined(__OpenBSD__) || defined (__APPLE__)
		// OpenBSD does not allow sending TCP frames through raw sockets
		// I dont know about macos. They have dropped ipfw in recent versions and their PF does not support divert-packet
		*sock = rawsend_socket_divert(family);
#else
		*sock = rawsend_socket_raw(family, IPPROTO_RAW);
#endif
		if (*sock==-1)
		{
			perror("rawsend: socket()");
			return -1;
		}
#ifdef BSD
#if !(defined(__OpenBSD__) || defined (__APPLE__))
		// HDRINCL not supported for ipv6 in any BSD
		if (family==AF_INET && setsockopt(*sock,IPPROTO_IP,IP_HDRINCL,&yes,sizeof(yes)) == -1)
		{
			perror("rawsend: setsockopt(IP_HDRINCL)");
			goto exiterr;
		}
#endif
#endif
#ifdef __linux__
		if (setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri)) == -1)
		{
			perror("rawsend: setsockopt(SO_PRIORITY)");
			goto exiterr;
		}
		if (family==AF_INET && setsockopt(*sock, IPPROTO_IP, IP_NODEFRAG, &yes, sizeof(yes)) == -1)
		{
			perror("rawsend: setsockopt(IP_NODEFRAG)");
			goto exiterr;
		}
		if (family==AF_INET && setsockopt(*sock, IPPROTO_IP, IP_FREEBIND, &yes, sizeof(yes)) == -1)
		{
			perror("rawsend: setsockopt(IP_FREEBIND)");
			goto exiterr;
		}
		if (family==AF_INET6 && setsockopt(*sock, SOL_IPV6, IPV6_FREEBIND, &yes, sizeof(yes)) == -1)
		{
			//perror("rawsend: setsockopt(IPV6_FREEBIND)");
			// dont error because it's supported only from kernel 4.15
		}
#endif
	}
	return *sock;
exiterr:
	rawsend_clean_sock(sock);
	return -1;
}
bool rawsend_preinit(bool bind_fix4, bool bind_fix6)
{
	b_bind_fix4 = bind_fix4;
	b_bind_fix6 = bind_fix6;
	// allow ipv6 disabled systems
	return rawsend_socket(AF_INET)!=-1 && (rawsend_socket(AF_INET6)!=-1 || errno==EAFNOSUPPORT);
}
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len)
{
	ssize_t bytes;
	int sock=rawsend_socket(dst->sa_family);
	if (sock==-1) return false;
	if (!set_socket_fwmark(sock,fwmark)) return false;

	int salen = dst->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	struct sockaddr_storage dst2;
	memcpy(&dst2,dst,salen);
	if (dst->sa_family==AF_INET6)
		((struct sockaddr_in6 *)&dst2)->sin6_port = 0; // or will be EINVAL in linux
#ifdef BSD
/*
		// this works only for local connections and not working for transit : cant spoof source addr
		if (len>=sizeof(struct ip6_hdr))
		{
			// BSD ipv6 raw socks are limited. cannot pass the whole packet with ip6 header.
			struct sockaddr_storage sa_src;
			int v;
			extract_endpoints(NULL,(struct ip6_hdr *)data,NULL,NULL, &sa_src, NULL);
			v = ((struct ip6_hdr *)data)->ip6_ctlun.ip6_un1.ip6_un1_hlim;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof(v)) == -1)
				perror("rawsend: setsockopt(IPV6_HOPLIMIT)");
			// the only way to control source address is bind. make it equal to ip6_hdr
			if (bind(sock, (struct sockaddr*)&sa_src, salen) < 0)
				perror("rawsend bind: ");
			//printf("BSD v6 RAWSEND "); print_sockaddr((struct sockaddr*)&sa_src); printf(" -> "); print_sockaddr((struct sockaddr*)&dst2); printf("\n");
			proto_skip_ipv6((uint8_t**)&data, &len, NULL);
		}
*/

#if !(defined(__OpenBSD__) || defined (__APPLE__))
	// OpenBSD doesnt allow rawsending tcp frames. always use divert socket
	if (dst->sa_family==AF_INET6)
#endif
	{
		ssize_t bytes = rawsend_sendto_divert(dst->sa_family,sock,data,len);
		if (bytes==-1)
		{
			perror("rawsend: sendto_divert");
			return false;
		}
		return true;
	}
#endif

#if defined(__FreeBSD__) && __FreeBSD__<=10
	// old FreeBSD requires some fields in host byte order
	if (dst->sa_family==AF_INET && len>=sizeof(struct ip))
	{
		((struct ip*)data)->ip_len = htons(((struct ip*)data)->ip_len);
		((struct ip*)data)->ip_off = htons(((struct ip*)data)->ip_off);
	}
#endif

#if defined(__linux__)
	struct sockaddr_storage sa_src;
	switch(dst->sa_family)
	{
		case AF_INET:
			if (!b_bind_fix4) goto nofix;
			extract_endpoints(data,NULL,NULL,NULL, &sa_src, NULL);
			break;
		case AF_INET6:
			if (!b_bind_fix6) goto nofix;
			extract_endpoints(NULL,data,NULL,NULL, &sa_src, NULL);
			break;
		default:
			return false; // should not happen
	}
	//printf("family %u dev %s bind : ",  dst->sa_family, ifout); print_sockaddr((struct sockaddr *)&sa_src); printf("\n");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifout, ifout ? strlen(ifout)+1 : 0) == -1)
	{
		perror("rawsend: setsockopt(SO_BINDTODEVICE)");
		return false;
	}
	if (bind(sock, (const struct sockaddr*)&sa_src, dst->sa_family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
	{
		perror("rawsend: bind (ignoring)");
		// do not fail. this can happen regardless of IP_FREEBIND
		// rebind to any address
		memset(&sa_src,0,sizeof(sa_src));
		sa_src.ss_family = dst->sa_family;
		if (bind(sock, (const struct sockaddr*)&sa_src, dst->sa_family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
		{
			perror("rawsend: bind to any");
			return false;
		}
	}
nofix:
#endif

	// normal raw socket sendto
	bytes = sendto(sock, data, len, 0, (struct sockaddr*)&dst2, salen);
#if defined(__FreeBSD) && __FreeBSD__<=10
	// restore byte order
	if (dst->sa_family==AF_INET && len>=sizeof(struct ip))
	{
		((struct ip*)data)->ip_len = htons(((struct ip*)data)->ip_len);
		((struct ip*)data)->ip_off = htons(((struct ip*)data)->ip_off);
	}
#endif
	if (bytes==-1)
	{
		perror("rawsend: sendto");
		return false;
	}
	return true;
}
