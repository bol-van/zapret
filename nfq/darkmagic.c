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

static void fill_tcphdr(struct tcphdr *tcp, uint8_t tcp_flags, uint32_t seq, uint32_t ack_seq, uint8_t fooling, uint16_t nsport, uint16_t ndport, uint16_t nwsize, uint32_t *timestamps)
{
	char *tcpopt = (char*)(tcp+1);
	uint8_t t=0;

	memset(tcp,0,sizeof(*tcp));
	tcp->th_sport     = nsport;
	tcp->th_dport       = ndport;
	if (fooling & TCP_FOOL_BADSEQ)
	{
		tcp->th_seq        = net32_add(seq,0x80000000);
		tcp->th_ack    = net32_add(ack_seq,0x80000000);
	}
	else
	{
		tcp->th_seq        = seq;
		tcp->th_ack    = ack_seq;
	}
	tcp->th_off       = 5;
	*((uint8_t*)tcp+13)= tcp_flags;
	tcp->th_win     = nwsize;
	if (fooling & TCP_FOOL_MD5SIG)
	{
		tcpopt[0] = 19; // kind
		tcpopt[1] = 18; // len
		*(uint32_t*)(tcpopt+2)=random();
		*(uint32_t*)(tcpopt+6)=random();
		*(uint32_t*)(tcpopt+10)=random();
		*(uint32_t*)(tcpopt+14)=random();
		t=18;
	}
	if (timestamps || (fooling & TCP_FOOL_TS))
	{
		tcpopt[t] = 8; // kind
		tcpopt[t+1] = 10; // len
		// forge only TSecr if orig timestamp is present
		*(uint32_t*)(tcpopt+t+2) = timestamps ? timestamps[0] : -1;
		*(uint32_t*)(tcpopt+t+6) = (timestamps && !(fooling & TCP_FOOL_TS)) ? timestamps[1] : -1;
		t+=10;
	}
	while (t&3) tcpopt[t++]=1; // noop
	tcp->th_off += t>>2;
}
static uint16_t tcpopt_len(uint8_t fooling, uint32_t *timestamps)
{
	uint16_t t=0;
	if (fooling & TCP_FOOL_MD5SIG) t=18;
	if ((fooling & TCP_FOOL_TS) || timestamps) t+=10;
	return (t+3)&~3;
}

static int rawsend_sock4=-1, rawsend_sock6=-1;
static void rawsend_clean_sock(int *sock)
{
	if (sock && *sock!=-1)
	{
		close(*sock);
		*sock=-1;
	}
}
void rawsend_cleanup()
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
	if (!set_socket_buffers(fd,4096,RAW_SNDBUF))
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

	memset(&sa,0,sizeof(sa));
	sa.ss_family = family;
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

static int rawsend_socket(sa_family_t family,uint32_t fwmark)
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
#ifdef SO_USER_COOKIE
		if (setsockopt(*sock, SOL_SOCKET, SO_USER_COOKIE, &fwmark, sizeof(fwmark)) == -1)
		{
			perror("rawsend: setsockopt(SO_MARK)");
			goto exiterr;
		}
#endif
#endif
#ifdef __linux__
		if (setsockopt(*sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == -1)
		{
			perror("rawsend: setsockopt(SO_MARK)");
			goto exiterr;
		}
		if (setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri)) == -1)
		{
			perror("rawsend: setsockopt(SO_PRIORITY)");
			goto exiterr;
		}
#endif
	}
	return *sock;
exiterr:
	rawsend_clean_sock(sock);
	return -1;
}
bool rawsend_preinit(uint32_t fwmark)
{
	return rawsend_socket(AF_INET,fwmark)!=-1 && rawsend_socket(AF_INET6,fwmark)!=-1;
}
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len)
{
	int sock=rawsend_socket(dst->sa_family,fwmark);
	if (sock==-1) return false;
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
			extract_endpoints(NULL,(struct ip6_hdr *)data,NULL, &sa_src, NULL);
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
	// old FreeBSD requires some fields in the host byte order
	if (dst->sa_family==AF_INET && len>=sizeof(struct ip))
	{
		((struct ip*)data)->ip_len = htons(((struct ip*)data)->ip_len);
		((struct ip*)data)->ip_off = htons(((struct ip*)data)->ip_off);
	}
#endif
	// normal raw socket sendto
	ssize_t bytes = sendto(sock, data, len, 0, (struct sockaddr*)&dst2, salen);
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
bool prepare_tcp_segment4(
	const struct sockaddr_in *src, const struct sockaddr_in *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps);
	uint16_t pktlen = sizeof(struct ip) + sizeof(struct tcphdr) + tcpoptlen  + len;
	if (pktlen>*buflen)
	{
		fprintf(stderr,"prepare_tcp_segment : packet len cannot exceed %zu\n",*buflen);
		return false;
	}

	struct ip *ip = (struct ip*) buf;
	struct tcphdr *tcp = (struct tcphdr*) (ip+1);

	ip->ip_off = 0;
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = htons(pktlen);
	ip->ip_id = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src = src->sin_addr;
	ip->ip_dst = dst->sin_addr;

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin_port,dst->sin_port,wsize,timestamps);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp4_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,&ip->ip_src,&ip->ip_dst);
	if (fooling & TCP_FOOL_BADSUM) tcp->th_sum^=0xBEAF;

	*buflen = pktlen;
	return true;
}


bool prepare_tcp_segment6(
	const struct sockaddr_in6 *src, const struct sockaddr_in6 *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	uint16_t tcpoptlen = tcpopt_len(fooling,timestamps);
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

	fill_tcphdr(tcp,tcp_flags,seq,ack_seq,fooling,src->sin6_port,dst->sin6_port,wsize,timestamps);

	memcpy((char*)tcp+sizeof(struct tcphdr)+tcpoptlen,data,len);
	tcp6_fix_checksum(tcp,sizeof(struct tcphdr)+tcpoptlen+len,&ip6->ip6_src,&ip6->ip6_dst);
	if (fooling & TCP_FOOL_BADSUM) tcp->th_sum^=0xBEAF;

	*buflen = pktlen;
	return true;
}

bool prepare_tcp_segment(
	const struct sockaddr *src, const struct sockaddr *dst,
	uint8_t tcp_flags,
	uint32_t seq, uint32_t ack_seq,
	uint16_t wsize,
	uint32_t *timestamps,
	uint8_t ttl,
	uint8_t fooling,
	const void *data, uint16_t len,
	uint8_t *buf, size_t *buflen)
{
	return (src->sa_family==AF_INET && dst->sa_family==AF_INET) ?
		prepare_tcp_segment4((struct sockaddr_in *)src,(struct sockaddr_in *)dst,tcp_flags,seq,ack_seq,wsize,timestamps,ttl,fooling,data,len,buf,buflen) :
		(src->sa_family==AF_INET6 && dst->sa_family==AF_INET6) ?
		prepare_tcp_segment6((struct sockaddr_in6 *)src,(struct sockaddr_in6 *)dst,tcp_flags,seq,ack_seq,wsize,timestamps,ttl,fooling,data,len,buf,buflen) :
		false;
}


void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	if (ip)
	{
		struct sockaddr_in *si;

		if (dst)
		{
			si = (struct sockaddr_in*)dst;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_dport : 0;
			si->sin_addr = ip->ip_dst;
		}

		if (src)
		{
			si = (struct sockaddr_in*)src;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_sport : 0;
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
			si->sin6_port = tcphdr ? tcphdr->th_dport : 0;
			si->sin6_addr = ip6hdr->ip6_dst;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}

		if (src)
		{
			si = (struct sockaddr_in6*)src;
			si->sin6_family = AF_INET6;
			si->sin6_port = tcphdr ? tcphdr->th_sport : 0;
			si->sin6_addr = ip6hdr->ip6_src;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}
	}
}

static const char *proto_name(uint8_t proto)
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
	char ss[64],s_proto[16];
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
	char ss[128],s_proto[16];
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




bool proto_check_ipv4(uint8_t *data, size_t len)
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
bool proto_check_tcp(uint8_t *data, size_t len)
{
	return	len >= 20 && len >= ((data[12] & 0xF0) >> 2);
}
void proto_skip_tcp(uint8_t **data, size_t *len)
{
	size_t l;
	l = ((*data)[12] & 0xF0) >> 2;
	*data += l;
	*len -= l;
}

bool proto_check_ipv6(uint8_t *data, size_t len)
{
	return 	len >= 40 && (data[0] & 0xF0) == 0x60 &&
		(len - 40) >= htons(*(uint16_t*)(data + 4)); // payload length
}
// move to transport protocol
// proto_type = 0 => error
void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type)
{
	size_t hdrlen;
	uint8_t HeaderType;

	if (proto_type) *proto_type = 0; // put error in advance

	HeaderType = (*data)[6]; // NextHeader field
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
