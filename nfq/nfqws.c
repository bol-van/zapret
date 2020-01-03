#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "darkmagic.h"
#include "hostlist.h"
#include "sec.h"

#define NF_DROP 0
#define NF_ACCEPT 1


#define Q_RCVBUF	(128*1024)	// in bytes
#define Q_MAXLEN	1024		// in packets
#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000


static const char fake_http_request[] = "GET / HTTP/1.1\r\nHost: www.w3.org\r\n"
                                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n"
					"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                                        "Accept-Encoding: gzip, deflate\r\n\r\n";
static const uint8_t fake_https_request[] = {
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x9a, 0x8f, 0xa7, 0x6a, 0x5d,
    0x57, 0xf3, 0x62, 0x19, 0xbe, 0x46, 0x82, 0x45, 0xe2, 0x59, 0x5c, 0xb4, 0x48, 0x31, 0x12, 0x15,
    0x14, 0x79, 0x2c, 0xaa, 0xcd, 0xea, 0xda, 0xf0, 0xe1, 0xfd, 0xbb, 0x20, 0xf4, 0x83, 0x2a, 0x94,
    0xf1, 0x48, 0x3b, 0x9d, 0xb6, 0x74, 0xba, 0x3c, 0x81, 0x63, 0xbc, 0x18, 0xcc, 0x14, 0x45, 0x57,
    0x6c, 0x80, 0xf9, 0x25, 0xcf, 0x9c, 0x86, 0x60, 0x50, 0x31, 0x2e, 0xe9, 0x00, 0x22, 0x13, 0x01,
    0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
    0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35,
    0x01, 0x00, 0x01, 0x91, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x77, 0x77, 0x77,
    0x2e, 0x77, 0x33, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00,
    0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
    0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00,
    0x20, 0xb0, 0xe4, 0xda, 0x34, 0xb4, 0x29, 0x8d, 0xd3, 0x5c, 0x70, 0xd3, 0xbe, 0xe8, 0xa7, 0x2a,
    0x6b, 0xe4, 0x11, 0x19, 0x8b, 0x18, 0x9d, 0x83, 0x9a, 0x49, 0x7c, 0x83, 0x7f, 0xa9, 0x03, 0x8c,
    0x3c, 0x00, 0x17, 0x00, 0x41, 0x04, 0x4c, 0x04, 0xa4, 0x71, 0x4c, 0x49, 0x75, 0x55, 0xd1, 0x18,
    0x1e, 0x22, 0x62, 0x19, 0x53, 0x00, 0xde, 0x74, 0x2f, 0xb3, 0xde, 0x13, 0x54, 0xe6, 0x78, 0x07,
    0x94, 0x55, 0x0e, 0xb2, 0x6c, 0xb0, 0x03, 0xee, 0x79, 0xa9, 0x96, 0x1e, 0x0e, 0x98, 0x17, 0x78,
    0x24, 0x44, 0x0c, 0x88, 0x80, 0x06, 0x8b, 0xd4, 0x80, 0xbf, 0x67, 0x7c, 0x37, 0x6a, 0x5b, 0x46,
    0x4c, 0xa7, 0x98, 0x6f, 0xb9, 0x22, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03,
    0x02, 0x03, 0x01, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00,
    0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00, 0x96, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};


static uint8_t zeropkt[1500];


enum dpi_desync_mode {
	DESYNC_NONE=0,
	DESYNC_FAKE,
	DESYNC_RST,
	DESYNC_RSTACK,
	DESYNC_DISORDER,
	DESYNC_DISORDER2
};


struct params_s
{
	bool debug;
	int wsize;
	int qnum;
	bool hostcase, hostnospace;
	char hostspell[4];
	enum dpi_desync_mode desync_mode;
	bool desync_retrans,desync_skip_nosni;
	int desync_split_pos;
	uint8_t desync_ttl;
	enum tcp_fooling_mode desync_tcp_fooling_mode;
	uint32_t desync_fwmark;
	char hostfile[256];
	strpool *hostlist;
};

static struct params_s params;

#define DLOG(format, ...) {if (params.debug) printf(format, ##__VA_ARGS__);}


static bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	if (params.hostlist)
		printf("Will reload hostlist on next request\n");
	bHup = true;
}
// should be called in normal execution
static void dohup()
{
	if (bHup)
	{
		if (params.hostlist)
		{
			if (!LoadHostList(&params.hostlist, params.hostfile))
			{
				// what will we do without hostlist ?? sure, gonna die
				exit(1);
			}
		}
		bHup = false;
	}
}


static const uint8_t *find_bin_const(const uint8_t *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data++;
		len--;
	}
	return NULL;
}
static uint8_t *find_bin(uint8_t *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data++;
		len--;
	}
	return NULL;
}


static void print_sockaddr(const struct sockaddr *sa)
{
	char str[64];
	switch (sa->sa_family)
	{
	case AF_INET:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in6*)sa)->sin6_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		printf("UNKNOWN_FAMILY_%d", sa->sa_family);
	}
}


static bool proto_check_ipv4(uint8_t *data, size_t len)
{
	return 	len >= 20 && (data[0] & 0xF0) == 0x40 &&
		len >= ((data[0] & 0x0F) << 2);
}
// move to transport protocol
static void proto_skip_ipv4(uint8_t **data, size_t *len)
{
	size_t l;

	l = (**data & 0x0F) << 2;
	*data += l;
	*len -= l;
}
static bool proto_check_tcp(uint8_t *data, size_t len)
{
	return	len >= 20 && len >= ((data[12] & 0xF0) >> 2);
}
static void proto_skip_tcp(uint8_t **data, size_t *len)
{
	size_t l;
	l = ((*data)[12] & 0xF0) >> 2;
	*data += l;
	*len -= l;
}

static bool proto_check_ipv6(uint8_t *data, size_t len)
{
	return 	len >= 40 && (data[0] & 0xF0) == 0x60 &&
		(len - 40) >= htons(*(uint16_t*)(data + 4)); // payload length
}
// move to transport protocol
// proto_type = 0 => error
static void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type)
{
	size_t hdrlen;
	uint8_t HeaderType;

	*proto_type = 0; // put error in advance

	HeaderType = (*data)[6]; // NextHeader field
	*data += 40; *len -= 40; // skip ipv6 base header
	while (*len > 0) // need at least one byte for NextHeader field
	{
		switch (HeaderType)
		{
		case 0: // Hop-by-Hop Options
		case 60: // Destination Options
		case 43: // routing
			if (*len < 2) return; // error
			hdrlen = 8 + ((*data)[1] << 3);
			break;
		case 44: // fragment
			hdrlen = 8;
			break;
		case 59: // no next header
			return; // error
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			*proto_type = HeaderType;
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

static inline bool tcp_synack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return  tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->psh == 0 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 1 &&
		tcphdr->fin == 0;
}
static inline bool tcp_ack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return  tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 0 &&
		tcphdr->fin == 0;
}


static void tcp_rewrite_winsize(struct tcphdr *tcp, uint16_t winsize)
{
	uint16_t winsize_old;
	/*
		uint8_t scale_factor=1;
		int optlen = (tcp->doff << 2);
		uint8_t *opt = (uint8_t*)(tcp+1);

		optlen = optlen>sizeof(struct tcphdr) ? optlen-sizeof(struct tcphdr) : 0;
		printf("optslen=%d\n",optlen);
		while (optlen)
		{
		switch(*opt)
		{
			case 0: break; // end of option list;
			case 1: opt++; optlen--; break; // noop
			default:
			if (optlen<2 || optlen<opt[1]) break;
			if (*opt==3 && opt[1]>=3)
			{
				scale_factor=opt[2];
				printf("Found scale factor %u\n",opt[2]);
				//opt[2]=0;
			}
			optlen-=opt[1];
			opt+=opt[1];
		}
		}
	*/
	winsize_old = htons(tcp->window); // << scale_factor;
	tcp->window = htons(winsize);
	DLOG("Window size change %u => %u\n", winsize_old, winsize)
}



static const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
static bool IsHttp(const char *data, size_t len)
{
	const char **method;
	size_t method_len;
	for (method = http_methods; *method; method++)
	{
		method_len = strlen(*method);
		if (method_len <= len && !memcmp(data, *method, method_len))
			return true;
	}
	return false;
}
static bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	const uint8_t *p, *s, *e=data+len;

	p = find_bin_const(data, len, "\nHost:", 6);
	if (!p) return false;
	p+=6;
	while(p<e && (*p==' ' || *p=='\t')) p++;
	s=p;
	while(s<e && (*s!='\r' && *s!='\n' && *s!=' ' && *s!='\t')) s++;
	if (s>p)
	{
		size_t slen = s-p;
		if (host && len_host)
		{
			if (slen>=len_host) slen=len_host-1;
			for(size_t i=0;i<slen;i++) host[i]=tolower(p[i]);
			host[slen]=0;
		}
		return true;
	}
	return false;
}
static bool IsTLSClientHello(const uint8_t *data, size_t len)
{
	return len>=6 && data[0]==0x16 && data[1]==0x03 && data[2]==0x01 && data[5]==0x01 && (ntohs(*(uint16_t*)(data+3))+5)<=len;
}
static bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext)
{
	// +0
	// u8	ContentType: Handshake
	// u16	Version: TLS1.0
	// u16	Length
	// +5 
	// u8	HandshakeType: ClientHello
	// u24	Length
	// u16	Version
	// c[32] random
	// u8	SessionIDLength
	//	<SessionID>
	// u16	CipherSuitesLength
	//	<CipherSuites>
	// u8	CompressionMethodsLength
	//	<CompressionMethods>
	// u16	ExtensionsLength

	size_t l,ll;

	l = 1+2+2+1+3+2+32;
	// SessionIDLength
	if (len<(l+1)) return false;
	ll = data[6]<<16 | data[7]<<8 | data[8]; // HandshakeProtocol length
	if (len<(ll+9)) return false;
	l += data[l]+1;
	// CipherSuitesLength
	if (len<(l+2)) return false;
	l += ntohs(*(uint16_t*)(data+l))+2;
	// CompressionMethodsLength
	if (len<(l+1)) return false;
	l += data[l]+1;
	// ExtensionsLength
	if (len<(l+2)) return false;

	data+=l; len-=l;
	l=ntohs(*(uint16_t*)data);
	data+=2; len-=2;
	if (l<len) return false;

	uint16_t ntype=htons(type);
	while(l>=4)
	{
		uint16_t etype=*(uint16_t*)data;
		size_t elen=ntohs(*(uint16_t*)(data+2));
		data+=4; l-=4;
		if (l<elen) break;
		if (etype==ntype)
		{
			if (ext && len_ext)
			{
				*ext = data;
				*len_ext = elen;
			}
			return true;
		}
		data+=elen; l-=elen;
	}

	return false;
}
static bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data,len,0,&ext,&elen)) return false;
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (elen<5 || ext[2]!=0) return false;
	size_t slen = ntohs(*(uint16_t*)(ext+3));
	ext+=5; elen-=5;
	if (slen<elen) return false;
	if (ext && len_host)
	{
		if (slen>=len_host) slen=len_host-1;
		for(size_t i=0;i<slen;i++) host[i]=tolower(ext[i]);
		host[slen]=0;
	}
	return true;
}

// data/len points to data payload
static bool modify_tcp_packet(uint8_t *data, size_t len, struct tcphdr *tcphdr)
{
	const char **method;
	size_t method_len = 0;
	uint8_t *phost, *pua;
	bool bRet = false;

	if (params.wsize && tcp_synack_segment(tcphdr))
	{
		tcp_rewrite_winsize(tcphdr, (uint16_t)params.wsize);
		bRet = true;
	}

	if ((params.hostcase || params.hostnospace) && (phost = find_bin(data, len, "\r\nHost: ", 8)))
	{
		if (params.hostcase)
		{
			DLOG("modifying Host: => %c%c%c%c:\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3])
			memcpy(phost + 2, params.hostspell, 4);
			bRet = true;
		}
		if (params.hostnospace && (pua = find_bin(data, len, "\r\nUser-Agent: ", 14)) && (pua = find_bin(pua + 1, len - (pua - data) - 1, "\r\n", 2)))
		{
			DLOG("removing space after Host: and adding it to User-Agent:\n")
			if (pua > phost)
			{
				memmove(phost + 7, phost + 8, pua - phost - 8);
				phost[pua - phost - 1] = ' ';
			}
			else
			{
				memmove(pua + 1, pua, phost - pua + 7);
				*pua = ' ';
			}
			bRet = true;
		}
	}
	return bRet;
}



// result : true - drop original packet, false = dont drop
static bool dpi_desync_packet(const uint8_t *data_pkt, size_t len_pkt, const struct iphdr *iphdr, const struct ip6_hdr *ip6hdr, const struct tcphdr *tcphdr, const uint8_t *data_payload, size_t len_payload)
{
	if (!!iphdr == !!ip6hdr) return false; // one and only one must be present

	if (!tcphdr->syn && len_payload)
	{
		struct sockaddr_storage src, dst;
		const uint8_t *fake;
		size_t fake_size;
		char host[256];
		bool bHaveHost=false;

		if (IsHttp(data_payload,len_payload)) 
		{
			DLOG("packet contains HTTP request\n")
			fake = (uint8_t*)fake_http_request;
			fake_size = sizeof(fake_http_request);
			if (params.hostlist || params.debug) bHaveHost=HttpExtractHost(data_payload,len_payload,host,sizeof(host));
		}
		else if (IsTLSClientHello(data_payload,len_payload))
		{
			DLOG("packet contains TLS ClientHello\n")
			fake = (uint8_t*)fake_https_request;
			fake_size = sizeof(fake_https_request);
			if (params.hostlist || params.desync_skip_nosni || params.debug)
			{
				bHaveHost=TLSHelloExtractHost(data_payload,len_payload,host,sizeof(host));
				if (params.desync_skip_nosni && !bHaveHost)
				{
					DLOG("Not applying dpi-desync to TLS ClientHello without hostname in the SNI\n")
					return false;
				}
			}
			
		}
		else
			return false;

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			if (params.hostlist && !SearchHostList(params.hostlist,host,params.debug))
			{
				DLOG("Not applying dpi-desync to this request\n")
				return false;
			}
		}

		extract_endpoints(iphdr, ip6hdr, tcphdr, &src, &dst);
		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}

		uint8_t newdata[1600];
		size_t newlen = sizeof(newdata);
		uint8_t ttl_orig = iphdr ? iphdr->ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
		uint8_t ttl_fake = params.desync_ttl ? params.desync_ttl : ttl_orig;
		uint8_t flags_orig = *((uint8_t*)tcphdr+13);

		switch(params.desync_mode)
		{
			case DESYNC_FAKE:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq,
					ttl_fake,params.desync_tcp_fooling_mode,
					fake, fake_size, newdata, &newlen))
				{
					return false;
				}
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (params.desync_mode==DESYNC_RSTACK ? TH_ACK:0), tcphdr->seq, tcphdr->ack_seq,
					ttl_fake,params.desync_tcp_fooling_mode,
					NULL, 0, newdata, &newlen))
				{
					return false;
				}
				break;
			case DESYNC_DISORDER:
			case DESYNC_DISORDER2:
				{
					size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
					uint8_t fakeseg[1600];
					size_t fakeseg_len;

					if (split_pos<len_payload)
					{
						DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu\n",split_pos,len_payload-1, len_payload-split_pos)
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq+split_pos, tcphdr->ack_seq,
								ttl_orig,TCP_FOOL_NONE,
								data_payload+split_pos, len_payload-split_pos, newdata, &newlen) ||
							!rawsend((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
						{
							return false;
						}
					}


					if (params.desync_mode==DESYNC_DISORDER)
					{
						DLOG("sending fake(1) 1st out-of-order tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq,
								ttl_fake,params.desync_tcp_fooling_mode,
								zeropkt, split_pos, fakeseg, &fakeseg_len) ||
							!rawsend((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
						{
							return false;
						}
					}


					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
					newlen = sizeof(newdata);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq,
							ttl_orig,TCP_FOOL_NONE,
							data_payload, split_pos, newdata, &newlen) ||
						!rawsend((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
					{
						return false;
					}

					if (params.desync_mode==DESYNC_DISORDER)
					{
						DLOG("sending fake(2) 1st out-of-order tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
						if (!rawsend((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return false;
					}

					return true;
				}
				break;

			default:
				return false;
		}

		if (!rawsend((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
			return false;

		if (params.desync_retrans)
			DLOG("dropping packet to force retransmission. len=%zu len_payload=%zu\n", len_pkt, len_payload)
		else
		{
			DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", len_pkt, len_payload)
			if (!rawsend((struct sockaddr *)&dst, params.desync_fwmark, data_pkt, len_pkt))
				return false;
		}
		return true;
	}

	return false;
}


typedef enum
{
	pass = 0, modify, drop
} packet_process_result;
static packet_process_result processPacketData(uint8_t *data_pkt, size_t len_pkt, uint32_t *mark)
{
	struct iphdr *iphdr = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	struct tcphdr *tcphdr = NULL;
	size_t len = len_pkt, len_tcp;
	uint8_t *data = data_pkt;
	packet_process_result res = pass;
	uint8_t proto;

	if (proto_check_ipv4(data, len))
	{
		iphdr = (struct iphdr *) data;
		proto = iphdr->protocol;
		proto_skip_ipv4(&data, &len);
	}
	else if (proto_check_ipv6(data, len))
	{
		ip6hdr = (struct ip6_hdr *) data;
		proto_skip_ipv6(&data, &len, &proto);
	}
	else
	{
		// not ipv6 and not ipv4
		return res;
	}

	if (proto == IPPROTO_TCP && proto_check_tcp(data, len))
	{

		tcphdr = (struct tcphdr *) data;
		len_tcp = len;
		proto_skip_tcp(&data, &len);
		//DLOG("got TCP packet. payload_len=%d\n",len)

		if (params.desync_mode!=DESYNC_NONE && !(*mark & params.desync_fwmark))
		{
			if (dpi_desync_packet(data_pkt, len_pkt, iphdr, ip6hdr, tcphdr, data, len))
				res = drop;
		}

		if (res!=drop && modify_tcp_packet(data, len, tcphdr))
		{
			if (iphdr)
				tcp_fix_checksum(tcphdr, len_tcp, iphdr->saddr, iphdr->daddr);
			else
				tcp6_fix_checksum(tcphdr, len_tcp, &ip6hdr->ip6_src, &ip6hdr->ip6_dst);
			res = modify;
		}
	}
	return res;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *cookie)
{
	int id;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	uint32_t mark = nfq_get_nfmark(nfa);
	len = nfq_get_payload(nfa, &data);
	DLOG("packet: id=%d len=%zu\n", id, len)
	if (len >= 0)
	{
		switch (processPacketData(data, len, &mark))
		{
		case modify: return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, len, data);
		case drop: return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
		}
	}

	return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
}



static void exithelp()
{
	printf(
		" --debug=0|1\n"
		" --qnum=<nfqueue_number>\n"
		" --daemon\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t; write pid to file\n"
		" --user=<username>\t\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t\t; drop root privs\n"
		" --wsize=<window_size>\t\t\t; set window size. 0 = do not modify\n"
		" --hostcase\t\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostnospace\t\t\t\t; remove space after Host: and add it to User-Agent: to preserve packet size\n"
		" --dpi-desync[=<mode>]\t\t\t; try to desync dpi state. modes : fake rst rstack disorder disorder2\n"
		" --dpi-desync-fwmark=<int|0xHEX>\t; override fwmark for desync packet. default = 0x%08X\n"
		" --dpi-desync-ttl=<int>\t\t\t; set ttl for desync packet\n"
		" --dpi-desync-fooling=none|md5sig|badsum\n"
		" --dpi-desync-retrans=0|1\t\t; 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission\n"
		" --dpi-desync-skip-nosni=0|1\t\t; 1(default)=do not act on ClientHello without SNI (ESNI ?)\n"
		" --dpi-desync-split-pos=<1..%d>\t; (for disorder only) split TCP packet at specified position\n"
		" --hostlist=<filename>\t\t\t; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply)\n",
		DPI_DESYNC_FWMARK_DEFAULT,sizeof(zeropkt)
	);
	exit(1);
}

void cleanup_params()
{
	if (params.hostlist)
	{
		StrPoolDestroy(&params.hostlist);
		params.hostlist = NULL;
	}
}
void exithelp_clean()
{
	cleanup_params();
	exithelp();
}
void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}



int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));
	int option_index = 0;
	int v;
	bool daemon = false;
	uid_t uid = 0;
	gid_t gid = 0;
	char pidfile[256];

	srand(time(NULL));

	memset(zeropkt, 0, sizeof(zeropkt));

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	*pidfile = 0;

	params.desync_fwmark = DPI_DESYNC_FWMARK_DEFAULT;
	params.desync_skip_nosni = true;
	params.desync_split_pos = 3;

	const struct option long_options[] = {
		{"debug",optional_argument,0,0},	// optidx=0
		{"qnum",required_argument,0,0},		// optidx=1
		{"daemon",no_argument,0,0},		// optidx=2
		{"pidfile",required_argument,0,0},	// optidx=3
		{"user",required_argument,0,0 },	// optidx=4
		{"uid",required_argument,0,0 },		// optidx=5
		{"wsize",required_argument,0,0},	// optidx=6
		{"hostcase",no_argument,0,0},		// optidx=7
		{"hostspell",required_argument,0,0},	// optidx=8
		{"hostnospace",no_argument,0,0},	// optidx=9
		{"dpi-desync",optional_argument,0,0},		// optidx=10
		{"dpi-desync-fwmark",required_argument,0,0},	// optidx=11
		{"dpi-desync-ttl",required_argument,0,0},	// optidx=12
		{"dpi-desync-fooling",required_argument,0,0},	// optidx=13
		{"dpi-desync-retrans",optional_argument,0,0},	// optidx=14
		{"dpi-desync-skip-nosni",optional_argument,0,0},// optidx=15
		{"dpi-desync-split-pos",required_argument,0,0},// optidx=16
		{"hostlist",required_argument,0,0},		// optidx=17
		{NULL,0,NULL,0}
	};
	if (argc < 2) exithelp();
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* debug */
			params.debug = !optarg || atoi(optarg);
			break;
		case 1: /* qnum */
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				fprintf(stderr, "bad qnum\n");
				exit_clean(1);
			}
			break;
		case 2: /* daemon */
			daemon = true;
			break;
		case 3: /* pidfile */
			strncpy(pidfile, optarg, sizeof(pidfile));
			pidfile[sizeof(pidfile) - 1] = '\0';
			break;
		case 4: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			break;
		}
		case 5: /* uid */
			gid = 0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg, "%u:%u", &uid, &gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 6: /* wsize */
			params.wsize = atoi(optarg);
			if (params.wsize < 0 || params.wsize>65535)
			{
				fprintf(stderr, "bad wsize\n");
				exit_clean(1);
			}
			break;
		case 7: /* hostcase */
			params.hostcase = true;
			break;
		case 8: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			break;
		case 9: /* hostnospace */
			params.hostnospace = true;
			break;
		case 10: /* dpi-desync */
			if (!optarg || !strcmp(optarg,"fake"))
				params.desync_mode = DESYNC_FAKE;
			else if (!strcmp(optarg,"rst"))
				params.desync_mode = DESYNC_RST;
			else if (!strcmp(optarg,"rstack"))
				params.desync_mode = DESYNC_RSTACK;
			else if (!strcmp(optarg,"disorder"))
				params.desync_mode = DESYNC_DISORDER;
			else if (!strcmp(optarg,"disorder2"))
				params.desync_mode = DESYNC_DISORDER2;
			else
			{
				fprintf(stderr, "invalid dpi-desync mode\n");
				exit_clean(1);
			}
			break;
		case 11: /* dpi-desync */
			params.desync_fwmark = 0;
			if (!sscanf(optarg, "0x%X", &params.desync_fwmark)) sscanf(optarg, "%u", &params.desync_fwmark);
			if (!params.desync_fwmark)
			{
				fprintf(stderr, "dpi-desync-fwmark should be decimal or 0xHEX and should not be zero\n");
				exit_clean(1);
			}
			break;
		case 12: /* dpi-desync-ttl */
			params.desync_ttl = (uint8_t)atoi(optarg);
			break;
		case 13: /* dpi-desync-fooling */
			if (!strcmp(optarg,"none"))
				params.desync_tcp_fooling_mode = TCP_FOOL_NONE;
			else if (!strcmp(optarg,"md5sig"))
				params.desync_tcp_fooling_mode = TCP_FOOL_MD5SIG;
			else if (!strcmp(optarg,"badsum"))
				params.desync_tcp_fooling_mode = TCP_FOOL_BADSUM;
			else
			{
				fprintf(stderr, "dpi-desync-fooling allowed values : none,md5sig,badsum\n");
				exit_clean(1);
			}
			break;
		case 14: /* dpi-desync-retrans */
			params.desync_retrans = !optarg || atoi(optarg);
			break;
		case 15: /* dpi-desync-skip-nosni */
			params.desync_skip_nosni = !optarg || atoi(optarg);
			break;
		case 16: /* dpi-desync-split-pos */
			params.desync_split_pos = atoi(optarg);
			if (params.desync_split_pos<1 || params.desync_split_pos>sizeof(zeropkt))
			{
				fprintf(stderr, "dpi-desync-split-pos must be within 1..%u range\n",sizeof(zeropkt));
				exit_clean(1);
			}
			break;
		case 17: /* hostlist */
			if (!LoadHostList(&params.hostlist, optarg))
				exit_clean(1);
			strncpy(params.hostfile,optarg,sizeof(params.hostfile));
			params.hostfile[sizeof(params.hostfile)-1]='\0';
			break;
		}
	}

	if (params.desync_mode==DESYNC_NONE && params.hostlist)
	{
		fprintf(stderr, "hostlist is applicable only to dpi-desync\n");
		exit_clean(1);
	}

	if (daemon) daemonize();

	h = NULL;
	qh = NULL;

	if (*pidfile && !writepid(pidfile))
	{
		fprintf(stderr, "could not write pidfile\n");
		goto exiterr;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		goto exiterr;
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		goto exiterr;
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		goto exiterr;
	}

	printf("binding this socket to queue '%u'\n", params.qnum);
	qh = nfq_create_queue(h, params.qnum, &cb, &params);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		goto exiterr;
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		goto exiterr;
	}
	if (nfq_set_queue_maxlen(qh, Q_MAXLEN) < 0) {
		fprintf(stderr, "can't set queue maxlen\n");
		goto exiterr;
	}
	// accept packets if they cant be handled
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN))
	{
		fprintf(stderr, "can't set queue flags. errno=%d\n", errno);
		// dot not fail. not supported on old linuxes <3.6 
	}

	if (!droproot(uid, gid)) goto exiterr;
	printf("Running as UID=%u GID=%u\n", getuid(), getgid());

	signal(SIGHUP, onhup); 

	fd = nfq_fd(h);

	// increase socket buffer size. on slow systems reloading hostlist can take a while.
	// if too many unhandled packets are received its possible to get "no buffer space available" error
	rv = Q_RCVBUF/2;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rv, sizeof(int)) <0)
	{
		perror("setsockopt (SO_RCVBUF): ");
		goto exiterr;
	}
	do
	{
		while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
		{
			dohup();
			int r = nfq_handle_packet(h, buf, rv);
			if (r) fprintf(stderr, "nfq_handle_packet error %d\n", r);
		}
		fprintf(stderr, "recv: errno %d\n",errno);
		perror("recv");
		// do not fail on ENOBUFS
	} while(errno==ENOBUFS);

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	rawsend_cleanup();
	cleanup_params();
	return 0;

exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	cleanup_params();
	return 1;
}
