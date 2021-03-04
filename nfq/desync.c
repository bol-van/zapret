#define _GNU_SOURCE

#include "desync.h"
#include "protocol.h"
#include "params.h"
#include "helpers.h"
#include "hostlist.h"

#include <string.h>


const char *fake_http_request_default = "GET / HTTP/1.1\r\nHost: www.w3.org\r\n"
                                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n"
                                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                                        "Accept-Encoding: gzip, deflate\r\n\r\n";
const uint8_t fake_tls_clienthello_default[517] = {
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

#define PKT_MAXDUMP 32

static uint8_t zeropkt[DPI_DESYNC_MAX_FAKE_LEN];

void desync_init()
{
	memset(zeropkt, 0, sizeof(zeropkt));
}


bool desync_valid_first_stage(enum dpi_desync_mode mode)
{
	return mode==DESYNC_FAKE || mode==DESYNC_RST || mode==DESYNC_RSTACK;
}
bool desync_valid_second_stage(enum dpi_desync_mode mode)
{
	return mode==DESYNC_NONE || mode==DESYNC_DISORDER || mode==DESYNC_DISORDER2 || mode==DESYNC_SPLIT || mode==DESYNC_SPLIT2;
}
enum dpi_desync_mode desync_mode_from_string(const char *s)
{
	if (!s)
		return DESYNC_NONE;
	else if (!strcmp(s,"fake"))
		return DESYNC_FAKE;
	else if (!strcmp(s,"rst"))
		return DESYNC_RST;
	else if (!strcmp(s,"rstack"))
		return DESYNC_RSTACK;
	else if (!strcmp(s,"disorder"))
		return DESYNC_DISORDER;
	else if (!strcmp(s,"disorder2"))
		return DESYNC_DISORDER2;
	else if (!strcmp(s,"split"))
		return DESYNC_SPLIT;
	else if (!strcmp(s,"split2"))
		return DESYNC_SPLIT2;
	return DESYNC_INVALID;
}


// auto creates internal socket and uses it for subsequent calls
static bool rawsend_rep(const struct sockaddr* dst,uint32_t fwmark,const void *data,size_t len)
{
	for (int i=0;i<params.desync_repeats;i++)
		if (!rawsend(dst,fwmark,data,len))
			return false;
	return true;
}


// result : true - drop original packet, false = dont drop
packet_process_result dpi_desync_packet(uint8_t *data_pkt, size_t len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, size_t len_tcp, uint8_t *data_payload, size_t len_payload)
{
	packet_process_result res=pass;

	if (!!ip == !!ip6hdr) return res; // one and only one must be present
	if (params.desync_mode==DESYNC_NONE && !params.hostcase && !params.hostnospace && !params.domcase) return res; // nothing to do. do not waste cpu

	if (!(tcphdr->th_flags & TH_SYN) && len_payload)
	{
		struct sockaddr_storage src, dst;
		const uint8_t *fake;
		size_t fake_size;
		char host[256];
		bool bHaveHost=false;
		bool bIsHttp;
		uint8_t *p, *phost;

		if ((bIsHttp = IsHttp(data_payload,len_payload)))
		{
			DLOG("packet contains HTTP request\n")
			fake = params.fake_http;
			fake_size = params.fake_http_size;
			if (params.hostlist || params.debug) bHaveHost=HttpExtractHost(data_payload,len_payload,host,sizeof(host));
			if (params.hostlist && !bHaveHost)
			{
				DLOG("not applying tampering to HTTP without Host:\n")
				return res;
			}
		}
		else if (IsTLSClientHello(data_payload,len_payload))
		{
			DLOG("packet contains TLS ClientHello\n")
			fake = params.fake_tls;
			fake_size = params.fake_tls_size;
			if (params.hostlist || params.desync_skip_nosni || params.debug)
			{
				bHaveHost=TLSHelloExtractHost(data_payload,len_payload,host,sizeof(host));
				if (params.desync_skip_nosni && !bHaveHost)
				{
					DLOG("not applying tampering to TLS ClientHello without hostname in the SNI\n")
					return res;
				}
			}
		}
		else
		{
			if (!params.desync_any_proto) return res;
			DLOG("applying tampering to unknown protocol\n")
			fake = zeropkt;
			fake_size = 256;
		}

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			if (params.hostlist && !SearchHostList(params.hostlist,host,params.debug))
			{
				DLOG("not applying tampering to this request\n")
				return res;
			}
		}

		if (bIsHttp && (params.hostcase || params.hostnospace || params.domcase) && (phost = (uint8_t*)memmem(data_payload, len_payload, "\r\nHost: ", 8)))
		{
			if (params.hostcase)
			{
				DLOG("modifying Host: => %c%c%c%c:\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3])
				memcpy(phost + 2, params.hostspell, 4);
				res=modify;
			}
			if (params.domcase)
			{
				DLOG("mixing domain case\n");
				for (p = phost+7; p < (data_payload + len_payload) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
				res=modify;
			}
			uint8_t *pua;
			if (params.hostnospace &&
				(pua = (uint8_t*)memmem(data_payload, len_payload, "\r\nUser-Agent: ", 14)) &&
				(pua = (uint8_t*)memmem(pua + 1, len_payload - (pua - data_payload) - 1, "\r\n", 2)))
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
				res=modify;
			}
		}

		if (params.desync_mode==DESYNC_NONE) return res;

		extract_endpoints(ip, ip6hdr, tcphdr, &src, &dst);
		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}

		uint8_t newdata[DPI_DESYNC_MAX_FAKE_LEN+100];
		size_t newlen;
		uint8_t ttl_orig = ip ? ip->ip_ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
		uint8_t ttl_fake = params.desync_ttl ? params.desync_ttl : ttl_orig;
		uint8_t flags_orig = *((uint8_t*)tcphdr+13);
		uint32_t *timestamps = tcp_find_timestamps(tcphdr);
		enum dpi_desync_mode desync_mode = params.desync_mode;
		bool b;

		newlen = sizeof(newdata);
		b = false;
		switch(desync_mode)
		{
			case DESYNC_FAKE:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
					ttl_fake,params.desync_tcp_fooling_mode,
					fake, fake_size, newdata, &newlen))
				{
					return res;
				}
				DLOG("sending fake request : ");
				hexdump_limited_dlog(fake,fake_size,PKT_MAXDUMP); DLOG("\n")
				b = true;
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (desync_mode==DESYNC_RSTACK ? TH_ACK:0), tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
					ttl_fake,params.desync_tcp_fooling_mode,
					NULL, 0, newdata, &newlen))
				{
					return res;
				}
				DLOG("sending fake RST/RSTACK\n");
				b = true;
				break;
		}

		if (b)
		{
			if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
				return res;
			if (params.desync_mode2==DESYNC_NONE)
			{
					if (params.desync_retrans)
					{
						DLOG("dropping original packet to force retransmission. len=%zu len_payload=%zu\n", len_pkt, len_payload)
					}
					else
					{
						DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", len_pkt, len_payload)
						#ifdef __FreeBSD__
						// FreeBSD tend to pass ipv6 frames with wrong checksum
						if (res==modify || ip6hdr)
						#else
						// if original packet was tampered earlier it needs checksum fixed
						if (res==modify)
						#endif
							tcp_fix_checksum(tcphdr,len_tcp,ip,ip6hdr);
						if (!rawsend((struct sockaddr *)&dst, params.desync_fwmark, data_pkt, len_pkt))
							return res;
					}
					return drop;
			}
			desync_mode = params.desync_mode2;
		}

		newlen = sizeof(newdata);
		switch(desync_mode)
		{
			case DESYNC_DISORDER:
			case DESYNC_DISORDER2:
				{
					size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (split_pos<len_payload)
					{
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,split_pos), tcphdr->th_ack, tcphdr->th_win, timestamps,
								ttl_orig,TCP_FOOL_NONE,
								data_payload+split_pos, len_payload-split_pos, newdata, &newlen))
							return res;
						DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu : ",split_pos,len_payload-1, len_payload-split_pos)
						hexdump_limited_dlog(data_payload+split_pos,len_payload-split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
							return res;
					}


					if (desync_mode==DESYNC_DISORDER)
					{
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
								ttl_fake,params.desync_tcp_fooling_mode,
								zeropkt, split_pos, fakeseg, &fakeseg_len))
							return res;
						DLOG("sending fake(1) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return res;
					}


					newlen = sizeof(newdata);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
							ttl_orig,TCP_FOOL_NONE,
							data_payload, split_pos, newdata, &newlen))
						return res;
					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
					hexdump_limited_dlog(data_payload,split_pos,PKT_MAXDUMP); DLOG("\n")
					if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
						return res;

					if (desync_mode==DESYNC_DISORDER)
					{
						DLOG("sending fake(2) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return res;
					}

					return drop;
				}
				break;
			case DESYNC_SPLIT:
			case DESYNC_SPLIT2:
				{
					size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (desync_mode==DESYNC_SPLIT)
					{
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
								ttl_fake,params.desync_tcp_fooling_mode,
								zeropkt, split_pos, fakeseg, &fakeseg_len))
							return res;
						DLOG("sending fake(1) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return res;
					}

					newlen = sizeof(newdata);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, timestamps,
							ttl_orig,TCP_FOOL_NONE,
							data_payload, split_pos, newdata, &newlen))
						return res;
					DLOG("sending 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
					hexdump_limited_dlog(data_payload,split_pos,PKT_MAXDUMP); DLOG("\n")
					if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
						return res;

					if (desync_mode==DESYNC_SPLIT)
					{
						DLOG("sending fake(2) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return res;
					}

					if (split_pos<len_payload)
					{
						newlen = sizeof(newdata);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,split_pos), tcphdr->th_ack, tcphdr->th_win, timestamps,
								ttl_orig,TCP_FOOL_NONE,
								data_payload+split_pos, len_payload-split_pos, newdata, &newlen))
							return res;
						DLOG("sending 2nd tcp segment %zu-%zu len=%zu : ",split_pos,len_payload-1, len_payload-split_pos)
						hexdump_limited_dlog(data_payload+split_pos,len_payload-split_pos,PKT_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
							return res;
					}

					return drop;
				}
				break;
		}

		return res;
	}

	return res;
}
