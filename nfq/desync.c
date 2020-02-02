#define _GNU_SOURCE

#include "desync.h"
#include "protocol.h"
#include "params.h"
#include "helpers.h"
#include "hostlist.h"

#include <string.h>


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

static uint8_t zeropkt[DPI_DESYNC_MAX_FAKE_LEN];

void desync_init()
{
	memset(zeropkt, 0, sizeof(zeropkt));
}


// result : true - drop original packet, false = dont drop
bool dpi_desync_packet(const uint8_t *data_pkt, size_t len_pkt, struct iphdr *iphdr, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, uint8_t *data_payload, size_t len_payload)
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
			if (params.hostlist && !bHaveHost)
			{
				DLOG("not applying dpi-desync to HTTP without Host:\n")
				return false;
			}
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
					DLOG("not applying dpi-desync to TLS ClientHello without hostname in the SNI\n")
					return false;
				}
			}
			
		}
		else
		{
			if (!params.desync_any_proto) return false;
			DLOG("applying dpi-desync to unknown protocol\n")
			fake = zeropkt;
			fake_size = 256;
		}

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			if (params.hostlist && !SearchHostList(params.hostlist,host,params.debug))
			{
				DLOG("not applying dpi-desync to this request\n")
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

		uint8_t newdata[DPI_DESYNC_MAX_FAKE_LEN+100];
		size_t newlen = sizeof(newdata);
		uint8_t ttl_orig = iphdr ? iphdr->ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
		uint8_t ttl_fake = params.desync_ttl ? params.desync_ttl : ttl_orig;
		uint8_t flags_orig = *((uint8_t*)tcphdr+13);
		uint32_t *timestamps = tcp_find_timestamps(tcphdr);

		switch(params.desync_mode)
		{
			case DESYNC_DISORDER:
			case DESYNC_DISORDER2:
				{
					size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (split_pos<len_payload)
					{
						DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu\n",split_pos,len_payload-1, len_payload-split_pos)
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->seq,split_pos), tcphdr->ack_seq, tcphdr->window, timestamps,
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
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
								ttl_fake,params.desync_tcp_fooling_mode,
								zeropkt, split_pos, fakeseg, &fakeseg_len) ||
							!rawsend((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
						{
							return false;
						}
					}


					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
					newlen = sizeof(newdata);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
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
			case DESYNC_SPLIT:
			case DESYNC_SPLIT2:
				{
					size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (params.desync_mode==DESYNC_SPLIT)
					{
						DLOG("sending fake(1) 1st tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
								ttl_fake,params.desync_tcp_fooling_mode,
								zeropkt, split_pos, fakeseg, &fakeseg_len) ||
							!rawsend((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
						{
							return false;
						}
					}

					DLOG("sending 1st tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
					newlen = sizeof(newdata);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
							ttl_orig,TCP_FOOL_NONE,
							data_payload, split_pos, newdata, &newlen) ||
						!rawsend((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
					{
						return false;
					}

					if (params.desync_mode==DESYNC_SPLIT)
					{
						DLOG("sending fake(2) 1st tcp segment 0-%zu len=%zu\n",split_pos-1, split_pos)
						if (!rawsend((struct sockaddr *)&dst, params.desync_fwmark, fakeseg, fakeseg_len))
							return false;
					}

					if (split_pos<len_payload)
					{
						DLOG("sending 2nd tcp segment %zu-%zu len=%zu\n",split_pos,len_payload-1, len_payload-split_pos)
						newlen = sizeof(newdata);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->seq,split_pos), tcphdr->ack_seq, tcphdr->window, timestamps,
								ttl_orig,TCP_FOOL_NONE,
								data_payload+split_pos, len_payload-split_pos, newdata, &newlen) ||
							!rawsend((struct sockaddr *)&dst, params.desync_fwmark, newdata, newlen))
						{
							return false;
						}
					}

					return true;
				}
				break;

			case DESYNC_FAKE:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
					ttl_fake,params.desync_tcp_fooling_mode,
					fake, fake_size, newdata, &newlen))
				{
					return false;
				}
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (params.desync_mode==DESYNC_RSTACK ? TH_ACK:0), tcphdr->seq, tcphdr->ack_seq, tcphdr->window, timestamps,
					ttl_fake,params.desync_tcp_fooling_mode,
					NULL, 0, newdata, &newlen))
				{
					return false;
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
