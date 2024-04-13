#define _GNU_SOURCE

#include "desync.h"
#include "protocol.h"
#include "params.h"
#include "helpers.h"
#include "hostlist.h"
#include "conntrack.h"

#include <string.h>


const char *fake_http_request_default = "GET / HTTP/1.1\r\nHost: www.iana.org\r\n"
                                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n"
                                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                                        "Accept-Encoding: gzip, deflate, br\r\n\r\n";

const uint8_t fake_tls_clienthello_default[517] = {
  0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03, 0x6F, 0x0B, 0xB6, 0x85, 0x58, 0x28, 0x59, 0xD5, 0x0D, 0x6C, 0x78, 0x39, 0x7F, 0x2B, 0x0B, 0x45, 0xA3, 0x71, 0x4F, 0x49, 0xD6, 0x34, 0x17, 0xC6, 0x59, 0xA5, 0x1D, 0x89, 0x01,
  0xE1, 0x72, 0x1D, 0x20, 0x9D, 0x2C, 0xAB, 0x26, 0x58, 0xA7, 0x83, 0xBF, 0xB7, 0xDC, 0x5F, 0x28, 0xAA, 0x11, 0xA7, 0x63, 0x54, 0x19, 0xCB, 0xC6, 0xC4, 0x0E, 0xA4, 0x15, 0x46, 0xCC, 0x2F, 0x25, 0x13, 0x9A, 0x14, 0x54, 0x00, 0x3E, 0x13, 0x02,
  0x13, 0x03, 0x13, 0x01, 0xC0, 0x2C, 0xC0, 0x30, 0x00, 0x9F, 0xCC, 0xA9, 0xCC, 0xA8, 0xCC, 0xAA, 0xC0, 0x2B, 0xC0, 0x2F, 0x00, 0x9E, 0xC0, 0x24, 0xC0, 0x28, 0x00, 0x6B, 0xC0, 0x23, 0xC0, 0x27, 0x00, 0x67, 0xC0, 0x0A, 0xC0, 0x14, 0x00, 0x39,
  0xC0, 0x09, 0xC0, 0x13, 0x00, 0x33, 0x00, 0x9D, 0x00, 0x9C, 0x00, 0x3D, 0x00, 0x3C, 0x00, 0x35, 0x00, 0x2F, 0x00, 0xFF, 0x01, 0x00, 0x01, 0x75, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x0B, 0x00, 0x00, 0x08, 0x69, 0x61, 0x6E, 0x61, 0x2E, 0x6F, 0x72,
  0x67, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0A, 0x00, 0x0C, 0x00, 0x0A, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x1E, 0x00, 0x19, 0x00, 0x18, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x0C, 0x02, 0x68, 0x32, 0x08, 0x68,
  0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x30, 0x00, 0x2E, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0A, 0x08,
  0x0B, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2B, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03,
  0x03, 0x02, 0x03, 0x01, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20, 0x1B, 0xB3, 0xF5, 0x23, 0x6E, 0x05, 0x98, 0x5D, 0x92, 0x30, 0x8A, 0xAC, 0x64, 0x61, 0x1F, 0xD7, 0x0A, 0x6D, 0xB1, 0xA5,
  0x74, 0xF9, 0x44, 0x07, 0xC0, 0x55, 0xD8, 0x8B, 0x0C, 0xEA, 0x29, 0x27, 0x00, 0x15, 0x00, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define PKTDATA_MAXDUMP 32
#define IP_MAXDUMP 80

static uint8_t zeropkt[DPI_DESYNC_MAX_FAKE_LEN];

void desync_init(void)
{
	memset(zeropkt, 0, sizeof(zeropkt));
}


bool desync_valid_zero_stage(enum dpi_desync_mode mode)
{
	return mode==DESYNC_SYNACK || mode==DESYNC_SYNDATA;
}
bool desync_valid_first_stage(enum dpi_desync_mode mode)
{
	return mode==DESYNC_FAKE || mode==DESYNC_FAKE_KNOWN || mode==DESYNC_RST || mode==DESYNC_RSTACK || mode==DESYNC_HOPBYHOP || mode==DESYNC_DESTOPT || mode==DESYNC_IPFRAG1;
}
bool desync_only_first_stage(enum dpi_desync_mode mode)
{
	return false;
}
bool desync_valid_second_stage(enum dpi_desync_mode mode)
{
	return mode==DESYNC_NONE || mode==DESYNC_DISORDER || mode==DESYNC_DISORDER2 || mode==DESYNC_SPLIT || mode==DESYNC_SPLIT2 || mode==DESYNC_IPFRAG2 || mode==DESYNC_UDPLEN || mode==DESYNC_TAMPER;
}
bool desync_valid_second_stage_tcp(enum dpi_desync_mode mode)
{
	return mode==DESYNC_NONE || mode==DESYNC_DISORDER || mode==DESYNC_DISORDER2 || mode==DESYNC_SPLIT || mode==DESYNC_SPLIT2 || mode==DESYNC_IPFRAG2;
}
bool desync_valid_second_stage_udp(enum dpi_desync_mode mode)
{
	return mode==DESYNC_NONE || mode==DESYNC_UDPLEN || mode==DESYNC_TAMPER || mode==DESYNC_IPFRAG2;
}
enum dpi_desync_mode desync_mode_from_string(const char *s)
{
	if (!s)
		return DESYNC_NONE;
	else if (!strcmp(s,"fake"))
		return DESYNC_FAKE;
	else if (!strcmp(s,"fakeknown"))
		return DESYNC_FAKE_KNOWN;
	else if (!strcmp(s,"rst"))
		return DESYNC_RST;
	else if (!strcmp(s,"rstack"))
		return DESYNC_RSTACK;
	else if (!strcmp(s,"synack"))
		return DESYNC_SYNACK;
	else if (!strcmp(s,"syndata"))
		return DESYNC_SYNDATA;
	else if (!strcmp(s,"disorder"))
		return DESYNC_DISORDER;
	else if (!strcmp(s,"disorder2"))
		return DESYNC_DISORDER2;
	else if (!strcmp(s,"split"))
		return DESYNC_SPLIT;
	else if (!strcmp(s,"split2"))
		return DESYNC_SPLIT2;
	else if (!strcmp(s,"ipfrag2"))
		return DESYNC_IPFRAG2;
	else if (!strcmp(s,"hopbyhop"))
		return DESYNC_HOPBYHOP;
	else if (!strcmp(s,"destopt"))
		return DESYNC_DESTOPT;
	else if (!strcmp(s,"ipfrag1"))
		return DESYNC_IPFRAG1;
	else if (!strcmp(s,"udplen"))
		return DESYNC_UDPLEN;
	else if (!strcmp(s,"tamper"))
		return DESYNC_TAMPER;
	return DESYNC_INVALID;
}


// auto creates internal socket and uses it for subsequent calls
static bool rawsend_rep(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len)
{
	for (int i=0;i<params.desync_repeats;i++)
		if (!rawsend(dst,fwmark,ifout,data,len))
			return false;
	return true;
}


static uint64_t cutoff_get_limit(const t_ctrack *ctrack, char mode)
{
	switch(mode)
	{
		case 'n': return ctrack->pcounter_orig;
		case 'd': return ctrack->pdcounter_orig;
		case 's': return ctrack->seq_last - ctrack->seq0;
		default: return 0;
	}
}
static bool cutoff_test(const t_ctrack *ctrack, uint64_t cutoff, char mode)
{
	return cutoff && cutoff_get_limit(ctrack, mode)>=cutoff;
}
static void maybe_cutoff(t_ctrack *ctrack, uint8_t proto)
{
	if (ctrack)
	{
		if (proto==IPPROTO_TCP)
			ctrack->b_wssize_cutoff |= cutoff_test(ctrack, params.wssize_cutoff, params.wssize_cutoff_mode);
		ctrack->b_desync_cutoff |= cutoff_test(ctrack, params.desync_cutoff, params.desync_cutoff_mode);

		// we do not need conntrack entry anymore if all cutoff conditions are either not defined or reached
		// do not drop udp entry because it will be recreated when next packet arrives
		if (proto==IPPROTO_TCP)
			ctrack->b_cutoff |= \
			    (!params.wssize || ctrack->b_wssize_cutoff) &&
			    (!params.desync_cutoff || ctrack->b_desync_cutoff) &&
			    (!*params.hostlist_auto_filename || ctrack->req_retrans_counter==RETRANS_COUNTER_STOP) &&
			    ReasmIsEmpty(&ctrack->reasm_orig);
	}
}
static void wssize_cutoff(t_ctrack *ctrack)
{
	if (ctrack)
	{
		ctrack->b_wssize_cutoff = true;
		maybe_cutoff(ctrack, IPPROTO_TCP);
	}
}
static void forced_wssize_cutoff(t_ctrack *ctrack)
{
 	if (ctrack && params.wssize && !ctrack->b_wssize_cutoff)
	{
		DLOG("forced wssize-cutoff\n");
		wssize_cutoff(ctrack);
	}
}

static void ctrack_stop_retrans_counter(t_ctrack *ctrack)
{
	if (ctrack && *params.hostlist_auto_filename)
	{
		ctrack->req_retrans_counter = RETRANS_COUNTER_STOP;
		maybe_cutoff(ctrack, IPPROTO_TCP);
	}
}

// return true if retrans trigger fires
static bool auto_hostlist_retrans(t_ctrack *ctrack, uint8_t l4proto, int threshold)
{
	if (*params.hostlist_auto_filename && ctrack && ctrack->req_retrans_counter!=RETRANS_COUNTER_STOP)
	{
		if (l4proto==IPPROTO_TCP)
		{
			if (!ctrack->req_seq_present)
				return false;
			if (!seq_within(ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end))
			{
				DLOG("req retrans : tcp seq %u not within the req range %u-%u. stop tracking.\n", ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end);
				ctrack_stop_retrans_counter(ctrack);
				ctrack->req_seq_present = false;
				return false;
			}
		}
		ctrack->req_retrans_counter++;
		if (ctrack->req_retrans_counter >= threshold)
		{
			DLOG("req retrans threshold reached : %u/%u\n",ctrack->req_retrans_counter, threshold);
			ctrack_stop_retrans_counter(ctrack);
			return true;
		}
		DLOG("req retrans counter : %u/%u\n",ctrack->req_retrans_counter, threshold);
	}
	return false;
}
static void auto_hostlist_failed(const char *hostname)
{
	hostfail_pool *fail_counter;
	
	fail_counter = HostFailPoolFind(params.hostlist_auto_fail_counters, hostname);
	if (!fail_counter)
	{
		fail_counter = HostFailPoolAdd(&params.hostlist_auto_fail_counters, hostname, params.hostlist_auto_fail_time);
		if (!fail_counter)
		{
			fprintf(stderr, "HostFailPoolAdd: out of memory\n");
			return;
		}
	}
	fail_counter->counter++;
	DLOG("auto hostlist : %s : fail counter %d/%d\n", hostname, fail_counter->counter, params.hostlist_auto_fail_threshold);
	HOSTLIST_DEBUGLOG_APPEND("%s : fail counter %d/%d", hostname, fail_counter->counter, params.hostlist_auto_fail_threshold);
	if (fail_counter->counter >= params.hostlist_auto_fail_threshold)
	{
		DLOG("auto hostlist : fail threshold reached. about to add %s to auto hostlist\n", hostname);
		HostFailPoolDel(&params.hostlist_auto_fail_counters, fail_counter);
		
		DLOG("auto hostlist : rechecking %s to avoid duplicates\n", hostname);
		bool bExcluded=false;
		if (!HostlistCheck(hostname, &bExcluded) && !bExcluded)
		{
			DLOG("auto hostlist : adding %s\n", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : adding", hostname);
			if (!StrPoolAddStr(&params.hostlist, hostname))
			{
				fprintf(stderr, "StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(params.hostlist_auto_filename, hostname))
			{
				perror("write to auto hostlist:");
				return;
			}
			params.hostlist_auto_mod_time = file_mod_time(params.hostlist_auto_filename);
		}
		else
		{
			DLOG("auto hostlist : NOT adding %s\n", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : NOT adding, duplicate detected", hostname);
		}
	}
}

static void process_retrans_fail(t_ctrack *ctrack, uint8_t proto)
{
	if (ctrack && ctrack->hostname && auto_hostlist_retrans(ctrack, proto, params.hostlist_auto_retrans_threshold))
	{
		HOSTLIST_DEBUGLOG_APPEND("%s : tcp retrans threshold reached", ctrack->hostname);
		auto_hostlist_failed(ctrack->hostname);
	}
}

static bool reasm_start(t_ctrack *ctrack, t_reassemble *reasm, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	ReasmClear(reasm);
	if (sz<=szMax)
	{
		if (ReasmInit(reasm,sz,ctrack->seq_last))
		{
			ReasmFeed(reasm,ctrack->seq_last,data_payload,len_payload);
			DLOG("starting reassemble. now we have %zu/%zu\n",reasm->size_present,reasm->size);
			return true;
		}
		else
			DLOG("reassemble init failed. out of memory\n");
	}
	else
		DLOG("unexpected large payload for reassemble: size=%zu\n",sz);
	return false;
}
static bool reasm_orig_start(t_ctrack *ctrack, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	return reasm_start(ctrack,&ctrack->reasm_orig,sz,szMax,data_payload,len_payload);
}
static bool reasm_feed(t_ctrack *ctrack, t_reassemble *reasm, const uint8_t *data_payload, size_t len_payload)
{
	if (ctrack && !ReasmIsEmpty(reasm))
	{
		if (ReasmFeed(reasm,ctrack->seq_last,data_payload,len_payload))
		{
			DLOG("reassemble : feeding data payload size=%zu. now we have %zu/%zu\n",len_payload,reasm->size_present,reasm->size)
			return true;
		}
		else
		{
			ReasmClear(reasm);
			DLOG("reassemble session failed\n")
		}
	}
	return false;
}
static bool reasm_orig_feed(t_ctrack *ctrack, const uint8_t *data_payload, size_t len_payload)
{
	return reasm_feed(ctrack, &ctrack->reasm_orig, data_payload, len_payload);
}
static void reasm_orig_fin(t_ctrack *ctrack)
{
	if (ctrack && ReasmIsFull(&ctrack->reasm_orig))
	{
		DLOG("reassemble session finished\n");
		ReasmClear(&ctrack->reasm_orig);
	}
}


static uint8_t ct_new_postnat_fix(const t_ctrack *ctrack, struct ip *ip, struct ip6_hdr *ip6, uint8_t proto, struct udphdr *udp, struct tcphdr *tcp, size_t *len_pkt)
{
#ifdef __linux__
	// if used in postnat chain, dropping initial packet will cause conntrack connection teardown
	// so we need to workaround this.
	// we can't use low ttl because TCP/IP stack listens to ttl expired ICMPs and notify socket
	// we also can't use fooling because DPI would accept fooled packets
	if (ctrack && ctrack->pcounter_orig==1)
	{
		DLOG("applying linux postnat conntrack workaround\n")
		if (proto==IPPROTO_UDP && udp && len_pkt)
		{
			// make malformed udp packet with zero length and invalid checksum
			udp->len = 0; // invalid length. must be >=8
			udp_fix_checksum(udp,sizeof(struct udphdr),ip,ip6);
			udp->check ^= htons(0xBEAF);
			// truncate packet
			*len_pkt = (uint8_t*)udp - (ip ? (uint8_t*)ip : (uint8_t*)ip6) + sizeof(struct udphdr);
			if (ip)
			{
				ip->ip_len = htons((uint16_t)*len_pkt);
				ip4_fix_checksum(ip);
			}
			else if (ip6)
				ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = (uint16_t)htons(sizeof(struct udphdr));
		}
		else if (proto==IPPROTO_TCP && tcp)
		{
			// only SYN here is expected
			// make flags invalid and also corrupt checksum
			tcp->th_flags = 0;
		}
		if (ip)	ip->ip_sum ^= htons(0xBEAF);
		return VERDICT_MODIFY | VERDICT_NOCSUM;
	}
#endif
	return VERDICT_DROP;
}

static uint8_t ct_new_postnat_fix_tcp(const t_ctrack *ctrack, struct ip *ip, struct ip6_hdr *ip6, struct tcphdr *tcphdr)
{
	return ct_new_postnat_fix(ctrack,ip,ip6,IPPROTO_TCP,NULL,tcphdr,NULL);
}
static uint8_t ct_new_postnat_fix_udp(const t_ctrack *ctrack, struct ip *ip, struct ip6_hdr *ip6, struct udphdr *udphdr, size_t *len_pkt)
{
	return ct_new_postnat_fix(ctrack,ip,ip6,IPPROTO_UDP,udphdr,NULL,len_pkt);
}


static bool check_desync_interval(const t_ctrack *ctrack)
{
	if (params.desync_start)
	{
		if (ctrack)
		{
			if (!cutoff_test(ctrack, params.desync_start, params.desync_start_mode))
			{
				DLOG("desync-start not reached (mode %c): %llu/%u . not desyncing\n", params.desync_start_mode, (unsigned long long)cutoff_get_limit(ctrack,params.desync_start_mode), params.desync_start);
				return false;
			}
			DLOG("desync-start reached (mode %c): %llu/%u\n", params.desync_start_mode, (unsigned long long)cutoff_get_limit(ctrack,params.desync_start_mode), params.desync_start);
		}
		else
		{
			DLOG("not desyncing. desync-start is set but conntrack entry is missing\n");
			return false;
		}
	}
	if (params.desync_cutoff)
	{
		if (ctrack)
		{
			if (ctrack->b_desync_cutoff)
			{
				DLOG("desync-cutoff reached (mode %c): %llu/%u . not desyncing\n", params.desync_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,params.desync_cutoff_mode), params.desync_cutoff);
				return false;
			}
			DLOG("desync-cutoff not reached (mode %c): %llu/%u\n", params.desync_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,params.desync_cutoff_mode), params.desync_cutoff);
		}
		else
		{
			DLOG("not desyncing. desync-cutoff is set but conntrack entry is missing\n");
			return false;
		}
	}
	return true;
}


// result : true - drop original packet, false = dont drop
uint8_t dpi_desync_tcp_packet(uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, size_t len_tcp, uint8_t *data_payload, size_t len_payload)
{
	uint8_t res=VERDICT_PASS;
	t_ctrack *ctrack=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake,flags_orig,scale_factor;
	uint32_t *timestamps;

	if (!!ip == !!ip6hdr) return res; // one and only one must be present
	ttl_orig = ip ? ip->ip_ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;

	ConntrackPoolPurge(&params.conntrack);
	if (ConntrackPoolFeed(&params.conntrack, ip, ip6hdr, tcphdr, NULL, len_payload, &ctrack, &bReverse))
		maybe_cutoff(ctrack, IPPROTO_TCP);
	HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

	//ConntrackPoolDump(&params.conntrack);

	if (params.wsize && tcp_synack_segment(tcphdr))
	{
		tcp_rewrite_winsize(tcphdr, params.wsize, params.wscale);
		res=VERDICT_MODIFY;
	}
	
	if (bReverse)
	{
		if (ctrack && !ctrack->autottl && ctrack->pcounter_reply==1)
		{
			autottl *attl = ip ? &params.desync_autottl : &params.desync_autottl6;
			if (AUTOTTL_ENABLED(*attl))
			{
				ctrack->autottl = autottl_guess(ttl_orig, attl);
				if (ctrack->autottl)
					DLOG("autottl: guessed %u\n",ctrack->autottl)
				else
					DLOG("autottl: could not guess\n")
			}
		}

		// process reply packets for auto hostlist mode
		// by looking at RSTs or HTTP replies we decide whether original request looks like DPI blocked
		// we only process first-sequence replies. do not react to subsequent redirects or RSTs
		if (*params.hostlist_auto_filename && ctrack && ctrack->hostname && (ctrack->ack_last-ctrack->ack0)==1)
		{
			bool bFail=false;
			if (tcphdr->th_flags & TH_RST)
			{
				DLOG("incoming RST detected for hostname %s\n", ctrack->hostname);
				HOSTLIST_DEBUGLOG_APPEND("%s : incoming RST", ctrack->hostname);
				bFail = true;
			}
			else if (len_payload && ctrack->l7proto==HTTP)
			{
				if (IsHttpReply(data_payload,len_payload))
				{
					DLOG("incoming HTTP reply detected for hostname %s\n", ctrack->hostname);
					bFail = HttpReplyLooksLikeDPIRedirect(data_payload, len_payload, ctrack->hostname);
					if (bFail)
					{
						DLOG("redirect to another domain detected. possibly DPI redirect.\n")
						HOSTLIST_DEBUGLOG_APPEND("%s : redirect to another domain", ctrack->hostname);
					}
					else
						DLOG("local or in-domain redirect detected. it's not a DPI redirect.\n")
				}
				else
				{
					// received not http reply. do not monitor this connection anymore
					DLOG("incoming unknown HTTP data detected for hostname %s\n", ctrack->hostname);
				}
			}
			if (bFail)
				auto_hostlist_failed(ctrack->hostname);
			if (tcphdr->th_flags & TH_RST)
				ConntrackClearHostname(ctrack); // do not react to further dup RSTs
		}
	
		return res; // nothing to do. do not waste cpu
	}

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;
	
	if (params.wssize)
	{
		if (ctrack)
		{
			if (ctrack->b_wssize_cutoff)
			{
				DLOG("not changing wssize. wssize-cutoff reached\n");
			}
			else
			{
				if (params.wssize_cutoff) DLOG("wssize-cutoff not reached (mode %c): %llu/%u\n", params.wssize_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,params.wssize_cutoff_mode), params.wssize_cutoff);
				tcp_rewrite_winsize(tcphdr, params.wssize, params.wsscale);
				res=VERDICT_MODIFY;
			}
		}
		else
		{
			DLOG("not changing wssize. wssize is set but conntrack entry is missing\n");
		}
	}

	if (params.desync_mode0!=DESYNC_NONE || params.desync_mode!=DESYNC_NONE) // save some cpu
	{
		ttl_fake = (ctrack && ctrack->autottl) ? ctrack->autottl : (ip6hdr ? (params.desync_ttl6 ? params.desync_ttl6 : ttl_orig) : (params.desync_ttl ? params.desync_ttl : ttl_orig));
		flags_orig = *((uint8_t*)tcphdr+13);
		scale_factor = tcp_find_scale_factor(tcphdr);
		timestamps = tcp_find_timestamps(tcphdr);

		extract_endpoints(ip, ip6hdr, tcphdr, NULL, &src, &dst);
	}

	if (tcp_syn_segment(tcphdr))
	{
		switch (params.desync_mode0)
		{
			case DESYNC_SYNACK:
				pkt1_len = sizeof(pkt1);
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_SYN|TH_ACK, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
					NULL, 0, pkt1, &pkt1_len))
				{
					return res;
				}
				DLOG("sending fake SYNACK\n");
				if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return res;
				break;
			case DESYNC_SYNDATA:
				// make sure we are not breaking TCP fast open
				if (tcp_has_fastopen(tcphdr))
				{
					DLOG("received SYN with TCP fast open option. syndata desync is not applied.\n");
					break;
				}
				if (len_payload)
				{
					DLOG("received SYN with data payload. syndata desync is not applied.\n");
					break;
				}
				pkt1_len = sizeof(pkt1);
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_orig,0,0,0, params.fake_syndata,params.fake_syndata_size, pkt1,&pkt1_len))
				{
					return res;
				}
				DLOG("sending SYN with fake data : ");
				hexdump_limited_dlog(params.fake_syndata,params.fake_syndata_size,PKTDATA_MAXDUMP); DLOG("\n")
				if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return res;

				res = ct_new_postnat_fix_tcp(ctrack, ip, ip6hdr, tcphdr);
				break;
		}
		// can do nothing else with SYN packet
		return res;
	}

	if (!params.wssize && params.desync_mode==DESYNC_NONE && !params.hostcase && !params.hostnospace && !params.domcase && !*params.hostlist_auto_filename) return res; // nothing to do. do not waste cpu

	// start and cutoff limiters
	if (!check_desync_interval(ctrack)) return res;

	if (!(tcphdr->th_flags & TH_SYN) && len_payload)
	{
		const uint8_t *fake;
		size_t fake_size;
		char host[256];
		bool bHaveHost=false;
		bool bIsHttp;
		bool bKnownProtocol = false;
		uint8_t *p, *phost;
		const uint8_t *rdata_payload = data_payload;
		size_t rlen_payload = len_payload;
		
		if (reasm_orig_feed(ctrack,data_payload,len_payload))
		{
			rdata_payload = ctrack->reasm_orig.packet;
			rlen_payload = ctrack->reasm_orig.size_present;
		}

		if ((bIsHttp = IsHttp(rdata_payload,rlen_payload)))
		{
			DLOG("packet contains HTTP request\n")
			if (ctrack && !ctrack->l7proto) ctrack->l7proto = HTTP;
			forced_wssize_cutoff(ctrack);
			fake = params.fake_http;
			fake_size = params.fake_http_size;
			if (params.hostlist || params.hostlist_exclude)
			{
				bHaveHost=HttpExtractHost(rdata_payload,rlen_payload,host,sizeof(host));
				if (!bHaveHost)
				{
					DLOG("not applying tampering to HTTP without Host:\n")
					process_retrans_fail(ctrack, IPPROTO_TCP);
					reasm_orig_fin(ctrack);
					return res;
				}
			}
			if (ctrack)
			{
				// we do not reassemble http
				if (!ctrack->req_seq_present)
				{
					ctrack->req_seq_start=ctrack->seq_last;
					ctrack->req_seq_end=ctrack->pos_orig-1;
					ctrack->req_seq_start_present=ctrack->req_seq_present=true;
					DLOG("req retrans : tcp seq interval %u-%u\n",ctrack->req_seq_start,ctrack->req_seq_end);
				}
			}
			bKnownProtocol = true;
		}
		else if (IsTLSClientHello(rdata_payload,rlen_payload,TLS_PARTIALS_ENABLE))
		{
			bool bReqFull = IsTLSRecordFull(rdata_payload,rlen_payload);
			DLOG(bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n")
			fake = params.fake_tls;
			fake_size = params.fake_tls_size;
			bHaveHost=TLSHelloExtractHost(rdata_payload,rlen_payload,host,sizeof(host),TLS_PARTIALS_ENABLE);
			if (ctrack)
			{
				if (!ctrack->l7proto) ctrack->l7proto = TLS;
				if (!bReqFull && ReasmIsEmpty(&ctrack->reasm_orig))
					// do not reconstruct unexpected large payload (they are feeding garbage ?)
					reasm_orig_start(ctrack,TLSRecordLen(data_payload),4096,data_payload,len_payload);
				if (!ctrack->req_seq_start_present)
				{
					// lower bound of request seq interval
					ctrack->req_seq_start=ctrack->seq_last;
					ctrack->req_seq_start_present=true;
				}
				if (!ctrack->req_seq_present && bReqFull)
				{
					// upper bound of request seq interval
					ctrack->req_seq_end=ctrack->pos_orig-1;
					ctrack->req_seq_present=ctrack->req_seq_start_present;
					DLOG("req retrans : seq interval %u-%u\n",ctrack->req_seq_start,ctrack->req_seq_end);
				}
			}
			if (bReqFull || !ctrack || ReasmIsEmpty(&ctrack->reasm_orig)) forced_wssize_cutoff(ctrack);

			if (params.desync_skip_nosni && !bHaveHost)
			{
				DLOG("not applying tampering to TLS ClientHello without hostname in the SNI\n")
				process_retrans_fail(ctrack, IPPROTO_TCP);
				reasm_orig_fin(ctrack);
				return res;
			}
			bKnownProtocol = true;
		}

		reasm_orig_fin(ctrack);
		rdata_payload=NULL;

		if (bHaveHost)
		{
			bool bExcluded;
			DLOG("hostname: %s\n",host)
			if ((params.hostlist || params.hostlist_exclude) && !HostlistCheck(host, &bExcluded))
			{
				DLOG("not applying tampering to this request\n")
				if (ctrack)
				{
					if (!bExcluded && *params.hostlist_auto_filename)
					{
						if (!ctrack->hostname) ctrack->hostname=strdup(host);
						process_retrans_fail(ctrack, IPPROTO_TCP);
					}
					else
						ctrack_stop_retrans_counter(ctrack);
				}
				return res;
			}
			ctrack_stop_retrans_counter(ctrack);
		}
		process_retrans_fail(ctrack, IPPROTO_TCP);
		
		if (!bKnownProtocol)
		{
			if (!params.desync_any_proto) return res;
			DLOG("applying tampering to unknown protocol\n")
			fake = params.fake_unknown;
			fake_size = params.fake_unknown_size;
		}

		if (bIsHttp && (params.hostcase || params.hostnospace || params.domcase) && (phost = (uint8_t*)memmem(data_payload, len_payload, "\r\nHost: ", 8)))
		{
			if (params.hostcase)
			{
				DLOG("modifying Host: => %c%c%c%c:\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3])
				memcpy(phost + 2, params.hostspell, 4);
				res=VERDICT_MODIFY;
			}
			if (params.domcase)
			{
				DLOG("mixing domain case\n");
				for (p = phost+7; p < (data_payload + len_payload) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
				res=VERDICT_MODIFY;
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
				res=VERDICT_MODIFY;
			}
		}

		if (params.desync_mode==DESYNC_NONE) return res;

		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}

		enum dpi_desync_mode desync_mode = params.desync_mode;
		uint32_t fooling_orig = FOOL_NONE;
		bool b;

		pkt1_len = sizeof(pkt1);
		b = false;
		switch(desync_mode)
		{
			case DESYNC_FAKE_KNOWN:
				if (!bKnownProtocol)
				{
					DLOG("not applying fake because of unknown protocol\n");
					desync_mode = params.desync_mode2;
					break;
				}
			case DESYNC_FAKE:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
					fake, fake_size, pkt1, &pkt1_len))
				{
					return res;
				}
				DLOG("sending fake request : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n")
				b = true;
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (desync_mode==DESYNC_RSTACK ? TH_ACK:0), tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
					NULL, 0, pkt1, &pkt1_len))
				{
					return res;
				}
				DLOG("sending fake RST/RSTACK\n");
				b = true;
				break;
			case DESYNC_HOPBYHOP:
			case DESYNC_DESTOPT:
			case DESYNC_IPFRAG1:
				fooling_orig = (desync_mode==DESYNC_HOPBYHOP) ? FOOL_HOPBYHOP : (desync_mode==DESYNC_DESTOPT) ? FOOL_DESTOPT : FOOL_IPFRAG1;
				if (ip6hdr && (params.desync_mode2==DESYNC_NONE || !desync_valid_second_stage_tcp(params.desync_mode2)))
				{
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
						ttl_orig,fooling_orig,0,0,
						data_payload, len_payload, pkt1, &pkt1_len))
					{
						return res;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;
					// this mode is final, no other options available
					return VERDICT_DROP;
				}
				desync_mode = params.desync_mode2;
		}

		if (b)
		{
			if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
				return res;
			if (params.desync_mode2==DESYNC_NONE || !desync_valid_second_stage_tcp(params.desync_mode2))
			{
					if (params.desync_retrans)
					{
						DLOG("dropping original packet to force retransmission. len=%zu len_payload=%zu\n", *len_pkt, len_payload)
					}
					else
					{
						DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", *len_pkt, len_payload)
						#ifdef __FreeBSD__
						// FreeBSD tend to pass ipv6 frames with wrong checksum
						if ((res & VERDICT_MASK)==VERDICT_MODIFY || ip6hdr)
						#else
						// if original packet was tampered earlier it needs checksum fixed
						if ((res & VERDICT_MASK)==VERDICT_MODIFY)
						#endif
							tcp_fix_checksum(tcphdr,len_tcp,ip,ip6hdr);
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , data_pkt, *len_pkt))
							return res;
					}
					return VERDICT_DROP;
			}
			desync_mode = params.desync_mode2;
		}

		size_t split_pos=len_payload>params.desync_split_pos ? params.desync_split_pos : 1;
		pkt1_len = sizeof(pkt1);
		switch(desync_mode)
		{
			case DESYNC_DISORDER:
			case DESYNC_DISORDER2:
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (split_pos<len_payload)
					{
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,split_pos), tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								data_payload+split_pos, len_payload-split_pos, pkt1, &pkt1_len))
							return res;
						DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu : ",split_pos,len_payload-1, len_payload-split_pos)
						hexdump_limited_dlog(data_payload+split_pos,len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							return res;
					}


					if (desync_mode==DESYNC_DISORDER)
					{
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								zeropkt, split_pos, fakeseg, &fakeseg_len))
							return res;
						DLOG("sending fake(1) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return res;
					}


					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
							ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
							data_payload, split_pos, pkt1, &pkt1_len))
						return res;
					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
					hexdump_limited_dlog(data_payload,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;

					if (desync_mode==DESYNC_DISORDER)
					{
						DLOG("sending fake(2) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return res;
					}

					return VERDICT_DROP;
				}
				break;
			case DESYNC_SPLIT:
			case DESYNC_SPLIT2:
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100];
					size_t fakeseg_len;

					if (desync_mode==DESYNC_SPLIT)
					{
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								zeropkt, split_pos, fakeseg, &fakeseg_len))
							return res;
						DLOG("sending fake(1) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return res;
					}

					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
							ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
							data_payload, split_pos, pkt1, &pkt1_len))
						return res;
					DLOG("sending 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
					hexdump_limited_dlog(data_payload,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;

					if (desync_mode==DESYNC_SPLIT)
					{
						DLOG("sending fake(2) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return res;
					}

					if (split_pos<len_payload)
					{
						pkt1_len = sizeof(pkt1);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,split_pos), tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								data_payload+split_pos, len_payload-split_pos, pkt1, &pkt1_len))
							return res;
						DLOG("sending 2nd tcp segment %zu-%zu len=%zu : ",split_pos,len_payload-1, len_payload-split_pos)
						hexdump_limited_dlog(data_payload+split_pos,len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							return res;
					}

					return VERDICT_DROP;
				}
				break;
			case DESYNC_IPFRAG2:
				{
					#ifdef __FreeBSD__
					// FreeBSD tend to pass ipv6 frames with wrong checksum
					if ((res & VERDICT_MASK)==VERDICT_MODIFY || ip6hdr)
					#else
					// if original packet was tampered earlier it needs checksum fixed
					if ((res & VERDICT_MASK)==VERDICT_MODIFY)
					#endif
						tcp_fix_checksum(tcphdr,len_tcp,ip,ip6hdr);

					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;

					size_t ipfrag_pos = (params.desync_ipfrag_pos_tcp && params.desync_ipfrag_pos_tcp<len_tcp) ? params.desync_ipfrag_pos_tcp : 24;
					uint32_t ident = ip ? ip->ip_id ? ip->ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (ip6hdr && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, data_pkt, *len_pkt, pkt3, &pkt_orig_len))
							return res;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = data_pkt;
						pkt_orig_len = *len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return res;

					DLOG("sending 1st ip fragment 0-%zu len=%zu : ", ipfrag_pos-1, ipfrag_pos)
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return res;

					DLOG("sending 2nd ip fragment %zu-%zu len=%zu : ", ipfrag_pos, len_tcp-1, len_tcp-ipfrag_pos)
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;

					return VERDICT_DROP;
				}
		}
	
	}

	return res;
}



uint8_t dpi_desync_udp_packet(uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct udphdr *udphdr, uint8_t *data_payload, size_t len_payload)
{
	uint8_t res=VERDICT_PASS;
	t_ctrack *ctrack=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake;

	if (!!ip == !!ip6hdr) return res; // one and only one must be present

	ConntrackPoolPurge(&params.conntrack);
	if (ConntrackPoolFeed(&params.conntrack, ip, ip6hdr, NULL, udphdr, len_payload, &ctrack, &bReverse))
		maybe_cutoff(ctrack, IPPROTO_UDP);
	HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

	//ConntrackPoolDump(&params.conntrack);

	if (bReverse) return res; // nothing to do. do not waste cpu

	if (params.desync_mode==DESYNC_NONE && !*params.hostlist_auto_filename) return res; // do not waste cpu

	// start and cutoff limiters
	if (!check_desync_interval(ctrack)) return res;

	if (len_payload)
	{
		const uint8_t *fake;
		size_t fake_size;
		bool b;
		char host[256];
		bool bHaveHost=false;
		bool bKnownProtocol=false;

		if (IsQUICInitial(data_payload,len_payload))
		{
			DLOG("packet contains QUIC initial\n")
			
			if (ctrack && !ctrack->l7proto) ctrack->l7proto = QUIC;
			fake = params.fake_quic;
			fake_size = params.fake_quic_size;

			bool bIsCryptoHello, bDecryptOK;
			bHaveHost=QUICExtractHostFromInitial(data_payload,len_payload,host,sizeof(host), &bDecryptOK,&bIsCryptoHello);
			if (bIsCryptoHello)
			{
				// decrypted and payload is ClientHello
				if (params.desync_skip_nosni && !bHaveHost)
				{
					DLOG("not applying tampering to QUIC ClientHello without hostname in the SNI\n")
					return res;
				}
			}
			else if (!bDecryptOK)
			{
				// could not decrypt
				if (params.desync_skip_nosni)
				{
					DLOG("not applying tampering to QUIC initial that could not be decrypted\n")
					return res;
				}
				else
					// consider this case the same way as absence of the SNI. DPI also might not be able to decrypt this and get SNI
					DLOG("QUIC initial decryption failed. still applying tampering because desync_skip_nosni is not set\n")
			}
			else
			{
				// decrypted and payload is not ClientHello
				if (params.desync_any_proto)
				{
					DLOG("QUIC initial without CRYPTO frame. applying tampering because desync_any_proto is set\n")
				}
				else
				{
					DLOG("not applying tampering to QUIC initial without CRYPTO frame\n")
					return res;
				}
			}
			bKnownProtocol = true;
		}
		else
		{
			// received payload without host. it means we are out of the request retransmission phase. stop counter
			ctrack_stop_retrans_counter(ctrack);

			if (IsWireguardHandshakeInitiation(data_payload,len_payload))
			{
				DLOG("packet contains wireguard handshake initiation\n")
				if (ctrack && !ctrack->l7proto) ctrack->l7proto = WIREGUARD;
				fake = params.fake_wg;
				fake_size = params.fake_wg_size;
				bKnownProtocol = true;
			}
			else if (IsDhtD1(data_payload,len_payload))
			{
				DLOG("packet contains DHT d1...e\n")
				if (ctrack && !ctrack->l7proto) ctrack->l7proto = DHT;
				fake = params.fake_dht;
				fake_size = params.fake_dht_size;
				bKnownProtocol = true;
			}
			else
			{
				if (!params.desync_any_proto) return res;
				DLOG("applying tampering to unknown protocol\n")
				fake = params.fake_unknown_udp;
				fake_size = params.fake_unknown_udp_size;
			}
		}

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			bool bExcluded;
			if ((params.hostlist || params.hostlist_exclude) && !HostlistCheck(host, &bExcluded))
			{
				DLOG("not applying tampering to this request\n")
				if (!bExcluded && *params.hostlist_auto_filename && ctrack)
				{
					if (!ctrack->hostname) ctrack->hostname=strdup(host);
					process_retrans_fail(ctrack, IPPROTO_UDP);
				}
				return res;
			}
		}

		enum dpi_desync_mode desync_mode = params.desync_mode;
		uint32_t fooling_orig = FOOL_NONE;

		ttl_orig = ip ? ip->ip_ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
		if (ip6hdr) ttl_fake = params.desync_ttl6 ? params.desync_ttl6 : ttl_orig;
		else ttl_fake = params.desync_ttl ? params.desync_ttl : ttl_orig;
		extract_endpoints(ip, ip6hdr, NULL, udphdr, &src, &dst);

		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}

		uint32_t desync_fwmark = fwmark | params.desync_fwmark;

		pkt1_len = sizeof(pkt1);
		b = false;
		switch(desync_mode)
		{
			case DESYNC_FAKE_KNOWN:
				if (!bKnownProtocol)
				{
					DLOG("not applying fake because of unknown protocol\n");
					desync_mode = params.desync_mode2;
					break;
				}
			case DESYNC_FAKE:
				if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_fake, params.desync_fooling_mode, NULL, 0, 0, fake, fake_size, pkt1, &pkt1_len))
					return res;
				DLOG("sending fake request : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n")
				if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return res;
				b = true;
				break;
			case DESYNC_HOPBYHOP:
			case DESYNC_DESTOPT:
			case DESYNC_IPFRAG1:
				fooling_orig = (desync_mode==DESYNC_HOPBYHOP) ? FOOL_HOPBYHOP : (desync_mode==DESYNC_DESTOPT) ? FOOL_DESTOPT : FOOL_IPFRAG1;
				if (ip6hdr && (params.desync_mode2==DESYNC_NONE || !desync_valid_second_stage_udp(params.desync_mode2)))
				{
					if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst,
						ttl_orig,fooling_orig,NULL,0,0,
						data_payload, len_payload, pkt1, &pkt1_len))
					{
						return res;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;
					// this mode is final, no other options available
					return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
				}
				desync_mode = params.desync_mode2;
				break;
		}

		if (b)
		{
			if (params.desync_mode2==DESYNC_NONE || !desync_valid_second_stage_udp(params.desync_mode2))
			{
				DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", *len_pkt, len_payload)
				#ifdef __FreeBSD__
				// FreeBSD tend to pass ipv6 frames with wrong checksum
				if ((res & VERDICT_MASK)==VERDICT_MODIFY || ip6hdr)
				#else
				// if original packet was tampered earlier it needs checksum fixed
				if ((res & VERDICT_MASK)==VERDICT_MODIFY)
				#endif
					udp_fix_checksum(udphdr,sizeof(struct udphdr)+len_payload,ip,ip6hdr);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , data_pkt, *len_pkt))
					return res;
				return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
			}
			desync_mode = params.desync_mode2;
		}

		switch(desync_mode)
		{
			case DESYNC_UDPLEN:
				pkt1_len = sizeof(pkt1);
				if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_orig,fooling_orig, params.udplen_pattern, sizeof(params.udplen_pattern), params.udplen_increment, data_payload, len_payload, pkt1, &pkt1_len))
				{
					DLOG("could not construct packet with modified length. too large ?\n");
					return res;
				}
				DLOG("resending original packet with increased by %d length\n", params.udplen_increment);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return res;
				return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
			case DESYNC_TAMPER:
				if (IsDhtD1(data_payload,len_payload))
				{
					size_t szbuf,szcopy;
					memcpy(pkt2,"d2:001:x",8);
					pkt2_len=8;
					szbuf=sizeof(pkt2)-pkt2_len;
					szcopy=len_payload-1;
					if (szcopy>szbuf)
					{
						DLOG("packet is too long to tamper");
						return res;
					}
					memcpy(pkt2+pkt2_len,data_payload+1,szcopy);
					pkt2_len+=szcopy;
					pkt1_len = sizeof(pkt1);
					if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_orig,fooling_orig, NULL, 0 , 0, pkt2, pkt2_len, pkt1, &pkt1_len))
					{
						DLOG("could not construct packet with modified length. too large ?\n");
						return res;
					}
					DLOG("resending tampered DHT\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;
					return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
				}
				else
				{
					DLOG("payload is not tamperable\n");
					return res;
				}
			case DESYNC_IPFRAG2:
				{

					#ifdef __FreeBSD__
					// FreeBSD tend to pass ipv6 frames with wrong checksum
					if ((res & VERDICT_MASK)==VERDICT_MODIFY || ip6hdr)
					#else
					// if original packet was tampered earlier it needs checksum fixed
					if ((res & VERDICT_MASK)==VERDICT_MODIFY)
					#endif
						udp_fix_checksum(udphdr,sizeof(struct udphdr)+len_payload,ip,ip6hdr);

					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;

					size_t len_transport = len_payload + sizeof(struct udphdr);
					size_t ipfrag_pos = (params.desync_ipfrag_pos_udp && params.desync_ipfrag_pos_udp<len_transport) ? params.desync_ipfrag_pos_udp : sizeof(struct udphdr);
					// freebsd do not set ip.id
					uint32_t ident = ip ? ip->ip_id ? ip->ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (ip6hdr && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, data_pkt, *len_pkt, pkt3, &pkt_orig_len))
							return res;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = data_pkt;
						pkt_orig_len = *len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return res;

					DLOG("sending 1st ip fragment 0-%zu len=%zu : ", ipfrag_pos-1, ipfrag_pos)
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return res;

					DLOG("sending 2nd ip fragment %zu-%zu len=%zu : ", ipfrag_pos, len_transport-1, len_transport-ipfrag_pos)
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return res;

					return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
				}
		}

	}

	return res;
}
