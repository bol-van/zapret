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
			    (!ctrack->hostname_ah_check || ctrack->req_retrans_counter==RETRANS_COUNTER_STOP) &&
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
	if (ctrack && ctrack->hostname_ah_check)
	{
		ctrack->req_retrans_counter = RETRANS_COUNTER_STOP;
		maybe_cutoff(ctrack, IPPROTO_TCP);
	}
}

static void auto_hostlist_reset_fail_counter(const char *hostname)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;
	
		fail_counter = HostFailPoolFind(params.hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&params.hostlist_auto_fail_counters, fail_counter);
			DLOG("auto hostlist : %s : fail counter reset. website is working.\n", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : fail counter reset. website is working.", hostname);
		}
	}
}

// return true if retrans trigger fires
static bool auto_hostlist_retrans(t_ctrack *ctrack, uint8_t l4proto, int threshold)
{
	if (ctrack && ctrack->hostname_ah_check && ctrack->req_retrans_counter!=RETRANS_COUNTER_STOP)
	{
		if (l4proto==IPPROTO_TCP)
		{
			if (!ctrack->req_seq_finalized || ctrack->req_seq_abandoned)
				return false;
			if (!seq_within(ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end))
			{
				DLOG("req retrans : tcp seq %u not within the req range %u-%u. stop tracking.\n", ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end);
				ctrack_stop_retrans_counter(ctrack);
				auto_hostlist_reset_fail_counter(ctrack->hostname);
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

static bool send_delayed(t_ctrack *ctrack)
{
	if (!rawpacket_queue_empty(&ctrack->delayed))
	{
		DLOG("SENDING %u delayed packets\n", rawpacket_queue_count(&ctrack->delayed))
		return rawsend_queue(&ctrack->delayed);
	}
	return true;
}


static bool reasm_start(t_ctrack *ctrack, t_reassemble *reasm, uint8_t proto, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	ReasmClear(reasm);
	if (sz<=szMax)
	{
		uint32_t seq = (proto==IPPROTO_TCP) ? ctrack->seq_last : 0;
		if (ReasmInit(reasm,sz,seq))
		{
			ReasmFeed(reasm,seq,data_payload,len_payload);
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
static bool reasm_orig_start(t_ctrack *ctrack, uint8_t proto, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	return reasm_start(ctrack,&ctrack->reasm_orig,proto,sz,szMax,data_payload,len_payload);
}
static bool reasm_feed(t_ctrack *ctrack, t_reassemble *reasm, uint8_t proto, const uint8_t *data_payload, size_t len_payload)
{
	if (ctrack && !ReasmIsEmpty(reasm))
	{
		uint32_t seq = (proto==IPPROTO_TCP) ? ctrack->seq_last : (uint32_t)reasm->size_present;
		if (ReasmFeed(reasm, seq, data_payload, len_payload))
		{
			DLOG("reassemble : feeding data payload size=%zu. now we have %zu/%zu\n", len_payload,reasm->size_present,reasm->size)
			return true;
		}
		else
		{
			ReasmClear(reasm);
			DLOG("reassemble session failed\n")
			send_delayed(ctrack);
		}
	}
	return false;
}
static bool reasm_orig_feed(t_ctrack *ctrack, uint8_t proto, const uint8_t *data_payload, size_t len_payload)
{
	return reasm_feed(ctrack, &ctrack->reasm_orig, proto, data_payload, len_payload);
}
static void reasm_orig_stop(t_ctrack *ctrack, const char *dlog_msg)
{
	if (ctrack)
	{
		if (!ReasmIsEmpty(&ctrack->reasm_orig))
		{
			DLOG("%s",dlog_msg);
			ReasmClear(&ctrack->reasm_orig);
		}
		send_delayed(ctrack);
	}
}
static void reasm_orig_cancel(t_ctrack *ctrack)
{
	reasm_orig_stop(ctrack, "reassemble session cancelled\n");
}
static void reasm_orig_fin(t_ctrack *ctrack)
{
	reasm_orig_stop(ctrack, "reassemble session finished\n");
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
static bool process_desync_interval(t_ctrack *ctrack)
{
	if (check_desync_interval(ctrack))
		return true;
	else
	{
		reasm_orig_cancel(ctrack);
		return false;
	}
}

static bool replay_queue(struct rawpacket_tailhead *q);

static size_t pos_normalize(size_t split_pos, size_t reasm_offset, size_t len_payload)
{
	size_t rsplit_pos = split_pos;
	// normalize split pos to current packet
	split_pos=(split_pos>reasm_offset && (split_pos-reasm_offset)<len_payload) ? split_pos-reasm_offset : 0;
	if (rsplit_pos)
	{
		if (split_pos==rsplit_pos)
			DLOG("split pos %zu\n",split_pos)
		else
		{
			if (split_pos)
				DLOG("split pos was normalized to packet data offset : %zu -> %zu\n",rsplit_pos,split_pos)
			else
				DLOG("split pos %zu is outside of this packet %zu-%zu\n",rsplit_pos,reasm_offset,reasm_offset+len_payload)
		}
	}
	return split_pos;
}

static uint8_t dpi_desync_tcp_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, size_t transport_len, uint8_t *data_payload, size_t len_payload)
{
	uint8_t verdict=VERDICT_PASS;

	t_ctrack *ctrack=NULL, *ctrack_replay=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake,flags_orig,scale_factor;
	uint32_t *timestamps;

	ttl_orig = ip ? ip->ip_ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	uint32_t desync_fwmark = fwmark | params.desync_fwmark;

	if (replay)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, ip, ip6hdr, tcphdr, NULL, &ctrack_replay, &bReverse) || bReverse)
			return verdict;
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		ConntrackPoolPurge(&params.conntrack);
		if (ConntrackPoolFeed(&params.conntrack, ip, ip6hdr, tcphdr, NULL, len_payload, &ctrack, &bReverse))
		{
			ctrack_replay = ctrack;
			maybe_cutoff(ctrack, IPPROTO_TCP);
		}
		HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

		//ConntrackPoolDump(&params.conntrack);

		if (params.wsize && tcp_synack_segment(tcphdr))
		{
			tcp_rewrite_winsize(tcphdr, params.wsize, params.wscale);
			verdict=VERDICT_MODIFY;
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
			if (ctrack && ctrack->hostname && ctrack->hostname_ah_check && (ctrack->ack_last-ctrack->ack0)==1)
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
				else
					if (len_payload)
						auto_hostlist_reset_fail_counter(ctrack->hostname);
				if (tcphdr->th_flags & TH_RST)
					ConntrackClearHostname(ctrack); // do not react to further dup RSTs
			}
			
			return verdict; // nothing to do. do not waste cpu
		}


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
					verdict=VERDICT_MODIFY;
				}
			}
			else
			{
				DLOG("not changing wssize. wssize is set but conntrack entry is missing\n");
			}
		}
	} // !replay

	if (params.desync_mode0!=DESYNC_NONE || params.desync_mode!=DESYNC_NONE) // save some cpu
	{
		ttl_fake = (ctrack_replay && ctrack_replay->autottl) ? ctrack_replay->autottl : (ip6hdr ? (params.desync_ttl6 ? params.desync_ttl6 : ttl_orig) : (params.desync_ttl ? params.desync_ttl : ttl_orig));
		flags_orig = *((uint8_t*)tcphdr+13);
		scale_factor = tcp_find_scale_factor(tcphdr);
		timestamps = tcp_find_timestamps(tcphdr);

		extract_endpoints(ip, ip6hdr, tcphdr, NULL, &src, &dst);
	}

	if (!replay)
	{
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
						return verdict;
					}
					DLOG("sending fake SYNACK\n");
					if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
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
						return verdict;
					}
					DLOG("sending SYN with fake data : ");
					hexdump_limited_dlog(params.fake_syndata,params.fake_syndata_size,PKTDATA_MAXDUMP); DLOG("\n")
					if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					verdict = ct_new_postnat_fix_tcp(ctrack, ip, ip6hdr, tcphdr);
					break;
			}
			// can do nothing else with SYN packet
			return verdict;
		}

		// start and cutoff limiters
		if (!process_desync_interval(ctrack)) return verdict;
	} // !replay
	
	if (!params.wssize && params.desync_mode==DESYNC_NONE && !params.hostcase && !params.hostnospace && !params.domcase && !*params.hostlist_auto_filename) return verdict; // nothing to do. do not waste cpu
	
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
		size_t split_pos;

		if (replay)
		{
			rdata_payload = ctrack_replay->reasm_orig.packet;
			rlen_payload = ctrack_replay->reasm_orig.size_present;
		}
		else if (reasm_orig_feed(ctrack,IPPROTO_TCP,data_payload,len_payload))
		{
			rdata_payload = ctrack->reasm_orig.packet;
			rlen_payload = ctrack->reasm_orig.size_present;
		}

		process_retrans_fail(ctrack, IPPROTO_TCP);

		if ((bIsHttp = IsHttp(rdata_payload,rlen_payload)))
		{
			DLOG("packet contains HTTP request\n")
			if (ctrack && !ctrack->l7proto) ctrack->l7proto = HTTP;

			// we do not reassemble http
			reasm_orig_cancel(ctrack);
			
			forced_wssize_cutoff(ctrack);
			fake = params.fake_http;
			fake_size = params.fake_http_size;
			if (params.hostlist || params.hostlist_exclude)
			{
				bHaveHost=HttpExtractHost(rdata_payload,rlen_payload,host,sizeof(host));
				if (!bHaveHost)
				{
					DLOG("not applying tampering to HTTP without Host:\n")
					return verdict;
				}
			}
			if (ctrack)
			{
				// we do not reassemble http
				if (!ctrack->req_seq_present)
				{
					ctrack->req_seq_start=ctrack->seq_last;
					ctrack->req_seq_end=ctrack->pos_orig-1;
					ctrack->req_seq_present=ctrack->req_seq_finalized=true;
					DLOG("req retrans : tcp seq interval %u-%u\n",ctrack->req_seq_start,ctrack->req_seq_end);
				}
			}
			split_pos = HttpPos(params.desync_split_http_req, params.desync_split_pos, rdata_payload, rlen_payload);
			bKnownProtocol = true;
		}
		else if (IsTLSClientHello(rdata_payload,rlen_payload,TLS_PARTIALS_ENABLE))
		{
			bool bReqFull = IsTLSRecordFull(rdata_payload,rlen_payload);
			DLOG(bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n")

			bHaveHost=TLSHelloExtractHost(rdata_payload,rlen_payload,host,sizeof(host),TLS_PARTIALS_ENABLE);

			if (ctrack)
			{
				if (!ctrack->l7proto) ctrack->l7proto = TLS;
				// do not reasm retransmissions
				if (!bReqFull && ReasmIsEmpty(&ctrack->reasm_orig) && !ctrack->req_seq_abandoned &&
					!(ctrack->req_seq_finalized && seq_within(ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end)))
				{
					// do not reconstruct unexpected large payload (they are feeding garbage ?)
					if (!reasm_orig_start(ctrack,IPPROTO_TCP,TLSRecordLen(data_payload),16384,data_payload,len_payload))
					{
						reasm_orig_cancel(ctrack);
						return verdict;
					}
					
				}
				if (!ctrack->req_seq_finalized)
				{
					if (!ctrack->req_seq_present)
					{
						// lower bound of request seq interval
						ctrack->req_seq_start=ctrack->seq_last;
						ctrack->req_seq_present=true;
					}
					// upper bound of request seq interval
					// it can grow on every packet until request is complete. then interval is finalized and never touched again.
					ctrack->req_seq_end=ctrack->pos_orig-1;
					DLOG("req retrans : seq interval %u-%u\n",ctrack->req_seq_start,ctrack->req_seq_end);
					ctrack->req_seq_finalized |= bReqFull;
				}
				if (bReqFull || ReasmIsEmpty(&ctrack->reasm_orig)) forced_wssize_cutoff(ctrack);

				if (!ReasmIsEmpty(&ctrack->reasm_orig))
				{
					verdict_tcp_csum_fix(verdict, tcphdr, transport_len, ip, ip6hdr);
					if (rawpacket_queue(&ctrack->delayed, &dst, desync_fwmark, ifout, data_pkt, *len_pkt, len_payload))
					{
						DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
					}
					else
					{
						fprintf(stderr, "rawpacket_queue failed !'\n");
						reasm_orig_cancel(ctrack);
						return verdict;
					}
					if (ReasmIsFull(&ctrack->reasm_orig))
					{
						replay_queue(&ctrack->delayed);
						reasm_orig_fin(ctrack);
					}
					return VERDICT_DROP;
				}
			}

			if (params.desync_skip_nosni && !bHaveHost)
			{
				DLOG("not applying tampering to TLS ClientHello without hostname in the SNI\n")
				reasm_orig_cancel(ctrack);
				return verdict;
			}
			
			fake = params.fake_tls;
			fake_size = params.fake_tls_size;
			split_pos = TLSPos(params.desync_split_tls, params.desync_split_pos, rdata_payload, rlen_payload, 0);
			bKnownProtocol = true;
		}
		else
			split_pos=params.desync_split_pos;

		reasm_orig_cancel(ctrack);
		rdata_payload=NULL;

		if (ctrack && ctrack->req_seq_finalized)
		{
			uint32_t dseq = ctrack->seq_last - ctrack->req_seq_end;
			// do not react to 32-bit overflowed sequence numbers. allow 16 Mb grace window then cutoff.
			if (dseq>=0x1000000 && !(dseq & 0x80000000)) ctrack->req_seq_abandoned=true;
		}

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			if (params.hostlist || params.hostlist_exclude)
			{
				bool bBypass;
				if (HostlistCheck(host, &bBypass))
					ctrack_stop_retrans_counter(ctrack_replay);
				else
				{
					if (ctrack_replay)
					{
						ctrack_replay->hostname_ah_check = *params.hostlist_auto_filename && !bBypass;
						if (ctrack_replay->hostname_ah_check)
						{
							if (!ctrack_replay->hostname) ctrack_replay->hostname=strdup(host);
						}
						else
							ctrack_stop_retrans_counter(ctrack_replay);
					}
					DLOG("not applying tampering to this request\n")
					return verdict;
				}
			}
		}
		
		if (!bKnownProtocol)
		{
			if (!params.desync_any_proto) return verdict;
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
				verdict=VERDICT_MODIFY;
			}
			if (params.domcase)
			{
				DLOG("mixing domain case\n");
				for (p = phost+7; p < (data_payload + len_payload) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
				verdict=VERDICT_MODIFY;
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
				verdict=VERDICT_MODIFY;
			}
		}

		if (params.desync_mode==DESYNC_NONE) return verdict;

		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}
		
		if (!split_pos || split_pos>rlen_payload) split_pos=1;
		split_pos=pos_normalize(split_pos,reasm_offset,len_payload);

		enum dpi_desync_mode desync_mode = params.desync_mode;
		uint32_t fooling_orig = FOOL_NONE;
		bool b;

		pkt1_len = sizeof(pkt1);
		b = false;
		switch(desync_mode)
		{
			case DESYNC_FAKE_KNOWN:
				if (reasm_offset)
				{
					desync_mode = params.desync_mode2;
					break;
				}
				if (!bKnownProtocol)
				{
					DLOG("not applying fake because of unknown protocol\n");
					desync_mode = params.desync_mode2;
					break;
				}
			case DESYNC_FAKE:
				if (reasm_offset) break;
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
					fake, fake_size, pkt1, &pkt1_len))
				{
					return verdict;
				}
				DLOG("sending fake request : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n")
				b = true;
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (reasm_offset) break;
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (desync_mode==DESYNC_RSTACK ? TH_ACK:0), tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
					ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
					NULL, 0, pkt1, &pkt1_len))
				{
					return verdict;
				}
				DLOG("sending fake RST/RSTACK\n");
				b = true;
				break;
			case DESYNC_HOPBYHOP:
			case DESYNC_DESTOPT:
			case DESYNC_IPFRAG1:
				fooling_orig = (desync_mode==DESYNC_HOPBYHOP) ? FOOL_HOPBYHOP : (desync_mode==DESYNC_DESTOPT) ? FOOL_DESTOPT : FOOL_IPFRAG1;
				desync_mode = params.desync_mode2;
				if (ip6hdr && (desync_mode==DESYNC_NONE || !desync_valid_second_stage_tcp(desync_mode) ||
					(!split_pos && (desync_mode==DESYNC_SPLIT || desync_mode==DESYNC_SPLIT2 || desync_mode==DESYNC_DISORDER || desync_mode==DESYNC_DISORDER2))))
				{
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
						ttl_orig,fooling_orig,0,0,
						data_payload, len_payload, pkt1, &pkt1_len))
					{
						return verdict;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					// this mode is final, no other options available
					return VERDICT_DROP;
				}
		}

		if (b)
		{
			if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
				return verdict;
			if (params.desync_mode2==DESYNC_NONE || !desync_valid_second_stage_tcp(params.desync_mode2))
			{
				DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", *len_pkt, len_payload)
				verdict_tcp_csum_fix(verdict, tcphdr, transport_len, ip, ip6hdr);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , data_pkt, *len_pkt))
					return verdict;
				return VERDICT_DROP;
			}
			desync_mode = params.desync_mode2;
		}

		pkt1_len = sizeof(pkt1);
		switch(desync_mode)
		{
			case DESYNC_DISORDER:
			case DESYNC_DISORDER2:
				if (split_pos)
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100], *seg;
					size_t seg_len;

					if (params.desync_seqovl>=split_pos)
					{
						DLOG("seqovl>=split_pos. desync is not possible.\n")
						return verdict;
					}

					if (split_pos<len_payload)
					{
						if (params.desync_seqovl)
						{
							seg_len = len_payload-split_pos+params.desync_seqovl;
							if (seg_len>sizeof(fakeseg))
							{
								DLOG("seqovl is too large\n")
								return verdict;
							}
							fill_pattern(fakeseg,params.desync_seqovl,params.seqovl_pattern,sizeof(params.seqovl_pattern));
							memcpy(fakeseg+params.desync_seqovl,data_payload+split_pos,len_payload-split_pos);
							seg = fakeseg;
						}
						else
						{
							seg = data_payload+split_pos;
							seg_len = len_payload-split_pos;
						}

						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(net32_add(tcphdr->th_seq,split_pos),-params.desync_seqovl), tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								seg, seg_len, pkt1, &pkt1_len))
							return verdict;
						DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu seqovl=%u : ",split_pos,len_payload-1, len_payload-split_pos, params.desync_seqovl)
						hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							return verdict;
					}


					if (desync_mode==DESYNC_DISORDER)
					{
						seg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								zeropkt, split_pos, fakeseg, &seg_len))
							return verdict;
						DLOG("sending fake(1) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, seg_len))
							return verdict;
					}

					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
							ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
							data_payload, split_pos, pkt1, &pkt1_len))
						return verdict;
					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
					hexdump_limited_dlog(data_payload,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					if (desync_mode==DESYNC_DISORDER)
					{
						DLOG("sending fake(2) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, seg_len))
							return verdict;
					}

					return VERDICT_DROP;
				}
				break;
			case DESYNC_SPLIT:
			case DESYNC_SPLIT2:
				if (split_pos)
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100],ovlseg[DPI_DESYNC_MAX_FAKE_LEN+100], *seg;
					size_t fakeseg_len,seg_len;

					if (desync_mode==DESYNC_SPLIT)
					{
						fakeseg_len = sizeof(fakeseg);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, tcphdr->th_seq, tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_fake,params.desync_fooling_mode,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								zeropkt, split_pos, fakeseg, &fakeseg_len))
							return verdict;
						DLOG("sending fake(1) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return verdict;
					}

					if (params.desync_seqovl)
					{
						seg_len = split_pos+params.desync_seqovl;
						if (seg_len>sizeof(ovlseg))
						{
							DLOG("seqovl is too large")
							return verdict;
						}
						fill_pattern(ovlseg,params.desync_seqovl,params.seqovl_pattern,sizeof(params.seqovl_pattern));
						memcpy(ovlseg+params.desync_seqovl,data_payload,split_pos);
						seg = ovlseg;
					}
					else
					{
						seg = data_payload;
						seg_len = split_pos;
					}

					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,-params.desync_seqovl), tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
							ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
							seg, seg_len, pkt1, &pkt1_len))
						return verdict;
					DLOG("sending 1st tcp segment 0-%zu len=%zu seqovl=%u : ",split_pos-1, split_pos, params.desync_seqovl)
					hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					if (desync_mode==DESYNC_SPLIT)
					{
						DLOG("sending fake(2) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos)
						hexdump_limited_dlog(zeropkt,split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
							return verdict;
					}
					if (split_pos<len_payload)
					{
						pkt1_len = sizeof(pkt1);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(tcphdr->th_seq,split_pos), tcphdr->th_ack, tcphdr->th_win, scale_factor, timestamps,
								ttl_orig,fooling_orig,params.desync_badseq_increment,params.desync_badseq_ack_increment,
								data_payload+split_pos, len_payload-split_pos, pkt1, &pkt1_len))
							return verdict;
						DLOG("sending 2nd tcp segment %zu-%zu len=%zu : ",split_pos,len_payload-1, len_payload-split_pos)
						hexdump_limited_dlog(data_payload+split_pos,len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n")
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							return verdict;
					}

					return VERDICT_DROP;
				}
				break;
			case DESYNC_IPFRAG2:
				if (!reasm_offset)
				{
					verdict_tcp_csum_fix(verdict, tcphdr, transport_len, ip, ip6hdr);

					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;

					size_t ipfrag_pos = (params.desync_ipfrag_pos_tcp && params.desync_ipfrag_pos_tcp<transport_len) ? params.desync_ipfrag_pos_tcp : 24;
					uint32_t ident = ip ? ip->ip_id ? ip->ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (ip6hdr && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, data_pkt, *len_pkt, pkt3, &pkt_orig_len))
							return verdict;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = data_pkt;
						pkt_orig_len = *len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return verdict;

					DLOG("sending 1st ip fragment 0-%zu ip_payload_len=%zu : ", ipfrag_pos-1, ipfrag_pos)
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					DLOG("sending 2nd ip fragment %zu-%zu ip_payload_len=%zu : ", ipfrag_pos, transport_len-1, transport_len-ipfrag_pos)
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return verdict;

					return VERDICT_DROP;
				}
		}
	
	}

	return verdict;
}

// return : true - should continue, false - should stop with verdict
static bool quic_reasm_cancel(t_ctrack *ctrack, const char *reason)
{
	reasm_orig_cancel(ctrack);
	if (params.desync_any_proto)
	{
		DLOG("%s. applying tampering because desync_any_proto is set\n",reason)
		return true;
	}
	else
	{
		DLOG("%s. not applying tampering because desync_any_proto is not set\n",reason)
		return false;
	}
}

static uint8_t dpi_desync_udp_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct udphdr *udphdr, size_t transport_len, uint8_t *data_payload, size_t len_payload)
{
	uint8_t verdict=VERDICT_PASS;

	// no need to desync middle packets in reasm session
	if (reasm_offset) return verdict;

	t_ctrack *ctrack=NULL, *ctrack_replay=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake;
	
	if (replay)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, ip, ip6hdr, NULL, udphdr, &ctrack_replay, &bReverse) || bReverse)
			return verdict;
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		ConntrackPoolPurge(&params.conntrack);
		if (ConntrackPoolFeed(&params.conntrack, ip, ip6hdr, NULL, udphdr, len_payload, &ctrack, &bReverse))
		{
			ctrack_replay = ctrack;
			maybe_cutoff(ctrack, IPPROTO_UDP);
		}
		HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);
		//ConntrackPoolDump(&params.conntrack);
	}

	if (bReverse) return verdict; // nothing to do. do not waste cpu

	if (params.desync_mode==DESYNC_NONE && !*params.hostlist_auto_filename) return verdict; // do not waste cpu

	// start and cutoff limiters
	if (!replay && !process_desync_interval(ctrack)) return verdict;

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;
	ttl_orig = ip ? ip->ip_ttl : ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	if (ip6hdr) ttl_fake = params.desync_ttl6 ? params.desync_ttl6 : ttl_orig;
	else ttl_fake = params.desync_ttl ? params.desync_ttl : ttl_orig;
	extract_endpoints(ip, ip6hdr, NULL, udphdr, &src, &dst);
	
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

			uint8_t clean[16384], *pclean;
			size_t clean_len;
			bool bIsHello = false;

			if (replay)
			{
				clean_len = ctrack_replay->reasm_orig.size_present;
				pclean = ctrack_replay->reasm_orig.packet;
			}
			else
			{
				clean_len = sizeof(clean);
				pclean = QUICDecryptInitial(data_payload,len_payload,clean,&clean_len) ? clean : NULL;
			}
			if (pclean)
			{
				if (ctrack && !ReasmIsEmpty(&ctrack->reasm_orig))
				{
					if (ReasmHasSpace(&ctrack->reasm_orig, clean_len))
					{
						reasm_orig_feed(ctrack,IPPROTO_UDP,clean,clean_len);
						pclean = ctrack->reasm_orig.packet;
						clean_len = ctrack->reasm_orig.size_present;
					}
					else
					{
						DLOG("QUIC reasm is too long. cancelling.\n");
						reasm_orig_cancel(ctrack);
						return verdict; // cannot be first packet
					}
				}

				uint8_t defrag[16384];
				size_t hello_offset, hello_len, defrag_len = sizeof(defrag);
				if (QUICDefragCrypto(pclean,clean_len,defrag,&defrag_len))
				{
					bool bIsHello = IsQUICCryptoHello(defrag, defrag_len, &hello_offset, &hello_len);
					bool bReqFull = bIsHello ? IsTLSHandshakeFull(defrag+hello_offset,hello_len) : false;

					DLOG(bIsHello ? bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n" : "packet does not contain TLS ClientHello\n")

					if (ctrack)
					{
						if (bIsHello && !bReqFull && ReasmIsEmpty(&ctrack->reasm_orig))
						{
							// preallocate max buffer to avoid reallocs that cause memory copy
							if (!reasm_orig_start(ctrack,IPPROTO_UDP,16384,16384,clean,clean_len))
							{
								reasm_orig_cancel(ctrack);
								return verdict;
							}
						}
						if (!ReasmIsEmpty(&ctrack->reasm_orig))
						{
							verdict_udp_csum_fix(verdict, udphdr, transport_len, ip, ip6hdr);
							if (rawpacket_queue(&ctrack->delayed, &dst, desync_fwmark, ifout, data_pkt, *len_pkt, len_payload))
							{
								DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
							}
							else
							{
								fprintf(stderr, "rawpacket_queue failed !'\n");
								reasm_orig_cancel(ctrack);
								return verdict;
							}
							if (bReqFull)
							{
								replay_queue(&ctrack->delayed);
								reasm_orig_fin(ctrack);
							}
							return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
						}
					}
			
					if (bIsHello)
					{
						bHaveHost = TLSHelloExtractHostFromHandshake(defrag + hello_offset, hello_len, host, sizeof(host), TLS_PARTIALS_ENABLE);
						if (!bHaveHost && params.desync_skip_nosni)
						{
							reasm_orig_cancel(ctrack);
							DLOG("not applying tampering to QUIC ClientHello without hostname in the SNI\n")
							return verdict;
						}
					}
					else
					{
						if (!quic_reasm_cancel(ctrack,"QUIC initial without ClientHello")) return verdict;
					}
				}
				else
				{
					// defrag failed
					if (!quic_reasm_cancel(ctrack,"QUIC initial defrag CRYPTO failed")) return verdict;
				}
			}
			else
			{
				// decrypt failed
				if (!quic_reasm_cancel(ctrack,"QUIC initial decryption failed")) return verdict;
			}
			
			fake = params.fake_quic;
			fake_size = params.fake_quic_size;
			bKnownProtocol = true;
		}
		else // not QUIC initial
		{
			// received payload without host. it means we are out of the request retransmission phase. stop counter
			ctrack_stop_retrans_counter(ctrack);
			
			reasm_orig_cancel(ctrack);

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
				if (!params.desync_any_proto) return verdict;
				DLOG("applying tampering to unknown protocol\n")
				fake = params.fake_unknown_udp;
				fake_size = params.fake_unknown_udp_size;
			}
		}

		if (bHaveHost)
		{
			DLOG("hostname: %s\n",host)
			if (params.hostlist || params.hostlist_exclude)
			{
				bool bBypass;
				if (!HostlistCheck(host, &bBypass))
				{
					if (ctrack_replay)
					{
						ctrack_replay->hostname_ah_check = *params.hostlist_auto_filename && !bBypass;
						if (ctrack_replay->hostname_ah_check)
						{
							// first request is not retrans
							if (ctrack_replay->hostname)
								process_retrans_fail(ctrack_replay, IPPROTO_UDP);
							else
								ctrack_replay->hostname=strdup(host);
						}
					}
					DLOG("not applying tampering to this request\n")
					return verdict;
				}
			}
		}

		enum dpi_desync_mode desync_mode = params.desync_mode;
		uint32_t fooling_orig = FOOL_NONE;

		if (params.debug)
		{
			printf("dpi desync src=");
			print_sockaddr((struct sockaddr *)&src);
			printf(" dst=");
			print_sockaddr((struct sockaddr *)&dst);
			printf("\n");
		}

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
					return verdict;
				DLOG("sending fake request : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n")
				if (!rawsend_rep((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return verdict;
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
						return verdict;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
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
				verdict_udp_csum_fix(verdict, udphdr, transport_len, ip, ip6hdr);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , data_pkt, *len_pkt))
					return verdict;
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
					return verdict;
				}
				DLOG("resending original packet with increased by %d length\n", params.udplen_increment);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return verdict;
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
						return verdict;
					}
					memcpy(pkt2+pkt2_len,data_payload+1,szcopy);
					pkt2_len+=szcopy;
					pkt1_len = sizeof(pkt1);
					if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_orig,fooling_orig, NULL, 0 , 0, pkt2, pkt2_len, pkt1, &pkt1_len))
					{
						DLOG("could not construct packet with modified length. too large ?\n");
						return verdict;
					}
					DLOG("resending tampered DHT\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
				}
				else
				{
					DLOG("payload is not tamperable\n");
					return verdict;
				}
			case DESYNC_IPFRAG2:
				{
					verdict_udp_csum_fix(verdict, udphdr, transport_len, ip, ip6hdr);
				
					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;
					
					size_t ipfrag_pos = (params.desync_ipfrag_pos_udp && params.desync_ipfrag_pos_udp<transport_len) ? params.desync_ipfrag_pos_udp : sizeof(struct udphdr);
					// freebsd do not set ip.id
					uint32_t ident = ip ? ip->ip_id ? ip->ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (ip6hdr && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, data_pkt, *len_pkt, pkt3, &pkt_orig_len))
							return verdict;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = data_pkt;
						pkt_orig_len = *len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return verdict;

					DLOG("sending 1st ip fragment 0-%zu ip_payload_len=%zu : ", ipfrag_pos-1, ipfrag_pos)
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					DLOG("sending 2nd ip fragment %zu-%zu ip_payload_len=%zu : ", ipfrag_pos, transport_len-1, transport_len-ipfrag_pos)
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n")
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return verdict;

					return ct_new_postnat_fix_udp(ctrack, ip, ip6hdr, udphdr, len_pkt);
				}
		}

	}

	return verdict;
}


static void packet_debug(bool replay, uint8_t proto, const struct ip *ip, const struct ip6_hdr *ip6hdr, const struct tcphdr *tcphdr, const struct udphdr *udphdr, const uint8_t *data_payload, size_t len_payload)
{
	if (params.debug)
	{
		if (replay) printf("REPLAY ");
		if (ip)
		{
			printf("IP4: ");
			print_ip(ip);
		}
		else if (ip6hdr)
		{
			printf("IP6: ");
			print_ip6hdr(ip6hdr, proto);
		}
		if (tcphdr)
		{
			printf(" ");
			print_tcphdr(tcphdr);
			printf("\n");
			if (len_payload) { printf("TCP: "); hexdump_limited_dlog(data_payload, len_payload, 32); printf("\n"); }

		}
		else if (udphdr)
		{
			printf(" ");
			print_udphdr(udphdr);
			printf("\n");
			if (len_payload) { printf("UDP: "); hexdump_limited_dlog(data_payload, len_payload, 32); printf("\n"); }
		}
		else
			printf("\n");
	}
}


static uint8_t dpi_desync_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt)
{
	struct ip *ip;
	struct ip6_hdr *ip6hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	size_t transport_len;
	uint8_t *data_payload,proto;
	size_t len_payload;
	uint8_t verdict = VERDICT_PASS;
	
	proto_dissect_l3l4(data_pkt,*len_pkt,&ip,&ip6hdr,&proto,&tcphdr,&udphdr,&transport_len,&data_payload,&len_payload);
	if (!!ip != !!ip6hdr)
	{
		packet_debug(replay, proto, ip, ip6hdr, tcphdr, udphdr, data_payload, len_payload);
		switch(proto)
		{
			case IPPROTO_TCP:
				if (tcphdr)
				{
					verdict = dpi_desync_tcp_packet_play(replay, reasm_offset, fwmark, ifout, data_pkt, len_pkt, ip, ip6hdr, tcphdr, transport_len, data_payload, len_payload);
					verdict_tcp_csum_fix(verdict, tcphdr, transport_len, ip, ip6hdr);
				}
				break;
			case IPPROTO_UDP:
				if (udphdr)
				{
					verdict = dpi_desync_udp_packet_play(replay, reasm_offset, fwmark, ifout, data_pkt, len_pkt, ip, ip6hdr, udphdr, transport_len, data_payload, len_payload);
					verdict_udp_csum_fix(verdict, udphdr, transport_len, ip, ip6hdr);
				}
				break;
		}
	}
	return verdict;
}
uint8_t dpi_desync_packet(uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt)
{
	return dpi_desync_packet_play(false, 0, fwmark, ifout, data_pkt, len_pkt);
}



static bool replay_queue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	size_t offset;
	unsigned int i;
	bool b = true;
	for (i=1,offset=0 ; (rp=rawpacket_dequeue(q)) ; offset+=rp->len_payload, rawpacket_free(rp), i++)
	{
		DLOG("REPLAYING delayed packet #%u offset %zu\n",i,offset)
		uint8_t verdict = dpi_desync_packet_play(true, offset, rp->fwmark, rp->ifout, rp->packet, &rp->len);
		switch(verdict & VERDICT_MASK)
		{
			case VERDICT_MODIFY:
				DLOG("SENDING delayed packet #%u modified\n", i)
				b &= rawsend_rp(rp);
				break;
			case VERDICT_PASS:
				DLOG("SENDING delayed packet #%u unmodified\n", i)
				b &= rawsend_rp(rp);
				break;
			case VERDICT_DROP:
				DLOG("DROPPING delayed packet #%u\n", i)
				break;
		}
	}
	return b;
}
