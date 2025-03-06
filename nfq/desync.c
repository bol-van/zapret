#define _GNU_SOURCE

#include <string.h>
#include <errno.h>

#include "desync.h"
#include "protocol.h"
#include "params.h"
#include "helpers.h"
#include "hostlist.h"
#include "ipset.h"
#include "conntrack.h"

const char *fake_http_request_default = "GET / HTTP/1.1\r\nHost: www.iana.org\r\n"
                                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n"
                                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                                        "Accept-Encoding: gzip, deflate, br\r\n\r\n";

// random : +11 size 32
// random : +44 size 32
// sni : gatech.edu +125 size 11
const uint8_t fake_tls_clienthello_default[648] = {
0x16,0x03,0x01,0x02,0x83,0x01,0x00,0x02,0x7f,0x03,0x03,0x98,0xfb,0x69,0x1d,0x31,
0x66,0xc4,0xd8,0x07,0x25,0x2b,0x74,0x47,0x01,0x44,0x09,0x08,0xcf,0x13,0x67,0xe0,
0x46,0x19,0x1f,0xcb,0xee,0xe6,0x8e,0x33,0xb9,0x91,0xa0,0x20,0xf2,0xed,0x56,0x73,
0xa4,0x0a,0xce,0xa6,0xad,0xd2,0xfd,0x71,0xb8,0xb9,0xfd,0x06,0x0e,0xdd,0xf0,0x57,
0x37,0x7d,0x96,0xb5,0x80,0x6e,0x54,0xe2,0x15,0xce,0x5f,0xff,0x00,0x22,0x13,0x01,
0x13,0x03,0x13,0x02,0xc0,0x2b,0xc0,0x2f,0xcc,0xa9,0xcc,0xa8,0xc0,0x2c,0xc0,0x30,
0xc0,0x0a,0xc0,0x09,0xc0,0x13,0xc0,0x14,0x00,0x9c,0x00,0x9d,0x00,0x2f,0x00,0x35,
0x01,0x00,0x02,0x14,0x00,0x00,0x00,0x0f,0x00,0x0d,0x00,0x00,0x0a,0x67,0x61,0x74,
0x65,0x63,0x68,0x2e,0x65,0x64,0x75,0x00,0x17,0x00,0x00,0xff,0x01,0x00,0x01,0x00,
0x00,0x0a,0x00,0x0e,0x00,0x0c,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x19,0x01,0x00,
0x01,0x01,0x00,0x0b,0x00,0x02,0x01,0x00,0x00,0x10,0x00,0x0e,0x00,0x0c,0x02,0x68,
0x32,0x08,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x31,0x00,0x05,0x00,0x05,0x01,0x00,
0x00,0x00,0x00,0x00,0x22,0x00,0x0a,0x00,0x08,0x04,0x03,0x05,0x03,0x06,0x03,0x02,
0x03,0x00,0x33,0x00,0x6b,0x00,0x69,0x00,0x1d,0x00,0x20,0x72,0xe5,0xce,0x58,0x31,
0x3c,0x08,0xaa,0x2f,0xa8,0x40,0xe7,0x7a,0xdf,0x46,0x5b,0x63,0x62,0xc7,0xfa,0x49,
0x18,0xac,0xa1,0x00,0x7c,0x42,0xc5,0x02,0x94,0x5c,0x44,0x00,0x17,0x00,0x41,0x04,
0x8f,0x3e,0x5f,0xd4,0x7f,0x37,0x47,0xd3,0x33,0x70,0x38,0x7f,0x11,0x35,0xc1,0x55,
0x8a,0x6c,0xc7,0x5a,0xd4,0xf7,0x31,0xbb,0x9e,0xee,0xd1,0x8f,0x74,0xdd,0x9b,0xbb,
0x91,0xa1,0x72,0xda,0xeb,0xf6,0xc6,0x82,0x84,0xfe,0xb7,0xfd,0x7b,0xe1,0x9f,0xd2,
0xb9,0x3e,0x83,0xa6,0x9c,0xac,0x81,0xe2,0x00,0xd5,0x19,0x55,0x91,0xa7,0x0c,0x29,
0x00,0x2b,0x00,0x05,0x04,0x03,0x04,0x03,0x03,0x00,0x0d,0x00,0x18,0x00,0x16,0x04,
0x03,0x05,0x03,0x06,0x03,0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,
0x01,0x02,0x03,0x02,0x01,0x00,0x1c,0x00,0x02,0x40,0x01,0xfe,0x0d,0x01,0x19,0x00,
0x00,0x01,0x00,0x01,0xfe,0x00,0x20,0xae,0x8b,0x30,0x3c,0xf0,0xa9,0x0d,0xa1,0x69,
0x95,0xb8,0xe2,0xed,0x08,0x6d,0x48,0xdf,0xf7,0x5b,0x9d,0x66,0xef,0x15,0x97,0xbc,
0x2c,0x99,0x91,0x12,0x7a,0x35,0xd0,0x00,0xef,0xb1,0x8d,0xff,0x61,0x57,0x52,0xef,
0xd6,0xea,0xbf,0xf3,0x6d,0x78,0x14,0x38,0xff,0xeb,0x58,0xe8,0x9d,0x59,0x4b,0xd5,
0x9f,0x59,0x12,0xf9,0x03,0x9a,0x20,0x37,0x85,0x77,0xb1,0x4c,0xd8,0xef,0xa6,0xc8,
0x54,0x8d,0x07,0x27,0x95,0xce,0xd5,0x37,0x4d,0x69,0x18,0xd4,0xfd,0x5e,0xdf,0x64,
0xcc,0x10,0x2f,0x7f,0x0e,0xc9,0xfd,0xd4,0xd0,0x18,0x61,0x1b,0x57,0x8f,0x41,0x7f,
0x6f,0x4f,0x5c,0xad,0x04,0xc6,0x5e,0x74,0x54,0x87,0xba,0x28,0xe6,0x11,0x0b,0x9d,
0x3f,0x0b,0x6d,0xf4,0x2d,0xfc,0x31,0x4e,0xfd,0x49,0xe7,0x15,0x96,0xaf,0xee,0x9a,
0x48,0x1b,0xae,0x5e,0x7c,0x20,0xbe,0xb4,0xec,0x68,0xb6,0x74,0x22,0xa0,0xec,0xff,
0x19,0x96,0xe4,0x10,0x8f,0x3c,0x91,0x88,0xa1,0xcc,0x78,0xef,0x4e,0x0e,0xe3,0xb6,
0x57,0x8c,0x33,0xef,0xaa,0xb0,0x1d,0x45,0x1c,0x02,0x4c,0xe2,0x80,0x30,0xe8,0x48,
0x7a,0x09,0x71,0x94,0x7c,0xb6,0x75,0x81,0x1c,0xae,0xe3,0x3f,0xde,0xea,0x2b,0x45,
0xcc,0xe3,0x64,0x09,0xf7,0x60,0x26,0x0c,0x7d,0xad,0x55,0x65,0xb6,0xf5,0x85,0x04,
0x64,0x2f,0x97,0xd0,0x6a,0x06,0x36,0xcd,0x25,0xda,0x51,0xab,0xd6,0xf7,0x5e,0xeb,
0xd4,0x03,0x39,0xa4,0xc4,0x2a,0x9c,0x17,0xe8,0xb0,0x9f,0xc0,0xd3,0x8c,0x76,0xdd,
0xa1,0x0b,0x76,0x9f,0x23,0xfa,0xed,0xfb,0xd7,0x78,0x0f,0x00,0xf7,0x45,0x03,0x04,
0x84,0x66,0x6b,0xec,0xc7,0xed,0xbc,0xe4
};

#define PKTDATA_MAXDUMP 32
#define IP_MAXDUMP 80

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
	return mode==DESYNC_NONE || mode==DESYNC_FAKEDDISORDER || mode==DESYNC_FAKEDSPLIT || mode==DESYNC_MULTISPLIT || mode==DESYNC_MULTIDISORDER || mode==DESYNC_IPFRAG2 || mode==DESYNC_UDPLEN || mode==DESYNC_TAMPER;
}
bool desync_valid_second_stage_tcp(enum dpi_desync_mode mode)
{
	return mode==DESYNC_NONE || mode==DESYNC_FAKEDDISORDER || mode==DESYNC_FAKEDSPLIT || mode==DESYNC_MULTISPLIT || mode==DESYNC_MULTIDISORDER || mode==DESYNC_IPFRAG2;
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
	else if (!strcmp(s,"fakeddisorder") || !strcmp(s,"disorder"))
		return DESYNC_FAKEDDISORDER;
	else if (!strcmp(s,"fakedsplit") || !strcmp(s,"split"))
		return DESYNC_FAKEDSPLIT;
	else if (!strcmp(s,"multisplit") || !strcmp(s,"split2"))
		return DESYNC_MULTISPLIT;
	else if (!strcmp(s,"multidisorder") || !strcmp(s,"disorder2"))
		return DESYNC_MULTIDISORDER;
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

static bool dp_match(
	struct desync_profile *dp,
	uint8_t l3proto, const struct sockaddr *dest, const char *hostname, t_l7proto l7proto,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	bool bHostlistsEmpty;

	if (bCheckDone) *bCheckDone = false;

	if (!HostlistsReloadCheckForProfile(dp)) return false;

	if ((dest->sa_family==AF_INET && !dp->filter_ipv4) || (dest->sa_family==AF_INET6 && !dp->filter_ipv6))
		// L3 filter does not match
		return false;
	if ((l3proto==IPPROTO_TCP && !port_filters_in_range(&dp->pf_tcp,saport(dest))) || (l3proto==IPPROTO_UDP && !port_filters_in_range(&dp->pf_udp,saport(dest))))
		// L4 filter does not match
		return false;
	if (dp->filter_l7 && !l7_proto_match(l7proto, dp->filter_l7))
		// L7 filter does not match
		return false;
	bHostlistsEmpty = PROFILE_HOSTLISTS_EMPTY(dp);
	if (!dp->hostlist_auto && !hostname && !bHostlistsEmpty)
		// avoid cpu consuming ipset check. profile cannot win if regular hostlists are present without auto hostlist and hostname is unknown.
		return false;
	if (!IpsetCheck(dp, dest->sa_family==AF_INET ? &((struct sockaddr_in*)dest)->sin_addr : NULL, dest->sa_family==AF_INET6 ? &((struct sockaddr_in6*)dest)->sin6_addr : NULL))
		// target ip does not match
		return false;

	// autohostlist profile matching l3/l4/l7 filter always win
	if (dp->hostlist_auto) return true;

	if (bHostlistsEmpty)
		// profile without hostlist filter wins
		return true;
	else
	{
		// if hostlists are present profile matches only if hostname is known and satisfy profile hostlists
		if (hostname)
		{
			if (bCheckDone) *bCheckDone = true;
			bool b;
			b = HostlistCheck(dp, hostname, bExcluded, true);
			if (bCheckResult) *bCheckResult = b;
			return b;
		}
	}
	return false;
}
static struct desync_profile *dp_find(
	struct desync_profile_list_head *head,
	uint8_t l3proto, const struct sockaddr *dest, const char *hostname, t_l7proto l7proto,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	struct desync_profile_list *dpl;
	if (params.debug)
	{
		char ip_port[48];
		ntop46_port(dest, ip_port,sizeof(ip_port));
		DLOG("desync profile search for %s target=%s l7proto=%s hostname='%s'\n", proto_name(l3proto), ip_port, l7proto_str(l7proto), hostname ? hostname : "");
	}
	if (bCheckDone) *bCheckDone = false;
	LIST_FOREACH(dpl, head, next)
	{
		if (dp_match(&dpl->dp,l3proto,dest,hostname,l7proto,bCheckDone,bCheckResult,bExcluded))
		{
			DLOG("desync profile %d matches\n",dpl->dp.n);
			return &dpl->dp;
		}
	}
	DLOG("desync profile not found\n");
	return NULL;
}

// auto creates internal socket and uses it for subsequent calls
static bool rawsend_rep(int repeats, const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len)
{
	for (int i=0;i<repeats;i++)
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
	if (ctrack && ctrack->dp)
	{
		if (proto==IPPROTO_TCP)
			ctrack->b_wssize_cutoff |= cutoff_test(ctrack, ctrack->dp->wssize_cutoff, ctrack->dp->wssize_cutoff_mode);
		ctrack->b_desync_cutoff |= cutoff_test(ctrack, ctrack->dp->desync_cutoff, ctrack->dp->desync_cutoff_mode);

		// in MULTI STRATEGY concept conntrack entry holds desync profile
		// we do not want to remove conntrack entries ASAP anymore

		/*
		// we do not need conntrack entry anymore if all cutoff conditions are either not defined or reached
		// do not drop udp entry because it will be recreated when next packet arrives
		if (proto==IPPROTO_TCP)
			ctrack->b_cutoff |= \
			    (!ctrack->dp->wssize || ctrack->b_wssize_cutoff) &&
			    (!ctrack->dp->desync_cutoff || ctrack->b_desync_cutoff) &&
			    (!ctrack->hostname_ah_check || ctrack->req_retrans_counter==RETRANS_COUNTER_STOP) &&
			    ReasmIsEmpty(&ctrack->reasm_orig);
		*/
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
 	if (ctrack && ctrack->dp && ctrack->dp->wssize && !ctrack->b_wssize_cutoff)
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

static void auto_hostlist_reset_fail_counter(struct desync_profile *dp, const char *hostname, const char *client_ip_port, t_l7proto l7proto)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;
	
		fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
			DLOG("auto hostlist (profile %d) : %s : fail counter reset. website is working.\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : fail counter reset. website is working.", hostname, dp->n, client_ip_port, l7proto_str(l7proto));
		}
	}
}

// return true if retrans trigger fires
static bool auto_hostlist_retrans(t_ctrack *ctrack, uint8_t l4proto, int threshold, const char *client_ip_port, t_l7proto l7proto)
{
	if (ctrack && ctrack->dp && ctrack->hostname_ah_check && ctrack->req_retrans_counter!=RETRANS_COUNTER_STOP)
	{
		if (l4proto==IPPROTO_TCP)
		{
			if (!ctrack->req_seq_finalized || ctrack->req_seq_abandoned)
				return false;
			if (!seq_within(ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end))
			{
				DLOG("req retrans : tcp seq %u not within the req range %u-%u. stop tracking.\n", ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end);
				ctrack_stop_retrans_counter(ctrack);
				auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname, client_ip_port, l7proto);
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
static void auto_hostlist_failed(struct desync_profile *dp, const char *hostname, const char *client_ip_port, t_l7proto l7proto)
{
	hostfail_pool *fail_counter;
	
	fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
	if (!fail_counter)
	{
		fail_counter = HostFailPoolAdd(&dp->hostlist_auto_fail_counters, hostname, dp->hostlist_auto_fail_time);
		if (!fail_counter)
		{
			DLOG_ERR("HostFailPoolAdd: out of memory\n");
			return;
		}
	}
	fail_counter->counter++;
	DLOG("auto hostlist (profile %d) : %s : fail counter %d/%d\n", dp->n, hostname, fail_counter->counter, dp->hostlist_auto_fail_threshold);
	HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : fail counter %d/%d", hostname, dp->n, client_ip_port, l7proto_str(l7proto), fail_counter->counter, dp->hostlist_auto_fail_threshold);
	if (fail_counter->counter >= dp->hostlist_auto_fail_threshold)
	{
		DLOG("auto hostlist (profile %d) : fail threshold reached. about to add %s to auto hostlist\n", dp->n, hostname);
		HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
		
		DLOG("auto hostlist (profile %d) : rechecking %s to avoid duplicates\n", dp->n, hostname);
		bool bExcluded=false;
		if (!HostlistCheck(dp, hostname, &bExcluded, false) && !bExcluded)
		{
			DLOG("auto hostlist (profile %d) : adding %s to %s\n", dp->n, hostname, dp->hostlist_auto->filename);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : adding to %s", hostname, dp->n, client_ip_port, l7proto_str(l7proto), dp->hostlist_auto->filename);
			if (!HostlistPoolAddStr(&dp->hostlist_auto->hostlist, hostname, 0))
			{
				DLOG_ERR("StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(dp->hostlist_auto->filename, hostname))
			{
				DLOG_PERROR("write to auto hostlist");
				return;
			}
			if (!file_mod_signature(dp->hostlist_auto->filename, &dp->hostlist_auto->mod_sig))
				DLOG_PERROR("file_mod_signature");
		}
		else
		{
			DLOG("auto hostlist (profile %d) : NOT adding %s\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : NOT adding, duplicate detected", hostname, dp->n, client_ip_port, l7proto_str(l7proto));
		}
	}
}

static void process_retrans_fail(t_ctrack *ctrack, uint8_t proto, const struct sockaddr *client)
{
	char client_ip_port[48];
	if (*params.hostlist_auto_debuglog)
		ntop46_port((struct sockaddr*)client,client_ip_port,sizeof(client_ip_port));
	else
		*client_ip_port=0;
	if (ctrack && ctrack->dp && ctrack->hostname && auto_hostlist_retrans(ctrack, proto, ctrack->dp->hostlist_auto_retrans_threshold, client_ip_port, ctrack->l7proto))
	{
		HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : retrans threshold reached", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
		auto_hostlist_failed(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
	}
}

static bool send_delayed(t_ctrack *ctrack)
{
	if (!rawpacket_queue_empty(&ctrack->delayed))
	{
		DLOG("SENDING %u delayed packets\n", rawpacket_queue_count(&ctrack->delayed));
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
			DLOG("reassemble : feeding data payload size=%zu. now we have %zu/%zu\n", len_payload,reasm->size_present,reasm->size);
			return true;
		}
		else
		{
			ReasmClear(reasm);
			DLOG("reassemble session failed\n");
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
		DLOG("applying linux postnat conntrack workaround\n");
		if (proto==IPPROTO_UDP && udp && len_pkt)
		{
			// make malformed udp packet with zero length and invalid checksum
			udp->uh_ulen = 0; // invalid length. must be >=8
			udp_fix_checksum(udp,sizeof(struct udphdr),ip,ip6);
			udp->uh_sum ^= htons(0xBEAF);
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


static bool check_desync_interval(const struct desync_profile *dp, const t_ctrack *ctrack)
{
	if (dp)
	{
		if (dp->desync_start)
		{
			if (ctrack)
			{
				if (!cutoff_test(ctrack, dp->desync_start, dp->desync_start_mode))
				{
					DLOG("desync-start not reached (mode %c): %llu/%u . not desyncing\n", dp->desync_start_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->desync_start_mode), dp->desync_start);
					return false;
				}
				DLOG("desync-start reached (mode %c): %llu/%u\n", dp->desync_start_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->desync_start_mode), dp->desync_start);
			}
			else
			{
				DLOG("not desyncing. desync-start is set but conntrack entry is missing\n");
				return false;
			}
		}
		if (dp->desync_cutoff)
		{
			if (ctrack)
			{
				if (ctrack->b_desync_cutoff)
				{
					DLOG("desync-cutoff reached (mode %c): %llu/%u . not desyncing\n", dp->desync_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->desync_cutoff_mode), dp->desync_cutoff);
					return false;
				}
				DLOG("desync-cutoff not reached (mode %c): %llu/%u\n", dp->desync_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->desync_cutoff_mode), dp->desync_cutoff);
			}
			else
			{
				DLOG("not desyncing. desync-cutoff is set but conntrack entry is missing\n");
				return false;
			}
		}
	}
	return true;
}
static bool process_desync_interval(const struct desync_profile *dp, t_ctrack *ctrack)
{
	if (check_desync_interval(dp, ctrack))
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
	return (split_pos>reasm_offset && (split_pos-reasm_offset)<len_payload) ? split_pos-reasm_offset : 0;
}

static void autottl_discover(t_ctrack *ctrack, bool bIpv6)
{
	if (ctrack && ctrack->incoming_ttl)
	{
		autottl *attl = bIpv6 ? &ctrack->dp->desync_autottl6 : &ctrack->dp->desync_autottl;
		if (AUTOTTL_ENABLED(*attl))
		{
			ctrack->autottl = autottl_guess(ctrack->incoming_ttl, attl);
			if (ctrack->autottl)
				DLOG("autottl: guessed %u\n",ctrack->autottl);
			else
				DLOG("autottl: could not guess\n");
		}
		else
			ctrack->autottl = 0;
	}
}

#ifdef BSD
// BSD pass to divert socket ip_id=0 and does not auto set it if sent via divert socket
static uint16_t IP4_IP_ID_FIX(const struct ip *ip)
{
	return ip ? ip->ip_id ? ip->ip_id : (uint16_t)random() : 0;
}
#define IP4_IP_ID_NEXT(ip_id) net16_add(ip_id,+1)
#define IP4_IP_ID_PREV(ip_id) net16_add(ip_id,-1)
#else
// in linux kernel sets increasing ip_id if it's zero
#define IP4_IP_ID_FIX(x) 0
#define IP4_IP_ID_NEXT(ip_id) ip_id
#define IP4_IP_ID_PREV(ip_id) ip_id
#endif


// fake_mod buffer must at least sizeof(desync_profile->fake_tls)
// size does not change
// return : true - altered, false - not altered
static bool runtime_tls_mod(const struct desync_profile *dp, uint8_t *fake_mod, const uint8_t *payload, size_t payload_len)
{
	bool b=false;
	if (dp->fake_tls_mod & FAKE_TLS_MOD_PADENCAP)
	{
		size_t sz_rec = pntoh16(dp->fake_tls+3) + payload_len;
		size_t sz_handshake = pntoh24(dp->fake_tls+6) + payload_len;
		size_t sz_ext = pntoh16(dp->fake_tls+dp->fake_tls_extlen_offset) + payload_len;
		size_t sz_pad = pntoh16(dp->fake_tls+dp->fake_tls_padlen_offset) + payload_len;
		if ((sz_rec & ~0xFFFF) || (sz_handshake & ~0xFFFFFF) || (sz_ext & ~0xFFFF) || (sz_pad & ~0xFFFF))
			DLOG("cannot apply padencap tls mod. length overflow.\n");
		else
		{
			memcpy(fake_mod,dp->fake_tls,dp->fake_tls_size);
			phton16(fake_mod+3,(uint16_t)sz_rec);
			phton24(fake_mod+6,(uint32_t)sz_handshake);
			phton16(fake_mod+dp->fake_tls_extlen_offset,(uint16_t)sz_ext);
			phton16(fake_mod+dp->fake_tls_padlen_offset,(uint16_t)sz_pad);
			b=true;
		}
	}
	if (dp->fake_tls_mod & FAKE_TLS_MOD_RND)
	{
		if (!b)	memcpy(fake_mod,dp->fake_tls,dp->fake_tls_size);
		fill_random_bytes(fake_mod+11,32); // random
		fill_random_bytes(fake_mod+44,fake_mod[43]); // session id
		b=true;
	}
	if (dp->fake_tls_mod & FAKE_TLS_MOD_DUP_SID)
	{
		if (dp->fake_tls[43]!=payload[43])
			DLOG("cannot apply dupsid tls mod. fake and orig session id length mismatch.\n");
		else if (payload_len<(44+payload[43]))
			DLOG("cannot apply dupsid tls mod. data payload is not valid.\n");
		else
		{
			if (!b)	memcpy(fake_mod,dp->fake_tls,dp->fake_tls_size);
			memcpy(fake_mod+44,payload+44,fake_mod[43]); // session id
			b=true;
		}
	}
	return b;
}

static uint8_t dpi_desync_tcp_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, struct dissect *dis)
{
	uint8_t verdict=VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	struct desync_profile *dp = NULL;

	t_ctrack *ctrack=NULL, *ctrack_replay=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake,flags_orig,scale_factor;
	uint32_t *timestamps;

	ttl_orig = dis->ip ? dis->ip->ip_ttl : dis->ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	uint32_t desync_fwmark = fwmark | params.desync_fwmark;
	extract_endpoints(dis->ip, dis->ip6, dis->tcp, NULL, &src, &dst);
	
	if (replay)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, dis->ip, dis->ip6, dis->tcp, NULL, &ctrack_replay, &bReverse) || bReverse)
			return verdict;

		dp = ctrack_replay->dp;
		if (dp)
			DLOG("using cached desync profile %d\n",dp->n);
		else if (!ctrack_replay->dp_search_complete)
		{
			dp = ctrack_replay->dp = dp_find(&params.desync_profiles, IPPROTO_TCP, (struct sockaddr *)&dst, ctrack_replay->hostname, ctrack_replay->l7proto, NULL, NULL, NULL);
			ctrack_replay->dp_search_complete = true;
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		ConntrackPoolPurge(&params.conntrack);
		if (ConntrackPoolFeed(&params.conntrack, dis->ip, dis->ip6, dis->tcp, NULL, dis->len_payload, &ctrack, &bReverse))
		{
			dp = ctrack->dp;
			ctrack_replay = ctrack;
		}
		if (dp)
			DLOG("using cached desync profile %d\n",dp->n);
		else if (!ctrack || !ctrack->dp_search_complete)
		{
			dp = dp_find(&params.desync_profiles, IPPROTO_TCP, (struct sockaddr *)&dst, ctrack ? ctrack->hostname : NULL, ctrack ? ctrack->l7proto : UNKNOWN, NULL, NULL, NULL);
			if (ctrack)
			{
				ctrack->dp = dp;
				ctrack->dp_search_complete = true;
			}
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
		maybe_cutoff(ctrack, IPPROTO_TCP);

		HostFailPoolPurgeRateLimited(&dp->hostlist_auto_fail_counters);

		//ConntrackPoolDump(&params.conntrack);

		if (dp->wsize && tcp_synack_segment(dis->tcp))
		{
			tcp_rewrite_winsize(dis->tcp, dp->wsize, dp->wscale);
			verdict=VERDICT_MODIFY;
		}

		if (bReverse)
		{
			if (ctrack)
			{
				if (!ctrack->incoming_ttl)
				{
					DLOG("incoming TTL %u\n",ttl_orig);
					ctrack->incoming_ttl = ttl_orig;
				}
				if (!ctrack->autottl) autottl_discover(ctrack,!!dis->ip6);
			}

			// process reply packets for auto hostlist mode
			// by looking at RSTs or HTTP replies we decide whether original request looks like DPI blocked
			// we only process first-sequence replies. do not react to subsequent redirects or RSTs
			if (ctrack && ctrack->hostname && ctrack->hostname_ah_check && (ctrack->ack_last-ctrack->ack0)==1)
			{
				bool bFail=false;

				char client_ip_port[48];
				if (*params.hostlist_auto_debuglog)
					ntop46_port((struct sockaddr*)&dst,client_ip_port,sizeof(client_ip_port));
				else
					*client_ip_port=0;

				if (dis->tcp->th_flags & TH_RST)
				{
					DLOG("incoming RST detected for hostname %s\n", ctrack->hostname);
					HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : incoming RST", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
					bFail = true;
				}
				else if (dis->len_payload && ctrack->l7proto==HTTP)
				{
					if (IsHttpReply(dis->data_payload,dis->len_payload))
					{
						DLOG("incoming HTTP reply detected for hostname %s\n", ctrack->hostname);
						bFail = HttpReplyLooksLikeDPIRedirect(dis->data_payload, dis->len_payload, ctrack->hostname);
						if (bFail)
						{
							DLOG("redirect to another domain detected. possibly DPI redirect.\n");
							HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : redirect to another domain", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
						}
						else
							DLOG("local or in-domain redirect detected. it's not a DPI redirect.\n");
					}
					else
					{
						// received not http reply. do not monitor this connection anymore
						DLOG("incoming unknown HTTP data detected for hostname %s\n", ctrack->hostname);
					}
				}
				if (bFail)
					auto_hostlist_failed(dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
				else
					if (dis->len_payload)
						auto_hostlist_reset_fail_counter(dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
				if (dis->tcp->th_flags & TH_RST)
					ConntrackClearHostname(ctrack); // do not react to further dup RSTs
			}
			
			return verdict; // nothing to do. do not waste cpu
		}

		if (dp->wssize)
		{
			if (ctrack)
			{
				if (ctrack->b_wssize_cutoff)
				{
					DLOG("wssize-cutoff reached (mode %c): %llu/%u . not changing wssize.\n", dp->wssize_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->wssize_cutoff_mode), dp->wssize_cutoff);
				}
				else
				{
					if (dp->wssize_cutoff) DLOG("wssize-cutoff not reached (mode %c): %llu/%u\n", dp->wssize_cutoff_mode, (unsigned long long)cutoff_get_limit(ctrack,dp->wssize_cutoff_mode), dp->wssize_cutoff);
					tcp_rewrite_winsize(dis->tcp, dp->wssize, dp->wsscale);
					verdict=VERDICT_MODIFY;
				}
			}
			else
			{
				DLOG("not changing wssize. wssize is set but conntrack entry is missing\n");
			}
		}
	} // !replay

	ttl_fake = (ctrack_replay && ctrack_replay->autottl) ? ctrack_replay->autottl : (dis->ip6 ? (dp->desync_ttl6 ? dp->desync_ttl6 : ttl_orig) : (dp->desync_ttl ? dp->desync_ttl : ttl_orig));
	flags_orig = *((uint8_t*)dis->tcp+13);
	scale_factor = tcp_find_scale_factor(dis->tcp);
	timestamps = tcp_find_timestamps(dis->tcp);

	if (!replay)
	{
		// start and cutoff limiters
		if (!process_desync_interval(dp, ctrack)) return verdict;

		if (tcp_syn_segment(dis->tcp))
		{
			switch (dp->desync_mode0)
			{
				case DESYNC_SYNACK:
					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_SYN|TH_ACK, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
						ttl_fake,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
						dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
						NULL, 0, pkt1, &pkt1_len))
					{
						return verdict;
					}
					DLOG("sending fake SYNACK\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					break;
				case DESYNC_SYNDATA:
					// make sure we are not breaking TCP fast open
					if (tcp_has_fastopen(dis->tcp))
					{
						DLOG("received SYN with TCP fast open option. syndata desync is not applied.\n");
						break;
					}
					if (dis->len_payload)
					{
						DLOG("received SYN with data payload. syndata desync is not applied.\n");
						break;
					}
					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
						ttl_orig,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
						0,0,0, dp->fake_syndata,dp->fake_syndata_size, pkt1,&pkt1_len))
					{
						return verdict;
					}
					DLOG("sending SYN with fake data : ");
					hexdump_limited_dlog(dp->fake_syndata,dp->fake_syndata_size,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					verdict = ct_new_postnat_fix_tcp(ctrack, dis->ip, dis->ip6, dis->tcp);
					break;
				default:
					break;
			}
			// can do nothing else with SYN packet
			return verdict;
		}

	} // !replay

	if (!(dis->tcp->th_flags & TH_SYN) && dis->len_payload)
	{
		const uint8_t *fake;
		size_t fake_size;
		char host[256];
		bool bHaveHost=false;
		uint8_t *p, *phost=NULL;
		const uint8_t *rdata_payload = dis->data_payload;
		size_t rlen_payload = dis->len_payload;
		size_t split_pos, seqovl_pos;
		size_t multisplit_pos[MAX_SPLITS];
		int multisplit_count;
		int i;
		uint16_t ip_id;
		t_l7proto l7proto = UNKNOWN;
		uint8_t fake_mod[sizeof(dp->fake_tls)];

		if (replay)
		{
			rdata_payload = ctrack_replay->reasm_orig.packet;
			rlen_payload = ctrack_replay->reasm_orig.size_present;
		}
		else if (reasm_orig_feed(ctrack,IPPROTO_TCP,dis->data_payload,dis->len_payload))
		{
			rdata_payload = ctrack->reasm_orig.packet;
			rlen_payload = ctrack->reasm_orig.size_present;
		}

		process_retrans_fail(ctrack, IPPROTO_TCP, (struct sockaddr*)&src);

		if (IsHttp(rdata_payload,rlen_payload))
		{
			DLOG("packet contains HTTP request\n");
			l7proto = HTTP;
			if (ctrack && ctrack->l7proto==UNKNOWN) ctrack->l7proto = l7proto;

			// we do not reassemble http
			reasm_orig_cancel(ctrack);
			forced_wssize_cutoff(ctrack);

			bHaveHost=HttpExtractHost(rdata_payload,rlen_payload,host,sizeof(host));
			if (!bHaveHost)
			{
				DLOG("not applying tampering to HTTP without Host:\n");
				return verdict;
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
		}
		else if (IsTLSClientHello(rdata_payload,rlen_payload,TLS_PARTIALS_ENABLE))
		{
			bool bReqFull = IsTLSRecordFull(rdata_payload,rlen_payload);
			DLOG(bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n");
			l7proto = TLS;

			bHaveHost=TLSHelloExtractHost(rdata_payload,rlen_payload,host,sizeof(host),TLS_PARTIALS_ENABLE);

			if (ctrack)
			{
				if (!ctrack->l7proto) ctrack->l7proto = l7proto;
				// do not reasm retransmissions
				if (!bReqFull && ReasmIsEmpty(&ctrack->reasm_orig) && !ctrack->req_seq_abandoned &&
					!(ctrack->req_seq_finalized && seq_within(ctrack->seq_last, ctrack->req_seq_start, ctrack->req_seq_end)))
				{
					// do not reconstruct unexpected large payload (they are feeding garbage ?)
					if (!reasm_orig_start(ctrack,IPPROTO_TCP,TLSRecordLen(dis->data_payload),16384,dis->data_payload,dis->len_payload))
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
					verdict_tcp_csum_fix(verdict, dis->tcp, dis->transport_len, dis->ip, dis->ip6);
					if (rawpacket_queue(&ctrack->delayed, &dst, desync_fwmark, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload))
					{
						DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
					}
					else
					{
						DLOG_ERR("rawpacket_queue failed !\n");
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

			if (dp->desync_skip_nosni && !bHaveHost)
			{
				DLOG("not applying tampering to TLS ClientHello without hostname in the SNI\n");
				reasm_orig_cancel(ctrack);
				return verdict;
			}
		}

		if (ctrack && ctrack->req_seq_finalized)
		{
			uint32_t dseq = ctrack->seq_last - ctrack->req_seq_end;
			// do not react to 32-bit overflowed sequence numbers. allow 16 Mb grace window then cutoff.
			if (dseq>=0x1000000 && !(dseq & 0x80000000)) ctrack->req_seq_abandoned=true;
		}

		if (bHaveHost) DLOG("hostname: %s\n",host);

		bool bDiscoveredL7;
		if (ctrack_replay)
		{
			bDiscoveredL7 = !ctrack_replay->l7proto_discovered && ctrack_replay->l7proto!=UNKNOWN;
			ctrack_replay->l7proto_discovered=true;
		}
		else
			bDiscoveredL7 = !ctrack_replay && l7proto!=UNKNOWN;
		if (bDiscoveredL7) DLOG("discovered l7 protocol\n");

		bool bDiscoveredHostname = bHaveHost && !(ctrack_replay && ctrack_replay->hostname);
		if (bDiscoveredHostname)
		{
			DLOG("discovered hostname\n");
			if (ctrack_replay)
			{
				ctrack_replay->hostname=strdup(host);
				if (!ctrack_replay->hostname)
				{
					DLOG_ERR("hostname dup : out of memory");
					reasm_orig_cancel(ctrack);
					return verdict;
				}
			}
		}

		bool bCheckDone=false, bCheckResult=false, bCheckExcluded=false;
		if (bDiscoveredL7 || bDiscoveredHostname)
		{
			struct desync_profile *dp_prev = dp;

			dp = dp_find(&params.desync_profiles, IPPROTO_TCP, (struct sockaddr *)&dst, ctrack_replay ? ctrack_replay->hostname : host, ctrack_replay ? ctrack_replay->l7proto : l7proto, &bCheckDone, &bCheckResult, &bCheckExcluded);
			if (ctrack_replay)
			{
				ctrack_replay->dp = dp;
				ctrack_replay->dp_search_complete = true;
				ctrack_replay->bCheckDone = bCheckDone;
				ctrack_replay->bCheckResult = bCheckResult;
				ctrack_replay->bCheckExcluded = bCheckExcluded;
			}
			if (!dp)
			{
				reasm_orig_cancel(ctrack);
				return verdict;
			}
			if (dp!=dp_prev)
			{
				DLOG("desync profile changed by revealed l7 protocol or hostname !\n");
				// rediscover autottl
				autottl_discover(ctrack_replay,!!dis->ip6);
				// re-evaluate start/cutoff limiters
				if (!replay)
				{
					maybe_cutoff(ctrack, IPPROTO_TCP);
					if (!process_desync_interval(dp, ctrack))
					{
						reasm_orig_cancel(ctrack);
						return verdict;
					}
				}
			}
		}
		else if (ctrack_replay)
		{
			bCheckDone = ctrack_replay->bCheckDone;
			bCheckResult = ctrack_replay->bCheckResult;
			bCheckExcluded = ctrack_replay->bCheckExcluded;
		}

		if (bHaveHost && !PROFILE_HOSTLISTS_EMPTY(dp))
		{
			if (!bCheckDone)
				bCheckResult = HostlistCheck(dp, host, &bCheckExcluded, false);
			if (bCheckResult)
				ctrack_stop_retrans_counter(ctrack_replay);
			else
			{
				if (ctrack_replay)
				{
					ctrack_replay->hostname_ah_check = dp->hostlist_auto && !bCheckExcluded;
					if (!ctrack_replay->hostname_ah_check)
						ctrack_stop_retrans_counter(ctrack_replay);
				}
				DLOG("not applying tampering to this request\n");
				reasm_orig_cancel(ctrack);
				return verdict;
			}
		}

		if (l7proto==UNKNOWN)
		{
			if (!dp->desync_any_proto)
			{
				DLOG("not applying tampering to unknown protocol\n");
				reasm_orig_cancel(ctrack);
				return verdict;
			}
			DLOG("applying tampering to unknown protocol\n");
		}

		ttl_fake = (ctrack_replay && ctrack_replay->autottl) ? ctrack_replay->autottl : (dis->ip6 ? (dp->desync_ttl6 ? dp->desync_ttl6 : ttl_orig) : (dp->desync_ttl ? dp->desync_ttl : ttl_orig));
		if ((l7proto == HTTP) && (dp->hostcase || dp->hostnospace || dp->domcase || dp->methodeol) && HttpFindHost(&phost,dis->data_payload,dis->len_payload))
		{
			if (dp->hostcase)
			{
				DLOG("modifying Host: => %c%c%c%c:\n", dp->hostspell[0], dp->hostspell[1], dp->hostspell[2], dp->hostspell[3]);
				memcpy(phost, dp->hostspell, 4);
				verdict=VERDICT_MODIFY;
			}
			if (dp->domcase)
			{
				DLOG("mixing domain case\n");
				for (p = phost+5; p < (dis->data_payload + dis->len_payload) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
				verdict=VERDICT_MODIFY;
			}
			uint8_t *pua;
			if (dp->hostnospace)
			{
				if ((pua = (uint8_t*)memmem(dis->data_payload, dis->len_payload, "\r\nUser-Agent: ", 14)) &&
					(pua = (uint8_t*)memmem(pua + 1, dis->len_payload - (pua - dis->data_payload) - 1, "\r\n", 2)))
				{
					DLOG("removing space after Host: and adding it to User-Agent:\n");
					if (pua > phost)
					{
						memmove(phost + 5, phost + 6, pua - phost - 6);
						pua[-1]=' ';
					}
					else
					{
						memmove(pua + 1, pua, phost - pua + 5);
						*pua = ' ';
					}
					verdict=VERDICT_MODIFY;
				}
				else
					DLOG("cannot do hostnospace because valid User-Agent: not found\n");
			}
			else if (dp->methodeol)
			{
				if (phost[5]==' ' || phost[5]=='\t')
				{
					DLOG("removing space after Host: and adding '\\n' before method\n");
					memmove(dis->data_payload+1,dis->data_payload,phost-dis->data_payload+5);
					dis->data_payload[0]='\n';
					verdict=VERDICT_MODIFY;
				}
				else
					DLOG("cannot do methodeol because there's no space or tab after Host:\n");
			}
			
		}

		if (dp->desync_mode==DESYNC_NONE)
		{
			reasm_orig_cancel(ctrack);
			return verdict;
		}

		if (params.debug)
		{
			char s1[48],s2[48];
			ntop46_port((struct sockaddr *)&src, s1, sizeof(s1));
			ntop46_port((struct sockaddr *)&dst, s2, sizeof(s2));
			DLOG("dpi desync src=%s dst=%s\n",s1,s2);
		}

		switch(l7proto)
		{
			case HTTP:
				fake = dp->fake_http;
				fake_size = dp->fake_http_size;
				break;
			case TLS:
				fake = runtime_tls_mod(dp,fake_mod,rdata_payload,rlen_payload) ? fake_mod : dp->fake_tls;
				fake_size = dp->fake_tls_size;
				break;
			default:
				fake = dp->fake_unknown;
				fake_size = dp->fake_unknown_size;
				break;
		}
		if (dp->desync_mode==DESYNC_MULTISPLIT || dp->desync_mode==DESYNC_MULTIDISORDER || dp->desync_mode2==DESYNC_MULTISPLIT || dp->desync_mode2==DESYNC_MULTIDISORDER)
		{
			split_pos=0;
			ResolveMultiPos(rdata_payload, rlen_payload, l7proto, dp->splits, dp->split_count, multisplit_pos, &multisplit_count);
			if (params.debug)
			{
				if (multisplit_count)
				{
					DLOG("multisplit pos: ");
					for (i=0;i<multisplit_count;i++) DLOG("%zu ",multisplit_pos[i]);
					DLOG("\n");
				}
				else
					DLOG("all multisplit pos are outside of this packet\n");
			}
			if (multisplit_count)
			{
				int j;
				for (i=j=0;i<multisplit_count;i++)
				{
					multisplit_pos[j]=pos_normalize(multisplit_pos[i],reasm_offset,dis->len_payload);
					if (multisplit_pos[j]) j++;
				}
				multisplit_count=j;
				if (params.debug)
				{
					if (multisplit_count)
					{
						DLOG("normalized multisplit pos: ");
						for (i=0;i<multisplit_count;i++) DLOG("%zu ",multisplit_pos[i]);
						DLOG("\n");
					}
					else
						DLOG("all multisplit pos are outside of this packet\n");
				}
			}
		}
		else if (dp->desync_mode==DESYNC_FAKEDSPLIT || dp->desync_mode==DESYNC_FAKEDDISORDER || dp->desync_mode2==DESYNC_FAKEDSPLIT || dp->desync_mode2==DESYNC_FAKEDDISORDER)
		{
			multisplit_count=0;
			// first look for non-abs split
			for(i=0,split_pos=0;i<dp->split_count && !split_pos;i++)
				if (dp->splits[i].marker!=PM_ABS)
					split_pos = ResolvePos(rdata_payload, rlen_payload, l7proto, dp->splits+i);
			// second look for abs split
			if (!split_pos)
				for(i=0,split_pos=0;i<dp->split_count && !split_pos;i++)
					if (dp->splits[i].marker==PM_ABS)
						split_pos = ResolvePos(rdata_payload, rlen_payload, l7proto, dp->splits+i);
			if (!split_pos) split_pos = 1;
			DLOG("regular split pos: %zu\n",split_pos);
			if (!split_pos || split_pos>rlen_payload) split_pos=1;
			split_pos=pos_normalize(split_pos,reasm_offset,dis->len_payload);
			if (split_pos)
				DLOG("normalized regular split pos : %zu\n",split_pos);
			else
				DLOG("regular split pos is outside of this packet\n");
		}
		else
		{
			multisplit_count=0;
			split_pos = 0;
		}
		if (dp->desync_mode==DESYNC_FAKEDSPLIT || dp->desync_mode==DESYNC_MULTISPLIT || dp->desync_mode2==DESYNC_FAKEDSPLIT || dp->desync_mode2==DESYNC_MULTISPLIT)
		{
			// split seqovl only uses absolute positive values
			seqovl_pos = (dp->seqovl.marker==PM_ABS && dp->seqovl.pos>0) ? dp->seqovl.pos : 0;
			if (seqovl_pos)	DLOG("seqovl : %zu\n",seqovl_pos);
		}
		else if (dp->desync_mode==DESYNC_FAKEDDISORDER || dp->desync_mode==DESYNC_MULTIDISORDER || dp->desync_mode2==DESYNC_FAKEDDISORDER || dp->desync_mode2==DESYNC_MULTIDISORDER)
		{
			seqovl_pos = ResolvePos(rdata_payload, rlen_payload, l7proto, &dp->seqovl);
			seqovl_pos = pos_normalize(seqovl_pos,reasm_offset,dis->len_payload);
			if (seqovl_pos)	DLOG("normalized seqovl : %zu\n",seqovl_pos);
		}
		else
			seqovl_pos = 0;

		// we do not need reasm buffer anymore
		reasm_orig_cancel(ctrack);
		rdata_payload=NULL;

		uint32_t fooling_orig = FOOL_NONE;
		bool bFake = false;
		pkt1_len = sizeof(pkt1);
		switch(dp->desync_mode)
		{
			case DESYNC_FAKE_KNOWN:
				if (reasm_offset) break;
				if (l7proto==UNKNOWN)
				{
					DLOG("not applying fake because of unknown protocol\n");
					break;
				}
			case DESYNC_FAKE:
				if (reasm_offset) break;
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
					ttl_fake,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
					dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
					fake, fake_size, pkt1, &pkt1_len))
				{
					return verdict;
				}
				DLOG("sending fake : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n");
				bFake = true;
				break;
			case DESYNC_RST:
			case DESYNC_RSTACK:
				if (reasm_offset) break;
				if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, TH_RST | (dp->desync_mode==DESYNC_RSTACK ? TH_ACK:0), dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
					ttl_fake,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
					dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
					NULL, 0, pkt1, &pkt1_len))
				{
					return verdict;
				}
				DLOG("sending fake RST/RSTACK\n");
				bFake = true;
				break;
			case DESYNC_HOPBYHOP:
			case DESYNC_DESTOPT:
			case DESYNC_IPFRAG1:
				fooling_orig = (dp->desync_mode==DESYNC_HOPBYHOP) ? FOOL_HOPBYHOP : (dp->desync_mode==DESYNC_DESTOPT) ? FOOL_DESTOPT : FOOL_IPFRAG1;
				if (dis->ip6 && (dp->desync_mode2==DESYNC_NONE || !desync_valid_second_stage_tcp(dp->desync_mode2) ||
					(!split_pos && (dp->desync_mode2==DESYNC_FAKEDSPLIT || dp->desync_mode2==DESYNC_FAKEDDISORDER)) ||
					(!multisplit_count && (dp->desync_mode2==DESYNC_MULTISPLIT || dp->desync_mode2==DESYNC_MULTIDISORDER))))
				{
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
						ttl_orig,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
						fooling_orig,0,0,
						dis->data_payload, dis->len_payload, pkt1, &pkt1_len))
					{
						return verdict;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					// this mode is final, no other options available
					return VERDICT_DROP;
				}
			default:
				pkt1_len=0;
				break;
		}

		if (bFake)
		{
			if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
				return verdict;
		}

		enum dpi_desync_mode desync_mode = dp->desync_mode2==DESYNC_NONE ? dp->desync_mode : dp->desync_mode2;
		switch(desync_mode)
		{
			case DESYNC_MULTISPLIT:
				if (multisplit_count)
				{
					uint8_t ovlseg[DPI_DESYNC_MAX_FAKE_LEN+100], *seg;
					size_t seg_len,from,to;
					unsigned int seqovl;

					ip_id = IP4_IP_ID_FIX(dis->ip);

					for (i=0,from=0 ; i<=multisplit_count ; i++)
					{
						to = i==multisplit_count ? dis->len_payload : multisplit_pos[i];

						// do seqovl only to the first packet
						// otherwise it's prone to race condition on server side
						// what happens first : server pushes socket buffer to process or another packet with seqovl arrives
						seqovl = (i==0 && reasm_offset==0) ? seqovl_pos : 0;
#ifdef __linux__
// only linux return error if MTU is exceeded
						for(;;seqovl=0)
						{
#endif
							if (seqovl)
							{
								seg_len = to-from+seqovl;
								if (seg_len>sizeof(ovlseg))
								{
									DLOG("seqovl is too large");
									return verdict;
								}
								fill_pattern(ovlseg,seqovl,dp->seqovl_pattern,sizeof(dp->seqovl_pattern));
								memcpy(ovlseg+seqovl,dis->data_payload+from,to-from);
								seg = ovlseg;
							}
							else
							{
								seqovl = 0;
								seg = dis->data_payload+from;
								seg_len = to-from;
							}

							pkt1_len = sizeof(pkt1);
							if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig,
									net32_add(dis->tcp->th_seq,from-seqovl), dis->tcp->th_ack,
									dis->tcp->th_win, scale_factor, timestamps,ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
									fooling_orig,0,0,
									seg, seg_len, pkt1, &pkt1_len))
								return verdict;
							ip_id=IP4_IP_ID_NEXT(ip_id);
							DLOG("sending multisplit part %d %zu-%zu len=%zu seqovl=%u : ",i+1,from,to-1,to-from,seqovl);
							hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n");
							if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							{
#ifdef __linux__
								if (errno==EMSGSIZE && seqovl)
								{
									DLOG("MTU exceeded. cancelling seqovl.\n");
									continue;
								}
#endif
								return verdict;
							}
#ifdef __linux__
							break;
						}
#endif

						from = to;
					}
					return VERDICT_DROP;
				}
				break;
			case DESYNC_MULTIDISORDER:
				if (multisplit_count)
				{
					uint8_t ovlseg[DPI_DESYNC_MAX_FAKE_LEN+100], *seg;
					size_t seg_len,from,to;
					unsigned int seqovl;

					ip_id = IP4_IP_ID_FIX(dis->ip);

					for (i=multisplit_count-1,to=dis->len_payload ; i>=-1 ; i--)
					{
						from = i>=0 ? multisplit_pos[i] : 0;

						seg = dis->data_payload+from;
						seg_len = to-from;
						seqovl = 0;
						// do seqovl only to the second packet
						// otherwise sequence overlap becomes problematic. overlap algorithm is not too obvious.
						// real observations revealed that server can receive overlap junk instead of real data
						if (i==0)
						{
							if (seqovl_pos>=from)
								DLOG("seqovl>=split_pos (%zu>=%zu). cancelling seqovl for part %d.\n",seqovl,from,i+2);
							else
							{
								seqovl = seqovl_pos;
								seg_len = to-from+seqovl;
								if (seg_len>sizeof(ovlseg))
								{
									DLOG("seqovl is too large");
									return verdict;
								}
								fill_pattern(ovlseg,seqovl,dp->seqovl_pattern,sizeof(dp->seqovl_pattern));
								memcpy(ovlseg+seqovl,dis->data_payload+from,to-from);
								seg = ovlseg;
							}
						}

						pkt1_len = sizeof(pkt1);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig,
								net32_add(dis->tcp->th_seq,from-seqovl), dis->tcp->th_ack,
								dis->tcp->th_win, scale_factor, timestamps,ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
								fooling_orig,0,0,
								seg, seg_len, pkt1, &pkt1_len))
							return verdict;
						ip_id=IP4_IP_ID_PREV(ip_id);
						DLOG("sending multisplit part %d %zu-%zu len=%zu seqovl=%u : ",i+2,from,to-1,to-from,seqovl);
						hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n");
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
							return verdict;

						to = from;
					}
					return VERDICT_DROP;
				}
				break;
			case DESYNC_FAKEDDISORDER:
				if (split_pos)
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100], fakeseg2[DPI_DESYNC_MAX_FAKE_LEN+100], pat[DPI_DESYNC_MAX_FAKE_LEN], *seg;
					size_t seg_len,fakeseg2_len;
					unsigned int seqovl;

					if (dis->len_payload > sizeof(pat))
					{
						DLOG("packet is too large\n");
						return verdict;
					}
					fill_pattern(pat,dis->len_payload,dp->fsplit_pattern,sizeof(dp->fsplit_pattern));

					ip_id = IP4_IP_ID_FIX(dis->ip);

					if (seqovl_pos>=split_pos)
					{
						DLOG("seqovl>=split_pos (%zu>=%zu). cancelling seqovl.\n",seqovl_pos,split_pos);
						seqovl = 0;
					}
					else
						seqovl = seqovl_pos;

					if (seqovl)
					{
						seg_len = dis->len_payload-split_pos+seqovl;
						if (seg_len>sizeof(fakeseg))
						{
							DLOG("seqovl is too large\n");
							return verdict;
						}
						fill_pattern(fakeseg,seqovl,dp->seqovl_pattern,sizeof(dp->seqovl_pattern));
						memcpy(fakeseg+seqovl,dis->data_payload+split_pos,dis->len_payload-split_pos);
						seg = fakeseg;
					}
					else
					{
						seg = dis->data_payload+split_pos;
						seg_len = dis->len_payload-split_pos;
					}

					fakeseg2_len = sizeof(fakeseg2);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(dis->tcp->th_seq,split_pos), dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_fake,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							pat+split_pos, dis->len_payload-split_pos, fakeseg2, &fakeseg2_len))
						return verdict;
					ip_id=IP4_IP_ID_PREV(ip_id);
					DLOG("sending fake(1) 2nd out-of-order tcp segment %zu-%zu len=%zu : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos);
					hexdump_limited_dlog(pat+split_pos,dis->len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg2, fakeseg2_len))
						return verdict;

					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(dis->tcp->th_seq , split_pos - seqovl), dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							fooling_orig,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							seg, seg_len, pkt1, &pkt1_len))
						return verdict;
					ip_id=IP4_IP_ID_PREV(ip_id);
					DLOG("sending 2nd out-of-order tcp segment %zu-%zu len=%zu seqovl=%u : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos, seqovl);
					hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					if (dis->ip) ((struct ip*)fakeseg2)->ip_id = ip_id;
					ip_id=IP4_IP_ID_PREV(ip_id);

					DLOG("sending fake(2) 2nd out-of-order tcp segment %zu-%zu len=%zu : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos);
					hexdump_limited_dlog(pat+split_pos,dis->len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg2, fakeseg2_len))
						return verdict;

					seg_len = sizeof(fakeseg);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_fake,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							pat, split_pos, fakeseg, &seg_len))
						return verdict;
					ip_id=IP4_IP_ID_PREV(ip_id);
					DLOG("sending fake(1) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos);
					hexdump_limited_dlog(pat,split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, seg_len))
						return verdict;

					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							fooling_orig,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							dis->data_payload, split_pos, pkt1, &pkt1_len))
						return verdict;
					ip_id=IP4_IP_ID_PREV(ip_id);
					DLOG("sending 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos);
					hexdump_limited_dlog(dis->data_payload,split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					if (dis->ip) ((struct ip*)fakeseg)->ip_id = ip_id;
					DLOG("sending fake(2) 1st out-of-order tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos);
					hexdump_limited_dlog(pat,split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, seg_len))
						return verdict;

					return VERDICT_DROP;
				}
				break;
			case DESYNC_FAKEDSPLIT:
				if (split_pos)
				{
					uint8_t fakeseg[DPI_DESYNC_MAX_FAKE_LEN+100],ovlseg[DPI_DESYNC_MAX_FAKE_LEN+100],pat[DPI_DESYNC_MAX_FAKE_LEN], *seg;
					size_t fakeseg_len,seg_len;

					if (dis->len_payload > sizeof(pat))
					{
						DLOG("packet is too large\n");
						return verdict;
					}
					fill_pattern(pat,dis->len_payload,dp->fsplit_pattern,sizeof(dp->fsplit_pattern));

					ip_id = IP4_IP_ID_FIX(dis->ip);

					fakeseg_len = sizeof(fakeseg);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, dis->tcp->th_seq, dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_fake,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							pat, split_pos, fakeseg, &fakeseg_len))
						return verdict;
					ip_id=IP4_IP_ID_NEXT(ip_id);
					DLOG("sending fake(1) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos);
					hexdump_limited_dlog(pat,split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
						return verdict;

					unsigned int seqovl = reasm_offset ? 0 : seqovl_pos;
#ifdef __linux__
// only linux return error if MTU is exceeded
					for(;;seqovl=0)
					{
#endif
						if (seqovl)
						{
							seg_len = split_pos+seqovl;
							if (seg_len>sizeof(ovlseg))
							{
								DLOG("seqovl is too large");
								return verdict;
							}
							fill_pattern(ovlseg,seqovl,dp->seqovl_pattern,sizeof(dp->seqovl_pattern));
							memcpy(ovlseg+seqovl,dis->data_payload,split_pos);
							seg = ovlseg;
						}
						else
						{
							seg = dis->data_payload;
							seg_len = split_pos;
						}

						pkt1_len = sizeof(pkt1);
						if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(dis->tcp->th_seq,-seqovl), dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
								ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
								fooling_orig,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
								seg, seg_len, pkt1, &pkt1_len))
							return verdict;
						ip_id=IP4_IP_ID_NEXT(ip_id);
						DLOG("sending 1st tcp segment 0-%zu len=%zu seqovl=%u : ",split_pos-1, split_pos, seqovl);
						hexdump_limited_dlog(seg,seg_len,PKTDATA_MAXDUMP); DLOG("\n");
						if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						{
#ifdef __linux__
							if (errno==EMSGSIZE && seqovl)
							{
								DLOG("MTU exceeded. cancelling seqovl.\n");
								continue;
							}
#endif
							return verdict;
						}
#ifdef __linux__
						break;
					}
#endif
					if (dis->ip) ((struct ip*)fakeseg)->ip_id = ip_id;
					ip_id=IP4_IP_ID_NEXT(ip_id);
					DLOG("sending fake(2) 1st tcp segment 0-%zu len=%zu : ",split_pos-1, split_pos);
					hexdump_limited_dlog(pat,split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
						return verdict;

					fakeseg_len = sizeof(fakeseg);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(dis->tcp->th_seq,split_pos), dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_fake,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							dp->desync_fooling_mode,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							pat+split_pos, dis->len_payload-split_pos, fakeseg, &fakeseg_len))
						return verdict;
					ip_id=IP4_IP_ID_NEXT(ip_id);
					DLOG("sending fake(1) 2nd tcp segment %zu-%zu len=%zu : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos);
					hexdump_limited_dlog(pat+split_pos,dis->len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
						return verdict;

					pkt1_len = sizeof(pkt1);
					if (!prepare_tcp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, flags_orig, net32_add(dis->tcp->th_seq,split_pos), dis->tcp->th_ack, dis->tcp->th_win, scale_factor, timestamps,
							ttl_orig,IP4_TOS(dis->ip),ip_id,IP6_FLOW(dis->ip6),
							fooling_orig,dp->desync_badseq_increment,dp->desync_badseq_ack_increment,
							dis->data_payload+split_pos, dis->len_payload-split_pos, pkt1, &pkt1_len))
						return verdict;
					ip_id=IP4_IP_ID_NEXT(ip_id);
					DLOG("sending 2nd tcp segment %zu-%zu len=%zu : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos);
					hexdump_limited_dlog(dis->data_payload+split_pos,dis->len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					if (dis->ip) ((struct ip*)fakeseg)->ip_id = ip_id;

					DLOG("sending fake(2) 2nd tcp segment %zu-%zu len=%zu : ",split_pos,dis->len_payload-1, dis->len_payload-split_pos);
					hexdump_limited_dlog(pat+split_pos,dis->len_payload-split_pos,PKTDATA_MAXDUMP); DLOG("\n");
					if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , fakeseg, fakeseg_len))
						return verdict;

					return VERDICT_DROP;
				}
				break;
			case DESYNC_IPFRAG2:
				if (!reasm_offset)
				{
					verdict_tcp_csum_fix(verdict, dis->tcp, dis->transport_len, dis->ip, dis->ip6);

					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;

					ip_id = IP4_IP_ID_FIX(dis->ip);
					uint32_t ident = dis->ip ? ip_id ? ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);
					size_t ipfrag_pos = (dp->desync_ipfrag_pos_tcp && dp->desync_ipfrag_pos_tcp<dis->transport_len) ? dp->desync_ipfrag_pos_tcp : 24;

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (dis->ip6 && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, dis->data_pkt, dis->len_pkt, pkt3, &pkt_orig_len))
							return verdict;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = dis->data_pkt;
						pkt_orig_len = dis->len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return verdict;

					DLOG("sending 1st ip fragment 0-%zu ip_payload_len=%zu : ", ipfrag_pos-1, ipfrag_pos);
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					DLOG("sending 2nd ip fragment %zu-%zu ip_payload_len=%zu : ", ipfrag_pos, dis->transport_len-1, dis->transport_len-ipfrag_pos);
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return verdict;

					return VERDICT_DROP;
				}
			default:
				break;
		}

		if (bFake)
		{
			// if we are here original message was not sent in any form
			// allowing system to pass the message to queue can result in unpredicted send order
			DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", dis->len_pkt, dis->len_payload);
			verdict_tcp_csum_fix(verdict, dis->tcp, dis->transport_len, dis->ip, dis->ip6);
			if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , dis->data_pkt, dis->len_pkt))
				return verdict;
			return VERDICT_DROP;
		}
	}

	return verdict;
}

// return : true - should continue, false - should stop with verdict
static bool quic_reasm_cancel(t_ctrack *ctrack, const char *reason)
{
	reasm_orig_cancel(ctrack);
	if (ctrack && ctrack->dp && ctrack->dp->desync_any_proto)
	{
		DLOG("%s. applying tampering because desync_any_proto is set\n",reason);
		return true;
	}
	else
	{
		DLOG("%s. not applying tampering because desync_any_proto is not set\n",reason);
		return false;
	}
}

static uint8_t dpi_desync_udp_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, struct dissect *dis)
{
	uint8_t verdict=VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	// no need to desync middle packets in reasm session
	if (reasm_offset) return verdict;

	struct desync_profile *dp = NULL;

	t_ctrack *ctrack=NULL, *ctrack_replay=NULL;
	bool bReverse=false;

	struct sockaddr_storage src, dst;
	uint8_t pkt1[DPI_DESYNC_MAX_FAKE_LEN+100], pkt2[DPI_DESYNC_MAX_FAKE_LEN+100];
	size_t pkt1_len, pkt2_len;
	uint8_t ttl_orig,ttl_fake;
	t_l7proto l7proto = UNKNOWN;

	ttl_orig = dis->ip ? dis->ip->ip_ttl : dis->ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
	extract_endpoints(dis->ip, dis->ip6, NULL, dis->udp, &src, &dst);

	if (replay)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, dis->ip, dis->ip6, NULL, dis->udp, &ctrack_replay, &bReverse) || bReverse)
			return verdict;

		dp = ctrack_replay->dp;
		if (dp)
			DLOG("using cached desync profile %d\n",dp->n);
		else if (!ctrack_replay->dp_search_complete)
		{
			dp = ctrack_replay->dp = dp_find(&params.desync_profiles, IPPROTO_UDP, (struct sockaddr *)&dst, ctrack_replay->hostname, ctrack_replay->l7proto, NULL, NULL, NULL);
			ctrack_replay->dp_search_complete = true;
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		ConntrackPoolPurge(&params.conntrack);
		if (ConntrackPoolFeed(&params.conntrack, dis->ip, dis->ip6, NULL, dis->udp, dis->len_payload, &ctrack, &bReverse))
		{
			dp = ctrack->dp;
			ctrack_replay = ctrack;
		}
		if (dp)
			DLOG("using cached desync profile %d\n",dp->n);
		else if (!ctrack || !ctrack->dp_search_complete)
		{
			dp = dp_find(&params.desync_profiles, IPPROTO_UDP, (struct sockaddr *)&dst, ctrack ? ctrack->hostname : NULL, ctrack ? ctrack->l7proto : UNKNOWN, NULL, NULL, NULL);
			if (ctrack)
			{
				ctrack->dp = dp;
				ctrack->dp_search_complete = true;
			}
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
		maybe_cutoff(ctrack, IPPROTO_UDP);

		HostFailPoolPurgeRateLimited(&dp->hostlist_auto_fail_counters);
		//ConntrackPoolDump(&params.conntrack);
	}

	if (bReverse && ctrack)
	{
		if (!ctrack->incoming_ttl)
		{
			DLOG("incoming TTL %u\n",ttl_orig);
			ctrack->incoming_ttl = ttl_orig;
		}
		if (!ctrack->autottl) autottl_discover(ctrack,!!dis->ip6);
		return verdict; // nothing to do. do not waste cpu
	}

	// start and cutoff limiters
	if (!replay && !process_desync_interval(dp, ctrack)) return verdict;

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;

	if (dis->len_payload)
	{
		const uint8_t *fake;
		size_t fake_size;
		char host[256];
		bool bHaveHost=false;
		uint16_t ip_id;

		if (IsQUICInitial(dis->data_payload,dis->len_payload))
		{
			DLOG("packet contains QUIC initial\n");
			l7proto = QUIC;
			if (ctrack && ctrack->l7proto==UNKNOWN) ctrack->l7proto = l7proto;

			uint8_t clean[16384], *pclean;
			size_t clean_len;

			if (replay)
			{
				clean_len = ctrack_replay->reasm_orig.size_present;
				pclean = ctrack_replay->reasm_orig.packet;
			}
			else
			{
				clean_len = sizeof(clean);
				pclean = QUICDecryptInitial(dis->data_payload,dis->len_payload,clean,&clean_len) ? clean : NULL;
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

					DLOG(bIsHello ? bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n" : "packet does not contain TLS ClientHello\n");

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
							verdict_udp_csum_fix(verdict, dis->udp, dis->transport_len, dis->ip, dis->ip6);
							if (rawpacket_queue(&ctrack->delayed, &dst, desync_fwmark, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload))
							{
								DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
							}
							else
							{
								DLOG_ERR("rawpacket_queue failed !\n");
								reasm_orig_cancel(ctrack);
								return verdict;
							}
							if (bReqFull)
							{
								replay_queue(&ctrack->delayed);
								reasm_orig_fin(ctrack);
							}
							return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
						}
					}
			
					if (bIsHello)
					{
						bHaveHost = TLSHelloExtractHostFromHandshake(defrag + hello_offset, hello_len, host, sizeof(host), TLS_PARTIALS_ENABLE);
						if (!bHaveHost && dp->desync_skip_nosni)
						{
							reasm_orig_cancel(ctrack);
							DLOG("not applying tampering to QUIC ClientHello without hostname in the SNI\n");
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
		}
		else // not QUIC initial
		{
			// received payload without host. it means we are out of the request retransmission phase. stop counter
			ctrack_stop_retrans_counter(ctrack);
			
			reasm_orig_cancel(ctrack);

			if (IsWireguardHandshakeInitiation(dis->data_payload,dis->len_payload))
			{
				DLOG("packet contains wireguard handshake initiation\n");
				l7proto = WIREGUARD;
				if (ctrack && ctrack->l7proto==UNKNOWN) ctrack->l7proto = l7proto;
			}
			else if (IsDhtD1(dis->data_payload,dis->len_payload))
			{
				DLOG("packet contains DHT d1...e\n");
				l7proto = DHT;
				if (ctrack && ctrack->l7proto==UNKNOWN) ctrack->l7proto = l7proto;
			}
			else
			{
				if (!dp->desync_any_proto)
				{
					DLOG("not applying tampering to unknown protocol\n");
					return verdict;
				}
				DLOG("applying tampering to unknown protocol\n");
			}
		}

		if (bHaveHost) DLOG("hostname: %s\n",host);

		bool bDiscoveredL7;
		if (ctrack_replay)
		{
			bDiscoveredL7 = !ctrack_replay->l7proto_discovered && ctrack_replay->l7proto!=UNKNOWN;
			ctrack_replay->l7proto_discovered=true;
		}
		else
			bDiscoveredL7 = !ctrack_replay && l7proto!=UNKNOWN;
		if (bDiscoveredL7) DLOG("discovered l7 protocol\n");

		bool bDiscoveredHostname = bHaveHost && !(ctrack_replay && ctrack_replay->hostname);
		if (bDiscoveredHostname)
		{
			DLOG("discovered hostname\n");
			if (ctrack_replay)
			{
				ctrack_replay->hostname=strdup(host);
				if (!ctrack_replay->hostname)
				{
					DLOG_ERR("hostname dup : out of memory");
					return verdict;
				}
			}
		}

		bool bCheckDone=false, bCheckResult=false, bCheckExcluded=false;
		if (bDiscoveredL7 || bDiscoveredHostname)
		{
			struct desync_profile *dp_prev = dp;

			dp = dp_find(&params.desync_profiles, IPPROTO_UDP, (struct sockaddr *)&dst, ctrack_replay ? ctrack_replay->hostname : host, ctrack_replay ? ctrack_replay->l7proto : l7proto, &bCheckDone, &bCheckResult, &bCheckExcluded);
			if (ctrack_replay)
			{
				ctrack_replay->dp = dp;
				ctrack_replay->dp_search_complete = true;
				ctrack_replay->bCheckDone = bCheckDone;
				ctrack_replay->bCheckResult = bCheckResult;
				ctrack_replay->bCheckExcluded = bCheckExcluded;
			}
			if (!dp)
			{
				reasm_orig_cancel(ctrack);
				return verdict;
			}
			if (dp!=dp_prev)
			{
				DLOG("desync profile changed by revealed l7 protocol or hostname !\n");
				// rediscover autottl
				autottl_discover(ctrack_replay,!!dis->ip6);
				// re-evaluate start/cutoff limiters
				if (!replay)
				{
					maybe_cutoff(ctrack, IPPROTO_UDP);
					if (!process_desync_interval(dp, ctrack)) return verdict;
				}
			}
		}
		else if (ctrack_replay)
		{
			bCheckDone = ctrack_replay->bCheckDone;
			bCheckResult = ctrack_replay->bCheckResult;
			bCheckExcluded = ctrack_replay->bCheckExcluded;
		}

		if (bHaveHost && !PROFILE_HOSTLISTS_EMPTY(dp))
		{
			if (!bCheckDone)
				bCheckResult = HostlistCheck(dp, host, &bCheckExcluded, false);
			if (bCheckResult)
				ctrack_stop_retrans_counter(ctrack_replay);
			else
			{
				if (ctrack_replay)
				{
					ctrack_replay->hostname_ah_check = dp->hostlist_auto && !bCheckExcluded;
					if (ctrack_replay->hostname_ah_check)
					{
						// first request is not retrans
						if (!bDiscoveredHostname)
							process_retrans_fail(ctrack_replay, IPPROTO_UDP, (struct sockaddr*)&src);
					}
				}
				DLOG("not applying tampering to this request\n");
				return verdict;
			}
		}

		// desync profile may have changed after hostname was revealed
		switch(l7proto)
		{
			case QUIC:
				fake = dp->fake_quic;
				fake_size = dp->fake_quic_size;
				break;
			case WIREGUARD:
				fake = dp->fake_wg;
				fake_size = dp->fake_wg_size;
				break;
			case DHT:
				fake = dp->fake_dht;
				fake_size = dp->fake_dht_size;
				break;
			default:
				fake = dp->fake_unknown_udp;
				fake_size = dp->fake_unknown_udp_size;
				break;
		}

		ttl_fake = (ctrack_replay && ctrack_replay->autottl) ? ctrack_replay->autottl : (dis->ip6 ? (dp->desync_ttl6 ? dp->desync_ttl6 : ttl_orig) : (dp->desync_ttl ? dp->desync_ttl : ttl_orig));

		uint32_t fooling_orig = FOOL_NONE;

		if (params.debug)
		{
			char s1[48],s2[48];
			ntop46_port((struct sockaddr *)&src, s1, sizeof(s1));
			ntop46_port((struct sockaddr *)&dst, s2, sizeof(s2));
			DLOG("dpi desync src=%s dst=%s\n",s1,s2);
		}

		bool bFake = false;
		pkt1_len = sizeof(pkt1);
		switch(dp->desync_mode)
		{
			case DESYNC_FAKE_KNOWN:
				if (l7proto==UNKNOWN)
				{
					DLOG("not applying fake because of unknown protocol\n");
					break;
				}
			case DESYNC_FAKE:
				if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_fake, IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6), dp->desync_fooling_mode, NULL, 0, 0, fake, fake_size, pkt1, &pkt1_len))
					return verdict;
				DLOG("sending fake : ");
				hexdump_limited_dlog(fake,fake_size,PKTDATA_MAXDUMP); DLOG("\n");
				if (!rawsend_rep(dp->desync_repeats,(struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return verdict;
				bFake = true;
				break;
			case DESYNC_HOPBYHOP:
			case DESYNC_DESTOPT:
			case DESYNC_IPFRAG1:
				fooling_orig = (dp->desync_mode==DESYNC_HOPBYHOP) ? FOOL_HOPBYHOP : (dp->desync_mode==DESYNC_DESTOPT) ? FOOL_DESTOPT : FOOL_IPFRAG1;
				if (dis->ip6 && (dp->desync_mode2==DESYNC_NONE || !desync_valid_second_stage_udp(dp->desync_mode2)))
				{
					if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst,
						ttl_orig,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6),
						fooling_orig,NULL,0,0,
						dis->data_payload, dis->len_payload, pkt1, &pkt1_len))
					{
						return verdict;
					}
					DLOG("resending original packet with extension header\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					// this mode is final, no other options available
					return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
				}
				break;
			default:
				pkt1_len=0;
				break;
		}

		enum dpi_desync_mode desync_mode = dp->desync_mode2==DESYNC_NONE ? dp->desync_mode : dp->desync_mode2;
		switch(desync_mode)
		{
			case DESYNC_UDPLEN:
				pkt1_len = sizeof(pkt1);
				if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_orig,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6), fooling_orig, dp->udplen_pattern, sizeof(dp->udplen_pattern), dp->udplen_increment, dis->data_payload, dis->len_payload, pkt1, &pkt1_len))
				{
					DLOG("could not construct packet with modified length. too large ?\n");
					break;
				}
				DLOG("resending original packet with increased by %d length\n", dp->udplen_increment);
				if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
					return verdict;
				return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
			case DESYNC_TAMPER:
				if (IsDhtD1(dis->data_payload,dis->len_payload))
				{
					size_t szbuf,szcopy;
					memcpy(pkt2,"d2:001:x",8);
					pkt2_len=8;
					szbuf=sizeof(pkt2)-pkt2_len;
					szcopy=dis->len_payload-1;
					if (szcopy>szbuf)
					{
						DLOG("packet is too long to tamper");
						break;
					}
					memcpy(pkt2+pkt2_len,dis->data_payload+1,szcopy);
					pkt2_len+=szcopy;
					pkt1_len = sizeof(pkt1);
					if (!prepare_udp_segment((struct sockaddr *)&src, (struct sockaddr *)&dst, ttl_orig,IP4_TOS(dis->ip),IP4_IP_ID_FIX(dis->ip),IP6_FLOW(dis->ip6), fooling_orig, NULL, 0 , 0, pkt2, pkt2_len, pkt1, &pkt1_len))
					{
						DLOG("could not construct packet with modified length. too large ?\n");
						break;
					}
					DLOG("resending tampered DHT\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;
					return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
				}
				else
				{
					DLOG("payload is not tamperable\n");
					break;
				}
			case DESYNC_IPFRAG2:
				{
					verdict_udp_csum_fix(verdict, dis->udp, dis->transport_len, dis->ip, dis->ip6);
				
					uint8_t pkt3[DPI_DESYNC_MAX_FAKE_LEN+100], *pkt_orig;
					size_t pkt_orig_len;
					
					// freebsd do not set ip.id
					ip_id = IP4_IP_ID_FIX(dis->ip);
					uint32_t ident = dis->ip ? ip_id ? ip_id : htons(1+random()%0xFFFF) : htonl(1+random()%0xFFFFFFFF);
					size_t ipfrag_pos = (dp->desync_ipfrag_pos_udp && dp->desync_ipfrag_pos_udp<dis->transport_len) ? dp->desync_ipfrag_pos_udp : sizeof(struct udphdr);

					pkt1_len = sizeof(pkt1);
					pkt2_len = sizeof(pkt2);

					if (dis->ip6 && (fooling_orig==FOOL_HOPBYHOP || fooling_orig==FOOL_DESTOPT))
					{
						pkt_orig_len = sizeof(pkt3);
						if (!ip6_insert_simple_hdr(fooling_orig==FOOL_HOPBYHOP ? IPPROTO_HOPOPTS : IPPROTO_DSTOPTS, dis->data_pkt, dis->len_pkt, pkt3, &pkt_orig_len))
							return verdict;
						pkt_orig = pkt3;
					}
					else
					{
						pkt_orig = dis->data_pkt;
						pkt_orig_len = dis->len_pkt;
					}

					if (!ip_frag(pkt_orig, pkt_orig_len, ipfrag_pos, ident, pkt1, &pkt1_len, pkt2, &pkt2_len))
						return verdict;

					DLOG("sending 1st ip fragment 0-%zu ip_payload_len=%zu : ", ipfrag_pos-1, ipfrag_pos);
					hexdump_limited_dlog(pkt1,pkt1_len,IP_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt1, pkt1_len))
						return verdict;

					DLOG("sending 2nd ip fragment %zu-%zu ip_payload_len=%zu : ", ipfrag_pos, dis->transport_len-1, dis->transport_len-ipfrag_pos);
					hexdump_limited_dlog(pkt2,pkt2_len,IP_MAXDUMP); DLOG("\n");
					if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , pkt2, pkt2_len))
						return verdict;

					return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
				}
			default:
				break;
		}

		if (bFake)
		{
			// if we are here original message was not sent in any form
			// allowing system to pass the message to queue can result in unpredicted send order
			DLOG("reinjecting original packet. len=%zu len_payload=%zu\n", dis->len_pkt, dis->len_payload);
			verdict_udp_csum_fix(verdict, dis->udp, dis->transport_len, dis->ip, dis->ip6);
			if (!rawsend((struct sockaddr *)&dst, desync_fwmark, ifout , dis->data_pkt, dis->len_pkt))
				return verdict;
			return ct_new_postnat_fix_udp(ctrack, dis->ip, dis->ip6, dis->udp, &dis->len_pkt);
		}
	}

	return verdict;
}


static void packet_debug(bool replay, const struct dissect *dis)
{
	if (params.debug)
	{
		if (replay) DLOG("REPLAY ");
		if (dis->ip)
		{
			char s[66];
			str_ip(s,sizeof(s),dis->ip);
			DLOG("IP4: %s",s);
		}
		else if (dis->ip6)
		{
			char s[128];
			str_ip6hdr(s,sizeof(s),dis->ip6, dis->proto);
			DLOG("IP6: %s",s);
		}
		if (dis->tcp)
		{
			char s[80];
			str_tcphdr(s,sizeof(s),dis->tcp);
			DLOG(" %s\n",s);
			if (dis->len_payload) { DLOG("TCP: len=%zu : ",dis->len_payload); hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP); DLOG("\n"); }

		}
		else if (dis->udp)
		{
			char s[30];
			str_udphdr(s,sizeof(s),dis->udp);
			DLOG(" %s\n",s);
			if (dis->len_payload) { DLOG("UDP: len=%zu : ",dis->len_payload); hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP); DLOG("\n"); }
		}
		else
			DLOG("\n");
	}
}


static uint8_t dpi_desync_packet_play(bool replay, size_t reasm_offset, uint32_t fwmark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt)
{
	struct dissect dis;
	uint8_t verdict = VERDICT_PASS;
	
	proto_dissect_l3l4(data_pkt,*len_pkt,&dis);
	if (!!dis.ip != !!dis.ip6)
	{
		packet_debug(replay, &dis);
		switch(dis.proto)
		{
			case IPPROTO_TCP:
				if (dis.tcp)
				{
					verdict = dpi_desync_tcp_packet_play(replay, reasm_offset, fwmark, ifout, &dis);
					verdict_tcp_csum_fix(verdict, dis.tcp, dis.transport_len, dis.ip, dis.ip6);
				}
				break;
			case IPPROTO_UDP:
				if (dis.udp)
				{
					verdict = dpi_desync_udp_packet_play(replay, reasm_offset, fwmark, ifout, &dis);
					verdict_udp_csum_fix(verdict, dis.udp, dis.transport_len, dis.ip, dis.ip6);
				}
				break;
		}
		*len_pkt = dis.len_pkt;
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
		DLOG("REPLAYING delayed packet #%u offset %zu\n",i,offset);
		uint8_t verdict = dpi_desync_packet_play(true, offset, rp->fwmark, rp->ifout, rp->packet, &rp->len);
		switch(verdict & VERDICT_MASK)
		{
			case VERDICT_MODIFY:
				DLOG("SENDING delayed packet #%u modified\n", i);
				b &= rawsend_rp(rp);
				break;
			case VERDICT_PASS:
				DLOG("SENDING delayed packet #%u unmodified\n", i);
				b &= rawsend_rp(rp);
				break;
			case VERDICT_DROP:
				DLOG("DROPPING delayed packet #%u\n", i);
				break;
		}
	}
	return b;
}
