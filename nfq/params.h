#pragma once

#include "pools.h"
#include "conntrack.h"
#include "desync.h"
#include "protocol.h"
#include "helpers.h"

#include <sys/param.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/queue.h>
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
#include <wordexp.h>
#endif

#define TLS_PARTIALS_ENABLE	true

#define RAW_SNDBUF	(64*1024)	// in bytes

#define Q_MAXLEN	1024		// in packets

#define BADSEQ_INCREMENT_DEFAULT 	-10000
#define BADSEQ_ACK_INCREMENT_DEFAULT 	-66000

#define IPFRAG_UDP_DEFAULT 8
#define IPFRAG_TCP_DEFAULT 32

#define UDPLEN_INCREMENT_DEFAULT 	2

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT	3
#define	HOSTLIST_AUTO_FAIL_TIME_DEFAULT 	60
#define	HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT	3

#define MAX_SPLITS	64

#define FAKE_TLS_MOD_SAVE_MASK		0x0F
#define FAKE_TLS_MOD_SET		0x01
#define FAKE_TLS_MOD_CUSTOM_FAKE	0x02
#define FAKE_TLS_MOD_RND		0x10
#define FAKE_TLS_MOD_DUP_SID		0x20
#define FAKE_TLS_MOD_RND_SNI		0x40
#define FAKE_TLS_MOD_PADENCAP		0x80

#define FAKE_MAX_TCP	1460
#define FAKE_MAX_UDP	1472

enum log_target { LOG_TARGET_CONSOLE=0, LOG_TARGET_FILE, LOG_TARGET_SYSLOG };

struct fake_tls_mod_cache
{
	size_t extlen_offset, padlen_offset;
};

struct desync_profile
{
	int n;	// number of the profile

	uint16_t wsize,wssize;
	uint8_t wscale,wsscale;
	char wssize_cutoff_mode; // n - packets, d - data packets, s - relative sequence
	unsigned int wssize_cutoff;

	bool hostcase, hostnospace, domcase, methodeol;
	char hostspell[4];
	enum dpi_desync_mode desync_mode0,desync_mode,desync_mode2;
	bool desync_retrans,desync_skip_nosni,desync_any_proto;
	unsigned int desync_repeats,desync_ipfrag_pos_tcp,desync_ipfrag_pos_udp;

	// multisplit
	struct proto_pos splits[MAX_SPLITS];
	int split_count;
	struct proto_pos seqovl;

	char desync_start_mode, desync_cutoff_mode; // n - packets, d - data packets, s - relative sequence
	unsigned int desync_start, desync_cutoff;
	uint8_t desync_ttl, desync_ttl6;
	autottl desync_autottl, desync_autottl6;
	uint32_t desync_fooling_mode;
	uint32_t desync_badseq_increment, desync_badseq_ack_increment;

	struct blob_collection_head fake_http,fake_tls,fake_unknown,fake_unknown_udp,fake_quic,fake_wg,fake_dht;
	uint8_t fake_syndata[FAKE_MAX_TCP],seqovl_pattern[FAKE_MAX_TCP],fsplit_pattern[FAKE_MAX_TCP],udplen_pattern[FAKE_MAX_UDP];
	size_t fake_syndata_size;

	uint8_t fake_tls_mod;

	int udplen_increment;

	bool filter_ipv4,filter_ipv6;
	struct port_filters_head pf_tcp,pf_udp;
	uint32_t filter_l7;	// L7_PROTO_* bits

	// list of pointers to ipsets
	struct ipset_collection_head ips_collection, ips_collection_exclude;

	// list of pointers to hostlist files
	struct hostlist_collection_head hl_collection, hl_collection_exclude;
	// pointer to autohostlist. NULL if no autohostlist for the profile.
	struct hostlist_file *hostlist_auto;
	int hostlist_auto_fail_threshold, hostlist_auto_fail_time, hostlist_auto_retrans_threshold;

	hostfail_pool *hostlist_auto_fail_counters;
};

#define PROFILE_IPSETS_ABSENT(dp) (!LIST_FIRST(&dp->ips_collection) && !LIST_FIRST(&dp->ips_collection_exclude))
#define PROFILE_IPSETS_EMPTY(dp) (ipset_collection_is_empty(&dp->ips_collection) && ipset_collection_is_empty(&dp->ips_collection_exclude))
#define PROFILE_HOSTLISTS_EMPTY(dp) (hostlist_collection_is_empty(&dp->hl_collection) && hostlist_collection_is_empty(&dp->hl_collection_exclude))

struct desync_profile_list {
	struct desync_profile dp;
	LIST_ENTRY(desync_profile_list) next;
};
LIST_HEAD(desync_profile_list_head, desync_profile_list);
struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head);
void dp_entry_destroy(struct desync_profile_list *entry);
void dp_list_destroy(struct desync_profile_list_head *head);
bool dp_list_have_autohostlist(struct desync_profile_list_head *head);
void dp_init(struct desync_profile *dp);
bool dp_fake_defaults(struct desync_profile *dp);
void dp_clear(struct desync_profile *dp);

struct params_s
{
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	wordexp_t wexp; // for file based config
#endif

	enum log_target debug_target;
	char debug_logfile[PATH_MAX];
	bool debug;

#ifdef __linux__
	int qnum;
#elif defined(BSD)
	uint16_t port; // divert port
#endif
	char bind_fix4,bind_fix6;
	uint32_t desync_fwmark; // unused in BSD
	
	struct desync_profile_list_head desync_profiles;
	
#ifdef __CYGWIN__
	struct str_list_head ssid_filter,nlm_filter;
#else
	bool droproot;
	uid_t uid;
	gid_t gid;
#endif

	char hostlist_auto_debuglog[PATH_MAX];

	// hostlist files with data for all profiles
	struct hostlist_files_head hostlists;
	// ipset files with data for all profiles
	struct ipset_files_head ipsets;

	unsigned int ctrack_t_syn, ctrack_t_est, ctrack_t_fin, ctrack_t_udp;
	t_conntrack conntrack;
};

extern struct params_s params;
extern const char *progname;

int DLOG(const char *format, ...);
int DLOG_ERR(const char *format, ...);
int DLOG_PERROR(const char *s);
int DLOG_CONDUP(const char *format, ...);
int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...);
void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit);
