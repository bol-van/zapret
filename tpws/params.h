#pragma once

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <time.h>
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
#include <wordexp.h>
#endif


#include "tpws.h"
#include "pools.h"
#include "helpers.h"
#include "protocol.h"

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT	3
#define	HOSTLIST_AUTO_FAIL_TIME_DEFAULT 	60

#define FIX_SEG_DEFAULT_MAX_WAIT 50

#define IPCACHE_LIFETIME 7200

#define MAX_GIDS 64

enum bindll { unwanted=0, no, prefer, force };

#define MAX_BINDS 32
struct bind_s
{
	char bindaddr[64],bindiface[IF_NAMESIZE];
	bool bind_if6;
	enum bindll bindll;
	int bind_wait_ifup,bind_wait_ip,bind_wait_ip_ll;
};

#define MAX_SPLITS 16

enum log_target { LOG_TARGET_CONSOLE=0, LOG_TARGET_FILE, LOG_TARGET_SYSLOG, LOG_TARGET_ANDROID };

struct desync_profile
{
	int n;	// number of the profile

	bool hostcase, hostdot, hosttab, hostnospace, methodspace, methodeol, unixeol, domcase;
	int hostpad;
	char hostspell[4];
	bool split_any_protocol;
	bool disorder, disorder_http, disorder_tls;
	bool oob, oob_http, oob_tls;
	uint8_t oob_byte;

	// multisplit
	struct proto_pos splits[MAX_SPLITS];
	int split_count;
	struct proto_pos tlsrec;

	int mss;

	bool tamper_start_n,tamper_cutoff_n;
	unsigned int tamper_start,tamper_cutoff;

	bool filter_ipv4,filter_ipv6;
	struct port_filters_head pf_tcp;
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
void dp_init(struct desync_profile *dp);
void dp_clear(struct desync_profile *dp);

struct params_s
{
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	wordexp_t wexp; // for file based config
#endif

	int debug;
	enum log_target debug_target;
	char debug_logfile[PATH_MAX];

	struct bind_s binds[MAX_BINDS];
	int binds_last;
	bool bind_wait_only;
	uint16_t port;
	struct sockaddr_in connect_bind4;
	struct sockaddr_in6 connect_bind6;
	char connect_bind6_ifname[IF_NAMESIZE];

	uint8_t proxy_type;
	unsigned int fix_seg;
	bool fix_seg_avail;
	bool no_resolve;
	bool skip_nodelay;
	bool daemon;
	bool droproot;
	char *user;
	uid_t uid;
	gid_t gid[MAX_GIDS];
	int gid_count;
	char pidfile[PATH_MAX];
	int maxconn,resolver_threads,maxfiles,max_orphan_time;
	int local_rcvbuf,local_sndbuf,remote_rcvbuf,remote_sndbuf;
#if defined(__linux__) || defined(__APPLE__)
	int tcp_user_timeout_local,tcp_user_timeout_remote;
#endif

#if defined(BSD)
	bool pf_enable;
#endif
#ifdef SPLICE_PRESENT
	bool nosplice;
#endif

	int ttl_default;
	char hostlist_auto_debuglog[PATH_MAX];

	// hostlist files with data for all profiles
	struct hostlist_files_head hostlists;
	// ipset files with data for all profiles
	struct ipset_files_head ipsets;

	bool tamper; // any tamper option is set
	bool tamper_lim; // tamper-start or tamper-cutoff set in any profile
	struct desync_profile_list_head desync_profiles;

	unsigned int ipcache_lifetime;
	bool cache_hostname;
	ip_cache ipcache;
};

extern struct params_s params;
extern const char *progname;
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
void cleanup_args(struct params_s *params);
#endif
void cleanup_params(struct params_s *params);

int DLOG(const char *format, int level, ...);
int DLOG_CONDUP(const char *format, ...);
int DLOG_ERR(const char *format, ...);
int DLOG_PERROR(const char *s);
int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...);
void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit);

#define VPRINT(format, ...) DLOG(format, 1, ##__VA_ARGS__)
#define DBGPRINT(format, ...) DLOG(format, 2, ##__VA_ARGS__)
