#pragma once

#include "pools.h"
#include "conntrack.h"
#include "desync.h"
#include "protocol.h"

#include <sys/param.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#define TLS_PARTIALS_ENABLE true

#define Q_RCVBUF (128 * 1024)  // in bytes
#define Q_SNDBUF (64 * 1024)   // in bytes
#define RAW_SNDBUF (64 * 1024) // in bytes

#define Q_MAXLEN 1024 // in packets

#define BADSEQ_INCREMENT_DEFAULT -10000
#define BADSEQ_ACK_INCREMENT_DEFAULT -66000

#define IPFRAG_UDP_DEFAULT 8
#define IPFRAG_TCP_DEFAULT 32

#define UDPLEN_INCREMENT_DEFAULT 2

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT 3
#define HOSTLIST_AUTO_FAIL_TIME_DEFAULT 60
#define HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT 3

enum log_target
{
	LOG_TARGET_CONSOLE = 0,
	LOG_TARGET_FILE,
	LOG_TARGET_SYSLOG
};

struct params_s
{
	enum log_target debug_target;
	char debug_logfile[PATH_MAX];
	bool debug;

	uint16_t wsize, wssize;
	uint8_t wscale, wsscale;
	char wssize_cutoff_mode; // n - packets, d - data packets, s - relative sequence
	unsigned int wssize_cutoff;
#ifdef __linux__
	int qnum;
#elif defined(BSD)
	uint16_t port; // divert port
#endif
	char bind_fix4, bind_fix6;
	bool hostcase, hostnospace, domcase;
	char hostspell[4];
	enum dpi_desync_mode desync_mode0, desync_mode, desync_mode2;
	bool desync_retrans, desync_skip_nosni, desync_any_proto;
	unsigned int desync_repeats, desync_split_pos, desync_seqovl, desync_ipfrag_pos_tcp, desync_ipfrag_pos_udp;
	enum httpreqpos desync_split_http_req;
	enum tlspos desync_split_tls;
	char desync_start_mode, desync_cutoff_mode; // n - packets, d - data packets, s - relative sequence
	unsigned int desync_start, desync_cutoff;
	uint8_t desync_ttl, desync_ttl6;
	autottl desync_autottl, desync_autottl6;
	uint32_t desync_fooling_mode;
	uint32_t desync_fwmark; // unused in BSD
	uint32_t desync_badseq_increment, desync_badseq_ack_increment;
	uint8_t fake_http[1460], fake_tls[1460], fake_unknown[1460], fake_syndata[1460], seqovl_pattern[1460];
	uint8_t fake_unknown_udp[1472], udplen_pattern[1472], fake_quic[1472], fake_wg[1472], fake_dht[1472];
	size_t fake_http_size, fake_tls_size, fake_quic_size, fake_wg_size, fake_dht_size, fake_unknown_size, fake_syndata_size, fake_unknown_udp_size;
	int udplen_increment;

#ifdef __CYGWIN__
	struct str_list_head ssid_filter, nlm_filter;
#else
	bool droproot;
	uid_t uid;
	gid_t gid;
#endif

	strpool *hostlist, *hostlist_exclude;
	struct str_list_head hostlist_files, hostlist_exclude_files;
	char hostlist_auto_filename[PATH_MAX], hostlist_auto_debuglog[PATH_MAX];
	int hostlist_auto_fail_threshold, hostlist_auto_fail_time, hostlist_auto_retrans_threshold;
	time_t hostlist_auto_mod_time;
	hostfail_pool *hostlist_auto_fail_counters;

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
