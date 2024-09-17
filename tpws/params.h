#pragma once

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <time.h>
#include "tpws.h"
#include "pools.h"
#include "helpers.h"
#include "protocol.h"

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT 3
#define HOSTLIST_AUTO_FAIL_TIME_DEFAULT 60

enum bindll
{
	unwanted = 0,
	no,
	prefer,
	force
};

#define MAX_BINDS 32
struct bind_s
{
	char bindaddr[64], bindiface[IF_NAMESIZE];
	bool bind_if6;
	enum bindll bindll;
	int bind_wait_ifup, bind_wait_ip, bind_wait_ip_ll;
};

enum log_target
{
	LOG_TARGET_CONSOLE = 0,
	LOG_TARGET_FILE,
	LOG_TARGET_SYSLOG
};

struct params_s
{
	struct bind_s binds[MAX_BINDS];
	int binds_last;
	bool bind_wait_only;
	uint16_t port;

	uint8_t proxy_type;
	bool no_resolve;
	bool skip_nodelay;
	bool droproot;
	uid_t uid;
	gid_t gid;
	bool daemon;
	int maxconn, resolver_threads, maxfiles, max_orphan_time;
	int local_rcvbuf, local_sndbuf, remote_rcvbuf, remote_sndbuf;
#if defined(__linux__) || defined(__APPLE__)
	int tcp_user_timeout_local, tcp_user_timeout_remote;
#endif

	bool tamper; // any tamper option is set
	bool hostcase, hostdot, hosttab, hostnospace, methodspace, methodeol, unixeol, domcase;
	int hostpad;
	char hostspell[4];
	enum httpreqpos split_http_req;
	enum tlspos tlsrec;
	int tlsrec_pos;
	enum tlspos split_tls;
	bool split_any_protocol;
	int split_pos;
	bool disorder, disorder_http, disorder_tls;
	bool oob, oob_http, oob_tls;
	uint8_t oob_byte;
	int ttl_default;

	int mss;
	port_filter mss_pf;

	char pidfile[256];

	strpool *hostlist, *hostlist_exclude;
	struct str_list_head hostlist_files, hostlist_exclude_files;
	char hostlist_auto_filename[PATH_MAX], hostlist_auto_debuglog[PATH_MAX];
	int hostlist_auto_fail_threshold, hostlist_auto_fail_time;
	time_t hostlist_auto_mod_time;
	hostfail_pool *hostlist_auto_fail_counters;

	bool tamper_start_n, tamper_cutoff_n;
	unsigned int tamper_start, tamper_cutoff;

	struct sockaddr_in connect_bind4;
	struct sockaddr_in6 connect_bind6;
	char connect_bind6_ifname[IF_NAMESIZE];

	int debug;
	enum log_target debug_target;
	char debug_logfile[PATH_MAX];

#if defined(BSD)
	bool pf_enable;
#endif
#ifdef SPLICE_PRESENT
	bool nosplice;
#endif
};

extern struct params_s params;

int DLOG(const char *format, int level, ...);
int DLOG_CONDUP(const char *format, ...);
int DLOG_ERR(const char *format, ...);
int DLOG_PERROR(const char *s);
int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...);

#define VPRINT(format, ...) DLOG(format, 1, ##__VA_ARGS__)
#define DBGPRINT(format, ...) DLOG(format, 2, ##__VA_ARGS__)
