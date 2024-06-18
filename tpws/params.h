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

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT	3
#define	HOSTLIST_AUTO_FAIL_TIME_DEFAULT 	60

enum bindll { unwanted=0, no, prefer, force };

#define MAX_BINDS	32
struct bind_s
{
	char bindaddr[64],bindiface[IF_NAMESIZE];
	bool bind_if6;
	enum bindll bindll;
	int bind_wait_ifup,bind_wait_ip,bind_wait_ip_ll;
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
	int maxconn,resolver_threads,maxfiles,max_orphan_time;
	int local_rcvbuf,local_sndbuf,remote_rcvbuf,remote_sndbuf;

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

	bool tamper_start_n,tamper_cutoff_n;
	unsigned int tamper_start,tamper_cutoff;

	int debug;

#if defined(BSD)
	bool pf_enable;
#endif
#ifdef SPLICE_PRESENT
	bool nosplice;
#endif
};

extern struct params_s params;

#define _DBGPRINT(format, level, ...) { if (params.debug>=level) printf(format "\n", ##__VA_ARGS__); }
#define VPRINT(format, ...) _DBGPRINT(format,1,##__VA_ARGS__)
#define DBGPRINT(format, ...) _DBGPRINT(format,2,##__VA_ARGS__)

#define LOG_APPEND(filename, format, ...) \
{ \
	FILE *F = fopen(filename,"at"); \
	if (F) \
	{ \
		fprint_localtime(F); \
		fprintf(F, " : " format "\n", ##__VA_ARGS__); \
		fclose(F); \
	} \
}
#define HOSTLIST_DEBUGLOG_APPEND(format, ...) if (*params.hostlist_auto_debuglog) LOG_APPEND(params.hostlist_auto_debuglog, format, ##__VA_ARGS__)
