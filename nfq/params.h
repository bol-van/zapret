#pragma once

#include "params.h"
#include "strpool.h"
#include "conntrack.h"
#include "desync.h"

#include <sys/param.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define Q_RCVBUF	(128*1024)	// in bytes
#define Q_SNDBUF	(64*1024)	// in bytes
#define RAW_SNDBUF	(64*1024)	// in bytes

#define Q_MAXLEN	1024		// in packets

struct params_s
{
	bool debug;
	uint16_t wsize,wssize;
	uint8_t wscale,wsscale;
	unsigned int wssize_cutoff;
#ifdef __linux__
	int qnum;
#elif defined(BSD)
	uint16_t port; // divert port
#endif
	bool hostcase, hostnospace, domcase;
	char hostspell[4];
	enum dpi_desync_mode desync_mode0,desync_mode,desync_mode2;
	bool desync_retrans,desync_skip_nosni,desync_any_proto;
	int desync_repeats,desync_split_pos;
	unsigned int desync_cutoff;
	uint8_t desync_ttl;
	uint8_t desync_tcp_fooling_mode;
	uint32_t desync_fwmark; // unused in BSD
	char hostfile[256];
	strpool *hostlist;
	uint8_t fake_http[1460],fake_tls[1460];
	size_t fake_http_size,fake_tls_size;
	bool droproot;
	uid_t uid;
	gid_t gid;

	unsigned int ctrack_t_syn, ctrack_t_est, ctrack_t_fin;
	t_conntrack conntrack;
};

extern struct params_s params;

#define DLOG(format, ...) {if (params.debug) printf(format, ##__VA_ARGS__);}
