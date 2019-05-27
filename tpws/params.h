#pragma once

#include <stdbool.h>
#include <net/if.h>
#include <stdint.h>
#include "strpool.h"

enum splithttpreq { split_none = 0, split_method, split_host };

struct params_s
{
	char bindaddr[64],bindiface[IFNAMSIZ];
	bool bind_if6;
	bool bindll,bindll_force;
	int bind_wait_ifup,bind_wait_ip,bind_wait_ip_ll;
	uid_t uid;
	gid_t gid;
	uint16_t port;
	bool daemon;
	bool hostcase, hostdot, hosttab, hostnospace, methodspace, methodeol, unixeol;
	char hostspell[4];
	enum splithttpreq split_http_req;
	int split_pos;
	int maxconn;
	char hostfile[256];
	char pidfile[256];
	strpool *hostlist;
	bool debug;
};

extern struct params_s params;

#define DBGPRINT(format, ...) { if (params.debug) printf(format "\n", ##__VA_ARGS__); }
