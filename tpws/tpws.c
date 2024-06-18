#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/resource.h>
#include <time.h>

#include "tpws.h"

#ifdef BSD
 #include <sys/sysctl.h>
#endif

#include "tpws_conn.h"
#include "hostlist.h"
#include "params.h"
#include "sec.h"
#include "redirect.h"
#include "helpers.h"
#include "gzip.h"
#include "pools.h"

struct params_s params;

bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	if (params.hostlist || params.hostlist_exclude)
		printf("Will reload hostlists on next request\n");
	bHup = true;
}
// should be called in normal execution
void dohup(void)
{
	if (bHup)
	{
		if (!LoadIncludeHostLists() || !LoadExcludeHostLists())
		{
			// what will we do without hostlist ?? sure, gonna die
			exit(1);
		}
		bHup = false;
	}
}

static void onusr2(int sig)
{
	printf("\nHOSTFAIL POOL DUMP\n");
	HostFailPoolDump(params.hostlist_auto_fail_counters);
	printf("\n");
}


static int8_t block_sigpipe(void)
{
	sigset_t sigset;
	memset(&sigset, 0, sizeof(sigset));

	//Get the old sigset, add SIGPIPE and update sigset
	if (sigprocmask(SIG_BLOCK, NULL, &sigset) == -1) {
		perror("sigprocmask (get)");
		return -1;
	}

	if (sigaddset(&sigset, SIGPIPE) == -1) {
		perror("sigaddset");
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
		perror("sigprocmask (set)");
		return -1;
	}

	return 0;
}


static bool is_interface_online(const char *ifname)
{
	struct ifreq ifr;
	int sock;
	
	if ((sock=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
		return false;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = 0;
	ioctl(sock, SIOCGIFFLAGS, &ifr);
	close(sock);
	return !!(ifr.ifr_flags & IFF_UP);
}
static int get_default_ttl(void)
{
	int sock,ttl=0;
	socklen_t optlen=sizeof(ttl);
	
	if ((sock=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP))!=-1)
	{
	    getsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, &optlen);
	    close(sock);
	}
	return ttl;
}


static void exithelp(void)
{
	printf(
		" --bind-addr=<v4_addr>|<v6_addr>\t; for v6 link locals append %%interface_name\n"
		" --bind-iface4=<interface_name>\t\t; bind to the first ipv4 addr of interface\n"
		" --bind-iface6=<interface_name>\t\t; bind to the first ipv6 addr of interface\n"
		" --bind-linklocal=no|unwanted|prefer|force ; prohibit, accept, prefer or force ipv6 link local bind\n"
		" --bind-wait-ifup=<sec>\t\t\t; wait for interface to appear and up\n"
		" --bind-wait-ip=<sec>\t\t\t; after ifup wait for ip address to appear up to N seconds\n"
		" --bind-wait-ip-linklocal=<sec>\t\t; (prefer) accept only LL first N seconds then any  (unwanted) accept only globals first N seconds then LL\n"
		" --bind-wait-only\t\t\t; wait for bind conditions satisfaction then exit. return code 0 if success.\n"
		" * multiple binds are supported. each bind-addr, bind-iface* start new bind\n"
		" --port=<port>\t\t\t\t; only one port number for all binds is supported\n"
		" --socks\t\t\t\t; implement socks4/5 proxy instead of transparent proxy\n"
		" --no-resolve\t\t\t\t; disable socks5 remote dns ability\n"
		" --resolver-threads=<int>\t\t; number of resolver worker threads\n"
		" --local-rcvbuf=<bytes>\n"
		" --local-sndbuf=<bytes>\n"
		" --remote-rcvbuf=<bytes>\n"
		" --remote-sndbuf=<bytes>\n"
#ifdef SPLICE_PRESENT
		" --nosplice\t\t\t\t; do not use splice to transfer data between sockets\n"
#endif
		" --skip-nodelay\t\t\t\t; do not set TCP_NODELAY option for outgoing connections (incompatible with split options)\n"
		" --maxconn=<max_connections>\n"
#ifdef SPLICE_PRESENT
		" --maxfiles=<max_open_files>\t\t; should be at least (X*connections+16), where X=6 in tcp proxy mode, X=4 in tampering mode\n"
#else
		" --maxfiles=<max_open_files>\t\t; should be at least (connections*2+16)\n"
#endif
		" --max-orphan-time=<sec>\t\t; if local leg sends something and closes and remote leg is still connecting then cancel connection attempt after N seconds\n"
		" --daemon\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t; write pid to file\n"
		" --user=<username>\t\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t\t; drop root privs\n"
#if defined(BSD) && !defined(__OpenBSD__) && !defined(__APPLE__)
		" --enable-pf\t\t\t\t; enable PF redirector support. required in FreeBSD when used with PF firewall.\n"
#endif
		" --debug=0|1|2\t\t\t\t; 0(default)=silent 1=verbose 2=debug\n"
		"\nFILTER:\n"
		" --hostlist=<filename>\t\t\t; only act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-exclude=<filename>\t\t; do not act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-auto=<filename>\t\t; detect DPI blocks and build hostlist automatically\n"
		" --hostlist-auto-fail-threshold=<int>\t; how many failed attempts cause hostname to be added to auto hostlist (default : %d)\n"
		" --hostlist-auto-fail-time=<int>\t; all failed attemps must be within these seconds (default : %d)\n"
		" --hostlist-auto-debug=<logfile>\t; debug auto hostlist positives\n"
		"\nTAMPER:\n"
		" --split-http-req=method|host\t\t; split at specified logical part of plain http request\n"
		" --split-tls=sni|sniext\t\t\t; split at specified logical part of TLS ClientHello\n"
		" --split-pos=<numeric_offset>\t\t; split at specified pos. split-http-req or split-tls take precedence for http.\n"
		" --split-any-protocol\t\t\t; split not only http and https\n"
#if defined(BSD) && !defined(__APPLE__)
		" --disorder[=http|tls]\t\t\t; when splitting simulate sending second fragment first (BSD sends entire message instead of first fragment, this is not good)\n"
#else
		" --disorder[=http|tls]\t\t\t; when splitting simulate sending second fragment first\n"
#endif
		" --oob[=http|tls]\t\t\t; when splitting send out of band byte. default is HEX 0x00.\n"
		" --oob-data=<char>|0xHEX\t\t; override default 0x00 OOB byte.\n"
		" --hostcase\t\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostdot\t\t\t\t; add \".\" after Host: name\n"
		" --hosttab\t\t\t\t; add tab after Host: name\n"
		" --hostnospace\t\t\t\t; remove space after Host:\n"
		" --hostpad=<bytes>\t\t\t; add dummy padding headers before Host:\n"
		" --domcase\t\t\t\t; mix domain case : Host: TeSt.cOm\n"
		" --methodspace\t\t\t\t; add extra space after method\n"
		" --methodeol\t\t\t\t; add end-of-line before method\n"
		" --unixeol\t\t\t\t; replace 0D0A to 0A\n"
		" --tlsrec=sni|sniext\t\t\t; make 2 TLS records. split at specified logical part. don't split if SNI is not present\n"
		" --tlsrec-pos=<pos>\t\t\t; make 2 TLS records. split at specified pos\n"
#ifdef __linux__
		" --mss=<int>\t\t\t\t; set client MSS. forces server to split messages but significantly decreases speed !\n"
		" --mss-pf=[~]port1[-port2]\t\t; MSS port filter. ~ means negation\n"
#endif
		" --tamper-start=[n]<pos>\t\t; start tampering only from specified outbound stream position. default is 0. 'n' means data block number.\n"
		" --tamper-cutoff=[n]<pos>\t\t; do not tamper anymore after specified outbound stream position. default is unlimited.\n",
		HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT, HOSTLIST_AUTO_FAIL_TIME_DEFAULT
	);
	exit(1);
}
static void cleanup_params(void)
{
	strlist_destroy(&params.hostlist_files);
	strlist_destroy(&params.hostlist_exclude_files);
	StrPoolDestroy(&params.hostlist_exclude);
	StrPoolDestroy(&params.hostlist);
	HostFailPoolDestroy(&params.hostlist_auto_fail_counters);
}
static void exithelp_clean(void)
{
	cleanup_params();
	exithelp();
}
static void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}
static void nextbind_clean(void)
{
	params.binds_last++;
	if (params.binds_last>=MAX_BINDS)
	{
		fprintf(stderr,"maximum of %d binds are supported\n",MAX_BINDS);
		exit_clean(1);
	}
}
static void checkbind_clean(void)
{
	if (params.binds_last<0)
	{
		fprintf(stderr,"start new bind with --bind-addr,--bind-iface*\n");
		exit_clean(1);
	}
}


void save_default_ttl(void)
{
	if (!params.ttl_default)
	{
    	    params.ttl_default = get_default_ttl();
	    if (!params.ttl_default)
	    {
		    fprintf(stderr, "could not get default ttl\n");
		    exit_clean(1);
	    }
	}
}

bool parse_httpreqpos(const char *s, enum httpreqpos *pos)
{
	if (!strcmp(s, "method"))
		*pos = httpreqpos_method;
	else if (!strcmp(s, "host"))
		*pos = httpreqpos_host;
	else
		return false;
	return true;
}
bool parse_tlspos(const char *s, enum tlspos *pos)
{
	if (!strcmp(s, "sni"))
		*pos = tlspos_sni;
	else if (!strcmp(s, "sniext"))
		*pos = tlspos_sniext;
	else
		return false;
	return true;
}


void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	params.maxconn = DEFAULT_MAX_CONN;
	params.max_orphan_time = DEFAULT_MAX_ORPHAN_TIME;
	params.binds_last = -1;
	params.hostlist_auto_fail_threshold = HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT;
	params.hostlist_auto_fail_time = HOSTLIST_AUTO_FAIL_TIME_DEFAULT;
	LIST_INIT(&params.hostlist_files);
	LIST_INIT(&params.hostlist_exclude_files);

#if defined(__OpenBSD__) || defined(__APPLE__)
	params.pf_enable = true; // OpenBSD and MacOS have no other choice
#endif
	if (can_drop_root())
	{
	    params.uid = params.gid = 0x7FFFFFFF; // default uid:gid
	    params.droproot = true;
	}

	const struct option long_options[] = {
		{ "help",no_argument,0,0 },// optidx=0
		{ "h",no_argument,0,0 },// optidx=1
		{ "bind-addr",required_argument,0,0 },// optidx=2
		{ "bind-iface4",required_argument,0,0 },// optidx=3
		{ "bind-iface6",required_argument,0,0 },// optidx=4
		{ "bind-linklocal",required_argument,0,0 },// optidx=5
		{ "bind-wait-ifup",required_argument,0,0 },// optidx=6
		{ "bind-wait-ip",required_argument,0,0 },// optidx=7
		{ "bind-wait-ip-linklocal",required_argument,0,0 },// optidx=8
		{ "bind-wait-only",no_argument,0,0 },// optidx=9
		{ "port",required_argument,0,0 },// optidx=10
		{ "daemon",no_argument,0,0 },// optidx=11
		{ "user",required_argument,0,0 },// optidx=12
		{ "uid",required_argument,0,0 },// optidx=13
		{ "maxconn",required_argument,0,0 },// optidx=14
		{ "maxfiles",required_argument,0,0 },// optidx=15
		{ "max-orphan-time",required_argument,0,0 },// optidx=16
		{ "hostcase",no_argument,0,0 },// optidx=17
		{ "hostspell",required_argument,0,0 },// optidx=18
		{ "hostdot",no_argument,0,0 },// optidx=19
		{ "hostnospace",no_argument,0,0 },// optidx=20
		{ "hostpad",required_argument,0,0 },// optidx=21
		{ "domcase",no_argument,0,0 },// optidx=22
		{ "split-http-req",required_argument,0,0 },// optidx=23
		{ "split-tls",required_argument,0,0 },// optidx=24
		{ "split-pos",required_argument,0,0 },// optidx=25
		{ "split-any-protocol",optional_argument,0,0},// optidx=26
		{ "disorder",optional_argument,0,0 },// optidx=27
		{ "oob",optional_argument,0,0 },// optidx=28
		{ "oob-data",required_argument,0,0 },// optidx=29
		{ "methodspace",no_argument,0,0 },// optidx=30
		{ "methodeol",no_argument,0,0 },// optidx=31
		{ "hosttab",no_argument,0,0 },// optidx=32
		{ "unixeol",no_argument,0,0 },// optidx=33
		{ "tlsrec",required_argument,0,0 },// optidx=34
		{ "tlsrec-pos",required_argument,0,0 },// optidx=35
		{ "hostlist",required_argument,0,0 },// optidx=36
		{ "hostlist-exclude",required_argument,0,0 },// optidx=37
		{ "hostlist-auto",required_argument,0,0}, // optidx=38
		{ "hostlist-auto-fail-threshold",required_argument,0,0}, // optidx=39
		{ "hostlist-auto-fail-time",required_argument,0,0},	// optidx=40
		{ "hostlist-auto-debug",required_argument,0,0}, // optidx=41
		{ "pidfile",required_argument,0,0 },// optidx=42
		{ "debug",optional_argument,0,0 },// optidx=43
		{ "local-rcvbuf",required_argument,0,0 },// optidx=44
		{ "local-sndbuf",required_argument,0,0 },// optidx=45
		{ "remote-rcvbuf",required_argument,0,0 },// optidx=46
		{ "remote-sndbuf",required_argument,0,0 },// optidx=47
		{ "socks",no_argument,0,0 },// optidx=48
		{ "no-resolve",no_argument,0,0 },// optidx=49
		{ "resolver-threads",required_argument,0,0 },// optidx=50
		{ "skip-nodelay",no_argument,0,0 },// optidx=51
		{ "tamper-start",required_argument,0,0 },// optidx=52
		{ "tamper-cutoff",required_argument,0,0 },// optidx=53
#if defined(BSD) && !defined(__OpenBSD__) && !defined(__APPLE__)
		{ "enable-pf",no_argument,0,0 },// optidx=54
#elif defined(__linux__)
		{ "mss",required_argument,0,0 },// optidx=54
		{ "mss-pf",required_argument,0,0 },// optidx=55
#ifdef SPLICE_PRESENT
		{ "nosplice",no_argument,0,0 },// optidx=55
#endif
#endif
		{ "hostlist-auto-retrans-threshold",optional_argument,0,0}, // ignored. for nfqws command line compatibility
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp_clean();
		switch (option_index)
		{
		case 0:
		case 1:
			exithelp_clean();
			break;
		case 2: /* bind-addr */
			nextbind_clean();
			{
				char *p = strchr(optarg,'%');
				if (p)
				{
					*p=0;
					strncpy(params.binds[params.binds_last].bindiface, p+1, sizeof(params.binds[params.binds_last].bindiface));
				}
				strncpy(params.binds[params.binds_last].bindaddr, optarg, sizeof(params.binds[params.binds_last].bindaddr));
			}
			params.binds[params.binds_last].bindaddr[sizeof(params.binds[params.binds_last].bindaddr) - 1] = 0;
			break;
		case 3: /* bind-iface4 */
			nextbind_clean();
			params.binds[params.binds_last].bind_if6=false;
			strncpy(params.binds[params.binds_last].bindiface, optarg, sizeof(params.binds[params.binds_last].bindiface));
			params.binds[params.binds_last].bindiface[sizeof(params.binds[params.binds_last].bindiface) - 1] = 0;
			break;
		case 4: /* bind-iface6 */
			nextbind_clean();
			params.binds[params.binds_last].bind_if6=true;
			strncpy(params.binds[params.binds_last].bindiface, optarg, sizeof(params.binds[params.binds_last].bindiface));
			params.binds[params.binds_last].bindiface[sizeof(params.binds[params.binds_last].bindiface) - 1] = 0;
			break;
		case 5: /* bind-linklocal */
			checkbind_clean();
			params.binds[params.binds_last].bindll = true;
			if (!strcmp(optarg, "no"))
				params.binds[params.binds_last].bindll=no;
			else if (!strcmp(optarg, "prefer"))
				params.binds[params.binds_last].bindll=prefer;
			else if (!strcmp(optarg, "force"))
				params.binds[params.binds_last].bindll=force;
			else if (!strcmp(optarg, "unwanted"))
				params.binds[params.binds_last].bindll=unwanted;
			else
			{
				fprintf(stderr, "invalid parameter in bind-linklocal : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 6: /* bind-wait-ifup */
			checkbind_clean();
			params.binds[params.binds_last].bind_wait_ifup = atoi(optarg);
			break;
		case 7: /* bind-wait-ip */
			checkbind_clean();
			params.binds[params.binds_last].bind_wait_ip = atoi(optarg);
			break;
		case 8: /* bind-wait-ip-linklocal */
			checkbind_clean();
			params.binds[params.binds_last].bind_wait_ip_ll = atoi(optarg);
			break;
		case 9: /* bind-wait-only */
			params.bind_wait_only = true;
			break;
		case 10: /* port */
			i = atoi(optarg);
			if (i <= 0 || i > 65535)
			{
				fprintf(stderr, "bad port number\n");
				exit_clean(1);
			}
			params.port = (uint16_t)i;
			break;
		case 11: /* daemon */
			params.daemon = true;
			break;
		case 12: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			params.droproot = true;
			break;
		}
		case 13: /* uid */
			params.gid=0x7FFFFFFF; // default git. drop gid=0
			params.droproot = true;
			if (sscanf(optarg,"%u:%u",&params.uid,&params.gid)<1)
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 14: /* maxconn */
			params.maxconn = atoi(optarg);
			if (params.maxconn <= 0 || params.maxconn > 10000)
			{
				fprintf(stderr, "bad maxconn\n");
				exit_clean(1);
			}
			break;
		case 15: /* maxfiles */
			params.maxfiles = atoi(optarg);
			if (params.maxfiles < 0)
			{
				fprintf(stderr, "bad maxfiles\n");
				exit_clean(1);
			}
			break;
		case 16: /* max-orphan-time */
			params.max_orphan_time = atoi(optarg);
			if (params.max_orphan_time < 0)
			{
				fprintf(stderr, "bad max_orphan_time\n");
				exit_clean(1);
			}
			break;
		case 17: /* hostcase */
			params.hostcase = true;
			params.tamper = true;
			break;
		case 18: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			params.tamper = true;
			break;
		case 19: /* hostdot */
			params.hostdot = true;
			params.tamper = true;
			break;
		case 20: /* hostnospace */
			params.hostnospace = true;
			params.tamper = true;
			break;
		case 21: /* hostpad */
			params.hostpad = atoi(optarg);
			params.tamper = true;
			break;
		case 22: /* domcase */
			params.domcase = true;
			params.tamper = true;
			break;
		case 23: /* split-http-req */
			if (!parse_httpreqpos(optarg, &params.split_http_req))
			{
				fprintf(stderr, "Invalid argument for split-http-req\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 24: /* split-tls */
			if (!parse_tlspos(optarg, &params.split_tls))
			{
				fprintf(stderr, "Invalid argument for split-tls\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 25: /* split-pos */
			i = atoi(optarg);
			if (i>0)
				params.split_pos = i;
			else
			{
				fprintf(stderr, "Invalid argument for split-pos\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 26: /* split-any-protocol */
			params.split_any_protocol = true;
			break;
		case 27: /* disorder */
			if (optarg)
			{
				if (!strcmp(optarg,"http")) params.disorder_http=true;
				else if (!strcmp(optarg,"tls")) params.disorder_tls=true;
				else
				{
					fprintf(stderr, "Invalid argument for disorder\n");
					exit_clean(1);
				}
			}
			else
				params.disorder = true;
			save_default_ttl();
			break;
		case 28: /* oob */
			if (optarg)
			{
				if (!strcmp(optarg,"http")) params.oob_http=true;
				else if (!strcmp(optarg,"tls")) params.oob_tls=true;
				else
				{
					fprintf(stderr, "Invalid argument for oob\n");
					exit_clean(1);
				}
			}
			else
				params.oob = true;
			break;
		case 29: /* oob-data */
			{
				size_t l = strlen(optarg);
				unsigned int bt;
				if (l==1) params.oob_byte = (uint8_t)*optarg;
				else if (l!=4 || sscanf(optarg,"0x%02X",&bt)!=1)
				{
					fprintf(stderr, "Invalid argument for oob-data\n");
					exit_clean(1);
				}
				else params.oob_byte = (uint8_t)bt;
			}
			break;
		case 30: /* methodspace */
			params.methodspace = true;
			params.tamper = true;
			break;
		case 31: /* methodeol */
			params.methodeol = true;
			params.tamper = true;
			break;
		case 32: /* hosttab */
			params.hosttab = true;
			params.tamper = true;
			break;
		case 33: /* unixeol */
			params.unixeol = true;
			params.tamper = true;
			break;
		case 34: /* tlsrec */
			if (!parse_tlspos(optarg, &params.tlsrec))
			{
				fprintf(stderr, "Invalid argument for tlsrec\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 35: /* tlsrec-pos */
			if ((params.tlsrec_pos = atoi(optarg))>0)
				params.tlsrec = tlspos_pos;
			else
			{
				fprintf(stderr, "Invalid argument for tlsrec-pos\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 36: /* hostlist */
			if (!strlist_add(&params.hostlist_files, optarg))
			{
				fprintf(stderr, "strlist_add failed\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 37: /* hostlist-exclude */
			if (!strlist_add(&params.hostlist_exclude_files, optarg))
			{
				fprintf(stderr, "strlist_add failed\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 38: /* hostlist-auto */
			if (*params.hostlist_auto_filename)
			{
				fprintf(stderr, "only one auto hostlist is supported\n");
				exit_clean(1);
			}
			{
				FILE *F = fopen(optarg,"a+t");
				if (!F)
				{
					fprintf(stderr, "cannot create %s\n", optarg);
					exit_clean(1);
				}
				bool bGzip = is_gzip(F);
				fclose(F);
				if (bGzip)
				{
					fprintf(stderr, "gzipped auto hostlists are not supported\n");
					exit_clean(1);
				}
				if (params.droproot && chown(optarg, params.uid, -1))
					fprintf(stderr, "could not chown %s. auto hostlist file may not be writable after privilege drop\n", optarg);
			}
			if (!strlist_add(&params.hostlist_files, optarg))
			{
				fprintf(stderr, "strlist_add failed\n");
				exit_clean(1);
			}
			strncpy(params.hostlist_auto_filename, optarg, sizeof(params.hostlist_auto_filename));
			params.hostlist_auto_filename[sizeof(params.hostlist_auto_filename) - 1] = '\0';
			params.tamper = true; // need to detect blocks and update autohostlist. cannot just slice.
			break;
		case 39: /* hostlist-auto-fail-threshold */
			params.hostlist_auto_fail_threshold = (uint8_t)atoi(optarg);
			if (params.hostlist_auto_fail_threshold<1 || params.hostlist_auto_fail_threshold>20)
			{
				fprintf(stderr, "auto hostlist fail threshold must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case 40: /* hostlist-auto-fail-time */
			params.hostlist_auto_fail_time = (uint8_t)atoi(optarg);
			if (params.hostlist_auto_fail_time<1)
			{
				fprintf(stderr, "auto hostlist fail time is not valid\n");
				exit_clean(1);
			}
			break;
		case 41: /* hostlist-auto-debug */
			{
				FILE *F = fopen(optarg,"a+t");
				if (!F)
				{
					fprintf(stderr, "cannot create %s\n", optarg);
					exit_clean(1);
				}
				fclose(F);
				if (params.droproot && chown(optarg, params.uid, -1))
					fprintf(stderr, "could not chown %s. auto hostlist debug log may not be writable after privilege drop\n", optarg);
				strncpy(params.hostlist_auto_debuglog, optarg, sizeof(params.hostlist_auto_debuglog));
				params.hostlist_auto_debuglog[sizeof(params.hostlist_auto_debuglog) - 1] = '\0';
			}
			break;
		case 42: /* pidfile */
			strncpy(params.pidfile,optarg,sizeof(params.pidfile));
			params.pidfile[sizeof(params.pidfile)-1]='\0';
			break;
		case 43:
			params.debug = optarg ? atoi(optarg) : 1;
			break;
		case 44: /* local-rcvbuf */
#ifdef __linux__
			params.local_rcvbuf = atoi(optarg)/2;
#else
			params.local_rcvbuf = atoi(optarg);
#endif
			break;
		case 45: /* local-sndbuf */
#ifdef __linux__
			params.local_sndbuf = atoi(optarg)/2;
#else
			params.local_sndbuf = atoi(optarg);
#endif
			break;
		case 46: /* remote-rcvbuf */
#ifdef __linux__
			params.remote_rcvbuf = atoi(optarg)/2;
#else
			params.remote_rcvbuf = atoi(optarg);
#endif
			break;
		case 47: /* remote-sndbuf */
#ifdef __linux__
			params.remote_sndbuf = atoi(optarg)/2;
#else
			params.remote_sndbuf = atoi(optarg);
#endif
			break;
		case 48: /* socks */
			params.proxy_type = CONN_TYPE_SOCKS;
			break;
		case 49: /* no-resolve */
			params.no_resolve = true;
			break;
		case 50: /* resolver-threads */
			params.resolver_threads = atoi(optarg);
			if (params.resolver_threads<1 || params.resolver_threads>300)
			{
				fprintf(stderr, "resolver-threads must be within 1..300\n");
				exit_clean(1);
			}
			break;
		case 51: /* skip-nodelay */
			params.skip_nodelay = true;
			break;
		case 52: /* tamper-start */
			{
				const char *p=optarg;
				if (*p=='n')
				{
					params.tamper_start_n=true;
					p++;
				}
				else
					params.tamper_start_n=false;
				params.tamper_start = atoi(p);
			}
			break;
		case 53: /* tamper-cutoff */
			{
				const char *p=optarg;
				if (*p=='n')
				{
					params.tamper_cutoff_n=true;
					p++;
				}
				else
					params.tamper_cutoff_n=false;
				params.tamper_cutoff = atoi(p);
			}
			break;
#if defined(BSD) && !defined(__OpenBSD__) && !defined(__APPLE__)
		case 54: /* enable-pf */
			params.pf_enable = true;
			break;
#elif defined(__linux__)
		case 54: /* mss */
			// this option does not work in any BSD and MacOS. OS may accept but it changes nothing
			params.mss = atoi(optarg);
			if (params.mss<88 || params.mss>32767)
			{
				fprintf(stderr, "Invalid value for MSS. Linux accepts MSS 88-32767.\n");
				exit_clean(1);
			}
			break;
		case 55: /* mss-pf */
			if (!pf_parse(optarg,&params.mss_pf))
			{
				fprintf(stderr, "Invalid MSS port filter.\n");
				exit_clean(1);
			}
			break;
#ifdef SPLICE_PRESENT
		case 56: /* nosplice */
			params.nosplice = true;
			break;
#endif
#endif
		}
	}
	if (!params.bind_wait_only && !params.port)
	{
		fprintf(stderr, "Need port number\n");
		exit_clean(1);
	}
	if (params.binds_last<=0)
	{
		params.binds_last=0; // default bind to all
	}
	if (params.skip_nodelay && (params.split_http_req || params.split_pos))
	{
		fprintf(stderr, "Cannot split with --skip-nodelay\n");
		exit_clean(1);
	}
	if (!params.resolver_threads) params.resolver_threads = 5 + params.maxconn/50;
	if (params.split_tls==tlspos_none && params.split_pos) params.split_tls=tlspos_pos;
	if (params.split_http_req==httpreqpos_none && params.split_pos) params.split_http_req=httpreqpos_pos;

	if (*params.hostlist_auto_filename) params.hostlist_auto_mod_time = file_mod_time(params.hostlist_auto_filename);
	if (!LoadIncludeHostLists())
	{
		fprintf(stderr, "Include hostlist load failed\n");
		exit_clean(1);
	}
	if (*params.hostlist_auto_filename) NonEmptyHostlist(&params.hostlist);
	if (!LoadExcludeHostLists())
	{
		fprintf(stderr, "Exclude hostlist load failed\n");
		exit_clean(1);
	}
}


static bool find_listen_addr(struct sockaddr_storage *salisten, const char *bindiface, bool bind_if6, enum bindll bindll, int *if_index)
{
	struct ifaddrs *addrs,*a;
	bool found=false;
	bool bindll_want = bindll==prefer || bindll==force;
    
	if (getifaddrs(&addrs)<0)
		return false;

	// for ipv6 preference order
	// bind-linklocal-1 : link-local,any
	// bind-linklocal=0 : private,global,link-local
	for(int pass=0;pass<3;pass++)
	{
		a  = addrs;
		while (a)
		{
			if (a->ifa_addr)
			{
				if (a->ifa_addr->sa_family==AF_INET &&
				    *bindiface && !bind_if6 && !strcmp(a->ifa_name, bindiface))
				{
					salisten->ss_family = AF_INET;
					memcpy(&((struct sockaddr_in*)salisten)->sin_addr, &((struct sockaddr_in*)a->ifa_addr)->sin_addr, sizeof(struct in_addr));
					found=true;
					goto ex;
				}
				// ipv6 links locals are fe80::/10
				else if (a->ifa_addr->sa_family==AF_INET6
				          &&
				         (!*bindiface && (bindll==prefer || bindll==force) ||
				          *bindiface && bind_if6 && !strcmp(a->ifa_name, bindiface))
				          &&
					 (bindll==force && is_linklocal((struct sockaddr_in6*)a->ifa_addr) ||
					  bindll==prefer && (pass==0 && is_linklocal((struct sockaddr_in6*)a->ifa_addr) || pass==1 && is_private6((struct sockaddr_in6*)a->ifa_addr) || pass==2) ||
					  bindll==no &&	(pass==0 && is_private6((struct sockaddr_in6*)a->ifa_addr) || pass==1 && !is_linklocal((struct sockaddr_in6*)a->ifa_addr)) ||
					  bindll==unwanted && (pass==0 && is_private6((struct sockaddr_in6*)a->ifa_addr) || pass==1 && !is_linklocal((struct sockaddr_in6*)a->ifa_addr) || pass==2))
					)
				{
					salisten->ss_family = AF_INET6;
					memcpy(&((struct sockaddr_in6*)salisten)->sin6_addr, &((struct sockaddr_in6*)a->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
					if (if_index) *if_index = if_nametoindex(a->ifa_name);
					found=true;
					goto ex;
				}
			}
			a = a->ifa_next;
		}
	}
ex:
	freeifaddrs(addrs);
	return found;
}

static bool read_system_maxfiles(rlim_t *maxfile)
{
#ifdef __linux__
	FILE *F;
	int n;
	uintmax_t um;
	if (!(F=fopen("/proc/sys/fs/file-max","r")))
		return false;
	n=fscanf(F,"%ju",&um);
	fclose(F);
	if (!n)	return false;
	*maxfile = (rlim_t)um;
	return true;
#elif defined(BSD)
	int maxfiles,mib[2]={CTL_KERN, KERN_MAXFILES};
	size_t len = sizeof(maxfiles);
	if (sysctl(mib,2,&maxfiles,&len,NULL,0)==-1)
		return false;
	*maxfile = (rlim_t)maxfiles;
	return true;
#else
	return false;
#endif
}
static bool write_system_maxfiles(rlim_t maxfile)
{
#ifdef __linux__
	FILE *F;
	int n;
	if (!(F=fopen("/proc/sys/fs/file-max","w")))
		return false;
	n=fprintf(F,"%ju",(uintmax_t)maxfile);
	fclose(F);
	return !!n;
#elif defined(BSD)
	int maxfiles=(int)maxfile,mib[2]={CTL_KERN, KERN_MAXFILES};
	if (sysctl(mib,2,NULL,0,&maxfiles,sizeof(maxfiles))==-1)
		return false;
	return true;
#else
	return false;
#endif
}

static bool set_ulimit(void)
{
	rlim_t fdmax,fdmin_system,cur_lim=0;
	int n;

	if (!params.maxfiles)
	{
		// 4 fds per tamper connection (2 pipe + 2 socket), 6 fds for tcp proxy connection (4 pipe + 2 socket), 2 fds (2 socket) for nosplice
		// additional 1/2 for unpaired remote legs sending buffers
		// 16 for listen_fd, epoll, hostlist, ...
#ifdef SPLICE_PRESENT
		fdmax = (params.nosplice ? 2 : (params.tamper && !params.tamper_start && !params.tamper_cutoff ? 4 : 6)) * params.maxconn;
#else
		fdmax = 2 * params.maxconn;
#endif
		fdmax += fdmax/2 + 16;
	}
	else
		fdmax = params.maxfiles;
	fdmin_system = fdmax + 4096;
	DBGPRINT("set_ulimit : fdmax=%ju fdmin_system=%ju",(uintmax_t)fdmax,(uintmax_t)fdmin_system)

	if (!read_system_maxfiles(&cur_lim))
		return false;
	DBGPRINT("set_ulimit : current system file-max=%ju",(uintmax_t)cur_lim)
	if (cur_lim<fdmin_system)
	{
		DBGPRINT("set_ulimit : system fd limit is too low. trying to increase to %ju",(uintmax_t)fdmin_system)
		if (!write_system_maxfiles(fdmin_system))
		{
			fprintf(stderr,"could not set system-wide max file descriptors\n");
			return false;
		}
	}

	struct rlimit rlim = {fdmax,fdmax};
	n=setrlimit(RLIMIT_NOFILE, &rlim);
	if (n==-1) perror("setrlimit");
	return n!=-1;
}

struct salisten_s
{
	struct sockaddr_storage salisten;
	socklen_t salisten_len;
	int ipv6_only;
	int bind_wait_ip_left; // how much seconds left from bind_wait_ip
};
static const char *bindll_s[] = { "unwanted","no","prefer","force" };
int main(int argc, char *argv[])
{
	int i, listen_fd[MAX_BINDS], yes = 1, retval = 0, if_index, exit_v=EXIT_FAILURE;
	struct salisten_s list[MAX_BINDS];
	char ip_port[48];

	srand(time(NULL));
	parse_params(argc, argv);

	if (params.daemon) daemonize();

	if (*params.pidfile && !writepid(params.pidfile))
	{
		fprintf(stderr,"could not write pidfile\n");
		goto exiterr;
	}

	memset(&list, 0, sizeof(list));
	for(i=0;i<=params.binds_last;i++) listen_fd[i]=-1;

	for(i=0;i<=params.binds_last;i++)
	{
		VPRINT("Prepare bind %d : addr=%s iface=%s v6=%u link_local=%s wait_ifup=%d wait_ip=%d wait_ip_ll=%d",i,
			params.binds[i].bindaddr,params.binds[i].bindiface,params.binds[i].bind_if6,bindll_s[params.binds[i].bindll],
			params.binds[i].bind_wait_ifup,params.binds[i].bind_wait_ip,params.binds[i].bind_wait_ip_ll);
		if_index=0;
		if (*params.binds[i].bindiface)
		{
			if (params.binds[i].bind_wait_ifup > 0)
			{
				int sec=0;
				if (!is_interface_online(params.binds[i].bindiface))
				{
					printf("waiting for ifup of %s for up to %d second(s)...\n",params.binds[i].bindiface,params.binds[i].bind_wait_ifup);
					do
					{
						sleep(1);
						sec++;
					}
					while (!is_interface_online(params.binds[i].bindiface) && sec<params.binds[i].bind_wait_ifup);
					if (sec>=params.binds[i].bind_wait_ifup)
					{
						printf("wait timed out\n");
						goto exiterr;
					}
				}
			}
			if (!(if_index = if_nametoindex(params.binds[i].bindiface)) && params.binds[i].bind_wait_ip<=0)
			{
				printf("bad iface %s\n",params.binds[i].bindiface);
				goto exiterr;
			}
		}
		list[i].bind_wait_ip_left = params.binds[i].bind_wait_ip;
		if (*params.binds[i].bindaddr)
		{
			if (inet_pton(AF_INET, params.binds[i].bindaddr, &((struct sockaddr_in*)(&list[i].salisten))->sin_addr))
			{
				list[i].salisten.ss_family = AF_INET;
			}
			else if (inet_pton(AF_INET6, params.binds[i].bindaddr, &((struct sockaddr_in6*)(&list[i].salisten))->sin6_addr))
			{
				list[i].salisten.ss_family = AF_INET6;
				list[i].ipv6_only = 1;
			}
			else
			{
				printf("bad bind addr : %s\n", params.binds[i].bindaddr);
				goto exiterr;
			}
		}
		else
		{
			if (*params.binds[i].bindiface || params.binds[i].bindll)
			{
				bool found;
				enum bindll bindll_1;
				int sec=0;

				if (params.binds[i].bind_wait_ip > 0)
				{
					printf("waiting for ip on %s for up to %d second(s)...\n", *params.binds[i].bindiface ? params.binds[i].bindiface : "<any>", params.binds[i].bind_wait_ip);
					if (params.binds[i].bind_wait_ip_ll>0)
					{
						if (params.binds[i].bindll==prefer)
							printf("during the first %d second(s) accepting only link locals...\n", params.binds[i].bind_wait_ip_ll);
						else if (params.binds[i].bindll==unwanted)
							printf("during the first %d second(s) accepting only ipv6 globals...\n", params.binds[i].bind_wait_ip_ll);
					}
				}

				for(;;)
				{
					// allow, no, prefer, force
					bindll_1 =	(params.binds[i].bindll==prefer && sec<params.binds[i].bind_wait_ip_ll) ? force : 
							(params.binds[i].bindll==unwanted && sec<params.binds[i].bind_wait_ip_ll) ? no : 
							params.binds[i].bindll;
					if (sec && sec==params.binds[i].bind_wait_ip_ll)
					{
						if (params.binds[i].bindll==prefer)
							printf("link local address wait timeout. now accepting globals\n");
						else if (params.binds[i].bindll==unwanted)
							printf("global ipv6 address wait timeout. now accepting link locals\n");
					}
					found = find_listen_addr(&list[i].salisten,params.binds[i].bindiface,params.binds[i].bind_if6,bindll_1,&if_index);
					if (found) break;

					if (sec>=params.binds[i].bind_wait_ip)
						break;

					sleep(1);
					sec++;
				} 

				if (!found)
				{
					printf("suitable ip address not found\n");
					goto exiterr;
				}
				list[i].bind_wait_ip_left = params.binds[i].bind_wait_ip - sec;
				list[i].ipv6_only=1;
			}
			else
			{
				list[i].salisten.ss_family = AF_INET6;
				// leave sin6_addr zero
			}
		}
		if (list[i].salisten.ss_family == AF_INET6)
		{
			list[i].salisten_len = sizeof(struct sockaddr_in6);
			((struct sockaddr_in6*)(&list[i].salisten))->sin6_port = htons(params.port);
			if (is_linklocal((struct sockaddr_in6*)(&list[i].salisten)))
				((struct sockaddr_in6*)(&list[i].salisten))->sin6_scope_id = if_index;
		}
		else
		{
			list[i].salisten_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in*)(&list[i].salisten))->sin_port = htons(params.port);
		}
	}

	if (params.bind_wait_only)
	{
		printf("bind wait condition satisfied\n");
		exit_v = 0;
		goto exiterr;
	}

	if (params.proxy_type==CONN_TYPE_TRANSPARENT && !redir_init())
	{
		fprintf(stderr,"could not initialize redirector !!!\n");
		goto exiterr;
	}

	for(i=0;i<=params.binds_last;i++)
	{
		if (params.debug)
		{
			ntop46_port((struct sockaddr *)&list[i].salisten, ip_port, sizeof(ip_port));
			VPRINT("Binding %d to %s",i,ip_port);
		}

		if ((listen_fd[i] = socket(list[i].salisten.ss_family, SOCK_STREAM, 0)) == -1) {
			perror("socket");
			goto exiterr;
		}

#ifndef __OpenBSD__
// in OpenBSD always IPV6_ONLY for wildcard sockets
		if ((list[i].salisten.ss_family == AF_INET6) && setsockopt(listen_fd[i], IPPROTO_IPV6, IPV6_V6ONLY, &list[i].ipv6_only, sizeof(int)) == -1)
		{
			perror("setsockopt (IPV6_ONLY)");
			goto exiterr;
		}
#endif

		if (setsockopt(listen_fd[i], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
		{
			perror("setsockopt (SO_REUSEADDR)");
			goto exiterr;
		}
	
		//Mark that this socket can be used for transparent proxying
		//This allows the socket to accept connections for non-local IPs
		if (params.proxy_type==CONN_TYPE_TRANSPARENT)
		{
		#ifdef __linux__
			if (setsockopt(listen_fd[i], SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) == -1)
			{
				perror("setsockopt (IP_TRANSPARENT)");
				goto exiterr;
			}
		#elif defined(BSD) && defined(SO_BINDANY)
			if (setsockopt(listen_fd[i], SOL_SOCKET, SO_BINDANY, &yes, sizeof(yes)) == -1)
			{
				perror("setsockopt (SO_BINDANY)");
				goto exiterr;
			}
		#endif
		}

		if (!set_socket_buffers(listen_fd[i], params.local_rcvbuf, params.local_sndbuf))
			goto exiterr;
		if (!params.local_rcvbuf)
		{
			// HACK : dont know why but if dont set RCVBUF explicitly RCVBUF of accept()-ed socket can be very large. may be linux bug ?
			int v;
			socklen_t sz=sizeof(int);
			if (!getsockopt(listen_fd[i],SOL_SOCKET,SO_RCVBUF,&v,&sz))
			{
				v/=2;
				setsockopt(listen_fd[i],SOL_SOCKET,SO_RCVBUF,&v,sizeof(int));
			}
		}
		bool bBindBug=false;
		for(;;)
		{
			if (bind(listen_fd[i], (struct sockaddr *)&list[i].salisten, list[i].salisten_len) == -1)
			{
				// in linux strange behaviour was observed
				// just after ifup and address assignment there's short window when bind() can't bind to addresses got from getifaddrs()
				// it does not happen to transparent sockets because they can bind to any non-existend ip
				// also only ipv6 seem to be buggy this way
				if (errno==EADDRNOTAVAIL && params.proxy_type!=CONN_TYPE_TRANSPARENT && list[i].bind_wait_ip_left)
				{
					if (!bBindBug)
					{
						ntop46_port((struct sockaddr *)&list[i].salisten, ip_port, sizeof(ip_port));
						printf("address %s is not available. will retry for %d sec\n",ip_port,list[i].bind_wait_ip_left);
						bBindBug=true;
					}
					sleep(1);
					list[i].bind_wait_ip_left--;
					continue;
				}
				perror("bind");
				goto exiterr;
			}
			break;
		}
		if (listen(listen_fd[i], BACKLOG) == -1)
		{
			perror("listen");
			goto exiterr;
		}
	}

	set_ulimit();
	sec_harden();

	if (params.droproot && !droproot(params.uid,params.gid))
		goto exiterr;
	print_id();
	//splice() causes the process to receive the SIGPIPE-signal if one part (for
	//example a socket) is closed during splice(). I would rather have splice()
	//fail and return -1, so blocking SIGPIPE.
	if (block_sigpipe() == -1) {
		fprintf(stderr, "Could not block SIGPIPE signal\n");
		goto exiterr;
	}

	printf(params.proxy_type==CONN_TYPE_SOCKS ? "socks mode\n" : "transparent proxy mode\n");
	if (!params.tamper) printf("TCP proxy mode (no tampering)\n");

	signal(SIGHUP, onhup); 
	signal(SIGUSR2, onusr2);

	retval = event_loop(listen_fd,params.binds_last+1);
	exit_v = retval < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	printf("Exiting\n");
	
exiterr:
	redir_close();
	for(i=0;i<=params.binds_last;i++) if (listen_fd[i]!=-1) close(listen_fd[i]);
	cleanup_params();
	return exit_v;
}
