#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
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
#include <syslog.h>

#ifdef __ANDROID__
#include "andr/ifaddrs.h"
#else
#include <ifaddrs.h>
#endif

#include "tpws.h"

#ifdef BSD
 #include <sys/sysctl.h>
#endif

#include "tpws_conn.h"
#include "hostlist.h"
#include "ipset.h"
#include "params.h"
#include "sec.h"
#include "redirect.h"
#include "helpers.h"
#include "gzip.h"
#include "pools.h"


#define MAX_CONFIG_FILE_SIZE 16384

struct params_s params;
static bool bReload=false;

static void onhup(int sig)
{
	printf("HUP received ! Lists will be reloaded.\n");
	bReload=true;
}
void ReloadCheck()
{
	if (bReload)
	{
		ResetAllHostlistsModTime();
		if (!LoadAllHostLists())
		{
			DLOG_ERR("hostlists load failed. this is fatal.\n");
			exit(1);
		}
		ResetAllIpsetModTime();
		if (!LoadAllIpsets())
		{
			DLOG_ERR("ipset load failed. this is fatal.\n");
			exit(1);
		}
		bReload=false;
	}
}

static void onusr2(int sig)
{
	printf("\nHOSTFAIL POOL DUMP\n");

	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		printf("\nDESYNC PROFILE %d\n",dpl->dp.n);
		HostFailPoolDump(dpl->dp.hostlist_auto_fail_counters);
	}

	printf("\n");
}


static int8_t block_sigpipe(void)
{
	sigset_t sigset;
	memset(&sigset, 0, sizeof(sigset));

	//Get the old sigset, add SIGPIPE and update sigset
	if (sigprocmask(SIG_BLOCK, NULL, &sigset) == -1) {
		DLOG_PERROR("sigprocmask (get)");
		return -1;
	}

	if (sigaddset(&sigset, SIGPIPE) == -1) {
		DLOG_PERROR("sigaddset");
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
		DLOG_PERROR("sigprocmask (set)");
		return -1;
	}

	return 0;
}

static bool test_list_files()
{
	struct hostlist_file *hfile;
	struct ipset_file *ifile;

	LIST_FOREACH(hfile, &params.hostlists, next)
		if (hfile->filename && !file_open_test(hfile->filename, O_RDONLY))
		{
			DLOG_PERROR("file_open_test");
			DLOG_ERR("cannot access hostlist file '%s'\n",hfile->filename);
			return false;
		}
	LIST_FOREACH(ifile, &params.ipsets, next)
		if (ifile->filename && !file_open_test(ifile->filename, O_RDONLY))
		{
			DLOG_PERROR("file_open_test");
			DLOG_ERR("cannot access ipset file '%s'\n",ifile->filename);
			return false;
		}
	return true;
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
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
		" @<config_file>|$<config_file>\t\t; read file for options. must be the only argument. other options are ignored.\n\n"
#endif
		" --bind-addr=<v4_addr>|<v6_addr>\t; for v6 link locals append %%interface_name\n"
		" --bind-iface4=<interface_name>\t\t; bind to the first ipv4 addr of interface\n"
		" --bind-iface6=<interface_name>\t\t; bind to the first ipv6 addr of interface\n"
		" --bind-linklocal=no|unwanted|prefer|force ; prohibit, accept, prefer or force ipv6 link local bind\n"
		" --bind-wait-ifup=<sec>\t\t\t; wait for interface to appear and up\n"
		" --bind-wait-ip=<sec>\t\t\t; after ifup wait for ip address to appear up to N seconds\n"
		" --bind-wait-ip-linklocal=<sec>\t\t; (prefer) accept only LL first N seconds then any  (unwanted) accept only globals first N seconds then LL\n"
		" --bind-wait-only\t\t\t; wait for bind conditions satisfaction then exit. return code 0 if success.\n"
		" * multiple binds are supported. each bind-addr, bind-iface* start new bind\n"
		" --connect-bind-addr=<v4_addr>|<v6_addr> ; address for outbound connections. for v6 link locals append %%interface_name\n"
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
#if defined(__linux__) || defined(__APPLE__)
		" --local-tcp-user-timeout=<seconds>\t; set tcp user timeout for local leg (default : %d, 0 = system default)\n"
		" --remote-tcp-user-timeout=<seconds>\t; set tcp user timeout for remote leg (default : %d, 0 = system default)\n"
#endif
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
#if defined(__FreeBSD__)
		" --enable-pf\t\t\t\t; enable PF redirector support. required in FreeBSD when used with PF firewall.\n"
#endif
#if defined(__linux__)
		" --fix-seg=<int>\t\t\t; fix segmentation failures at the cost of possible slowdown. wait up to N msec (default %u)\n"
#endif
		" --debug=0|1|2|syslog|@<filename>\t; 1 and 2 means log to console and set debug level. for other targets use --debug-level.\n"
		" --debug-level=0|1|2\t\t\t; specify debug level\n"
		" --dry-run\t\t\t\t; verify parameters and exit with code 0 if successful\n"
		" --version\t\t\t\t; print version and exit\n"
		" --comment=any_text\n"
		"\nMULTI-STRATEGY:\n"
		" --new\t\t\t\t\t; begin new strategy\n"
		" --skip\t\t\t\t\t; do not use this strategy\n"
		" --filter-l3=ipv4|ipv6\t\t\t; L3 protocol filter. multiple comma separated values allowed.\n"
		" --filter-tcp=[~]port1[-port2]|*\t; TCP port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --filter-l7=[http|tls|unknown]\t\t; L6-L7 protocol filter. multiple comma separated values allowed.\n"
		" --ipset=<filename>\t\t\t; ipset include filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		" --ipset-ip=<ip_list>\t\t\t; comma separated fixed subnet list\n"
		" --ipset-exclude=<filename>\t\t; ipset exclude filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		" --ipset-exclude-ip=<ip_list>\t\t; comma separated fixed subnet list\n"
		"\nHOSTLIST FILTER:\n"
		" --hostlist=<filename>\t\t\t; only act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-domains=<domain_list>\t; comma separated fixed domain list\n"
		" --hostlist-exclude=<filename>\t\t; do not act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-exclude-domains=<domain_list> ; comma separated fixed domain list\n"
		" --hostlist-auto=<filename>\t\t; detect DPI blocks and build hostlist automatically\n"
		" --hostlist-auto-fail-threshold=<int>\t; how many failed attempts cause hostname to be added to auto hostlist (default : %d)\n"
		" --hostlist-auto-fail-time=<int>\t; all failed attemps must be within these seconds (default : %d)\n"
		" --hostlist-auto-debug=<logfile>\t; debug auto hostlist positives\n"
		"\nTAMPER:\n"
		" --split-pos=N|-N|marker+N|marker-N\t; comma separated list of split positions\n"
		"\t\t\t\t\t; markers: method,host,endhost,sld,endsld,midsld,sniext\n"
		" --split-any-protocol\t\t\t; split not only http and TLS\n"
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
		" --tlsrec=N|-N|marker+N|marker-N\t; make 2 TLS records. split records at specified position.\n"
#ifdef __linux__
		" --mss=<int>\t\t\t\t; set client MSS. forces server to split messages but significantly decreases speed !\n"
#endif
		" --tamper-start=[n]<pos>\t\t; start tampering only from specified outbound stream position. default is 0. 'n' means data block number.\n"
		" --tamper-cutoff=[n]<pos>\t\t; do not tamper anymore after specified outbound stream position. default is unlimited.\n",
#if defined(__linux__) || defined(__APPLE__)
		DEFAULT_TCP_USER_TIMEOUT_LOCAL,DEFAULT_TCP_USER_TIMEOUT_REMOTE,
#endif
#ifdef __linux__
		FIX_SEG_DEFAULT_MAX_WAIT,
#endif
		HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT, HOSTLIST_AUTO_FAIL_TIME_DEFAULT
	);
	exit(1);
}
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
static void cleanup_args()
{
	wordfree(&params.wexp);
}
#endif
static void cleanup_params(void)
{
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	cleanup_args();
#endif

	dp_list_destroy(&params.desync_profiles);

	hostlist_files_destroy(&params.hostlists);
	ipset_files_destroy(&params.ipsets);
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
		DLOG_ERR("maximum of %d binds are supported\n",MAX_BINDS);
		exit_clean(1);
	}
}
static void checkbind_clean(void)
{
	if (params.binds_last<0)
	{
		DLOG_ERR("start new bind with --bind-addr,--bind-iface*\n");
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
		    DLOG_ERR("could not get default ttl\n");
		    exit_clean(1);
	    }
	}
}

static bool parse_httpreqpos(const char *s, struct proto_pos *sp)
{
	if (!strcmp(s, "method"))
	{
		sp->marker = PM_HTTP_METHOD;
		sp->pos=2;
	}
	else if (!strcmp(s, "host"))
	{
		sp->marker = PM_HOST;
		sp->pos=1;
	}
	else
		return false;
	return true;
}
static bool parse_tlspos(const char *s, struct proto_pos *sp)
{
	if (!strcmp(s, "sni"))
	{
		sp->marker = PM_HOST;
		sp->pos=1;
	}
	else if (!strcmp(s, "sniext"))
	{
		sp->marker = PM_SNI_EXT;
		sp->pos=1;
	}
	else if (!strcmp(s, "snisld"))
	{
		sp->marker = PM_HOST_MIDSLD;
		sp->pos=0;
	}
	else
		return false;
	return true;
}

static bool parse_int16(const char *p, int16_t *v)
{
	if (*p=='+' || *p=='-' || *p>='0' && *p<='9')
	{
		int i = atoi(p);
		*v = (int16_t)i;
		return *v==i; // check overflow
	}
	return false;
}
static bool parse_posmarker(const char *opt, uint8_t *posmarker)
{
	if (!strcmp(opt,"host"))
		*posmarker = PM_HOST;
	else if (!strcmp(opt,"endhost"))
		*posmarker = PM_HOST_END;
	else if (!strcmp(opt,"sld"))
		*posmarker = PM_HOST_SLD;
	else if (!strcmp(opt,"midsld"))
		*posmarker = PM_HOST_MIDSLD;
	else if (!strcmp(opt,"endsld"))
		*posmarker = PM_HOST_ENDSLD;
	else if (!strcmp(opt,"method"))
		*posmarker = PM_HTTP_METHOD;
	else if (!strcmp(opt,"sniext"))
		*posmarker = PM_SNI_EXT;
	else
		return false;
	return true;
}
static bool parse_split_pos(char *opt, struct proto_pos *split)
{
	if (parse_int16(opt,&split->pos))
	{
		split->marker = PM_ABS;
		return !!split->pos;
	}
	else
	{
		char c,*p=opt;
		bool b;

		for (; *opt && *opt!='+' && *opt!='-'; opt++);
		c=*opt; *opt=0;
		b=parse_posmarker(p,&split->marker);
		*opt=c;
		if (!b) return false;
		if (*opt)
			return parse_int16(opt,&split->pos);
		else
			split->pos = 0;
	}
	return true;
}
static bool parse_split_pos_list(char *opt, struct proto_pos *splits, int splits_size, int *split_count)
{
	char c,*e,*p;

	for (p=opt, *split_count=0 ; p && *split_count<splits_size ; (*split_count)++)
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}
		if (!parse_split_pos(p,splits+*split_count)) return false;
		if (e) *e++=c;
		p = e;
	}
	if (p) return false; // too much splits
	return true;
}
static void SplitDebug(void)
{
	struct desync_profile_list *dpl;
	const struct desync_profile *dp;
	int x;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		dp = &dpl->dp;
		for(x=0;x<dp->split_count;x++)
			VPRINT("profile %d multisplit %s %d\n",dp->n,posmarker_name(dp->splits[x].marker),dp->splits[x].pos);
		if (!PROTO_POS_EMPTY(&dp->tlsrec))
			VPRINT("profile %d tlsrec %s %d\n",dp->n,posmarker_name(dp->tlsrec.marker),dp->tlsrec.pos);
	}
}

static bool wf_make_l3(char *opt, bool *ipv4, bool *ipv6)
{
	char *e,*p,c;

	for (p=opt,*ipv4=*ipv6=false ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (!strcmp(p,"ipv4"))
			*ipv4 = true;
		else if (!strcmp(p,"ipv6"))
			*ipv6 = true;
		else return false;

		if (e) *e++=c;
		p = e;
	}
	return true;
}

static bool parse_l7_list(char *opt, uint32_t *l7)
{
	char *e,*p,c;

	for (p=opt,*l7=0 ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (!strcmp(p,"http"))
			*l7 |= L7_PROTO_HTTP;
		else if (!strcmp(p,"tls"))
			*l7 |= L7_PROTO_TLS;
		else if (!strcmp(p,"unknown"))
			*l7 |= L7_PROTO_UNKNOWN;
		else return false;

		if (e) *e++=c;
		p = e;
	}
	return true;
}

static bool parse_pf_list(char *opt, struct port_filters_head *pfl)
{
	char *e,*p,c;
	port_filter pf;
	bool b;

	for (p=opt ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		b = pf_parse(p,&pf) && port_filter_add(pfl,&pf);
		if (e) *e++=c;
		if (!b) return false;

		p = e;
	}
	return true;
}

static bool parse_domain_list(char *opt, hostlist_pool **pp)
{
	char *e,*p,c;

	for (p=opt ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (*p && !AppendHostlistItem(pp,p)) return false;

		if (e) *e++=c;
		p = e;
	}
	return true;
}

static bool parse_ip_list(char *opt, ipset *pp)
{
	char *e,*p,c;

	for (p=opt ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (*p && !AppendIpsetItem(pp,p)) return false;

		if (e) *e++=c;
		p = e;
	}
	return true;
}

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
// no static to not allow optimizer to inline this func (save stack)
void config_from_file(const char *filename)
{
	// config from a file
	char buf[MAX_CONFIG_FILE_SIZE];
	buf[0]='x';	// fake argv[0]
	buf[1]=' ';
	size_t bufsize=sizeof(buf)-3;
	if (!load_file(filename,buf+2,&bufsize))
	{
		DLOG_ERR("could not load config file '%s'\n",filename);
		exit_clean(1);
	}
	buf[bufsize+2]=0;
	// wordexp fails if it sees \t \n \r between args
	replace_char(buf,'\n',' ');
	replace_char(buf,'\r',' ');
	replace_char(buf,'\t',' ');
	if (wordexp(buf, &params.wexp, WRDE_NOCMD))
	{
		DLOG_ERR("failed to split command line options from file '%s'\n",filename);
		exit_clean(1);
	}
}
#endif

#ifndef __linux__
static bool check_oob_disorder(const struct desync_profile *dp)
{
	return !(
		dp->oob && (dp->disorder || dp->disorder_http || dp->disorder_tls) ||
		dp->oob_http && (dp->disorder || dp->disorder_http) ||
		dp->oob_tls && (dp->disorder || dp->disorder_tls));
}
#endif

void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;
	bool bSkip=false, bDry=false;
	struct hostlist_file *anon_hl = NULL, *anon_hl_exclude = NULL;
	struct ipset_file *anon_ips = NULL, *anon_ips_exclude = NULL;

	memset(&params, 0, sizeof(params));
	params.maxconn = DEFAULT_MAX_CONN;
	params.max_orphan_time = DEFAULT_MAX_ORPHAN_TIME;
	params.binds_last = -1;
#if defined(__linux__) || defined(__APPLE__)
	params.tcp_user_timeout_local = DEFAULT_TCP_USER_TIMEOUT_LOCAL;
	params.tcp_user_timeout_remote = DEFAULT_TCP_USER_TIMEOUT_REMOTE;
#endif

#if defined(__OpenBSD__) || defined(__APPLE__)
	params.pf_enable = true; // OpenBSD and MacOS have no other choice
#endif

#ifdef __linux__
	params.fix_seg_avail = socket_supports_notsent();
#endif

	LIST_INIT(&params.hostlists);
	LIST_INIT(&params.ipsets);

	if (can_drop_root())
	{
	    params.uid = params.gid = 0x7FFFFFFF; // default uid:gid
	    params.droproot = true;
	}

	struct desync_profile_list *dpl;
	struct desync_profile *dp;
	int desync_profile_count=0;
	if (!(dpl = dp_list_add(&params.desync_profiles)))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}
	dp = &dpl->dp;
	dp->n = ++desync_profile_count;

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	if (argc>=2 && (argv[1][0]=='@' || argv[1][0]=='$'))
	{
		config_from_file(argv[1]+1);
		argv=params.wexp.we_wordv;
		argc=params.wexp.we_wordc;
	}
#endif
	
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
		{ "hostlist-domains",required_argument,0,0 },// optidx=37
		{ "hostlist-exclude",required_argument,0,0 },// optidx=38
		{ "hostlist-exclude-domains",required_argument,0,0 },// optidx=39
		{ "hostlist-auto",required_argument,0,0}, // optidx=40
		{ "hostlist-auto-fail-threshold",required_argument,0,0}, // optidx=41
		{ "hostlist-auto-fail-time",required_argument,0,0},	// optidx=42
		{ "hostlist-auto-debug",required_argument,0,0}, // optidx=43
		{ "pidfile",required_argument,0,0 },// optidx=44
		{ "debug",optional_argument,0,0 },// optidx=45
		{ "debug-level",required_argument,0,0 },// optidx=46
		{ "dry-run",no_argument,0,0 },// optidx=47
		{ "version",no_argument,0,0 },// optidx=48
		{ "comment",optional_argument,0,0 },// optidx=49
		{ "local-rcvbuf",required_argument,0,0 },// optidx=50
		{ "local-sndbuf",required_argument,0,0 },// optidx=51
		{ "remote-rcvbuf",required_argument,0,0 },// optidx=52
		{ "remote-sndbuf",required_argument,0,0 },// optidx=53
		{ "socks",no_argument,0,0 },// optidx=54
		{ "no-resolve",no_argument,0,0 },// optidx=55
		{ "resolver-threads",required_argument,0,0 },// optidx=56
		{ "skip-nodelay",no_argument,0,0 },// optidx=57
		{ "tamper-start",required_argument,0,0 },// optidx=58
		{ "tamper-cutoff",required_argument,0,0 },// optidx=59
		{ "connect-bind-addr",required_argument,0,0 },// optidx=60

		{ "new",no_argument,0,0 },				// optidx=61
		{ "skip",no_argument,0,0 },				// optidx=62
		{ "filter-l3",required_argument,0,0 },			// optidx=63
		{ "filter-tcp",required_argument,0,0 },			// optidx=64
		{ "filter-l7",required_argument,0,0 },			// optidx=65
		{ "ipset",required_argument,0,0 },			// optidx=66
		{ "ipset-ip",required_argument,0,0 },			// optidx=67
		{ "ipset-exclude",required_argument,0,0 },		// optidx=68
		{ "ipset-exclude-ip",required_argument,0,0 },		// optidx=69

#if defined(__FreeBSD__)
		{ "enable-pf",no_argument,0,0 },// optidx=69
#elif defined(__APPLE__)
		{ "local-tcp-user-timeout",required_argument,0,0 },	// optidx=79
		{ "remote-tcp-user-timeout",required_argument,0,0 },	// optidx=71
#elif defined(__linux__)
		{ "local-tcp-user-timeout",required_argument,0,0 },	// optidx=70
		{ "remote-tcp-user-timeout",required_argument,0,0 },	// optidx=71
		{ "mss",required_argument,0,0 },			// optidx=72
		{ "fix-seg",optional_argument,0,0 },			// optidx=73
#ifdef SPLICE_PRESENT
		{ "nosplice",no_argument,0,0 },				// optidx=74
#endif
#endif
		{ "hostlist-auto-retrans-threshold",optional_argument,0,0}, // ignored. for nfqws command line compatibility
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v)
		{
			if (bDry)
				exit_clean(1);
			else
				exithelp_clean();
		}
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
				DLOG_ERR("invalid parameter in bind-linklocal : %s\n",optarg);
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
				DLOG_ERR("bad port number\n");
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
				DLOG_ERR("non-existent username supplied\n");
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
				DLOG_ERR("--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 14: /* maxconn */
			params.maxconn = atoi(optarg);
			if (params.maxconn <= 0 || params.maxconn > 10000)
			{
				DLOG_ERR("bad maxconn\n");
				exit_clean(1);
			}
			break;
		case 15: /* maxfiles */
			params.maxfiles = atoi(optarg);
			if (params.maxfiles < 0)
			{
				DLOG_ERR("bad maxfiles\n");
				exit_clean(1);
			}
			break;
		case 16: /* max-orphan-time */
			params.max_orphan_time = atoi(optarg);
			if (params.max_orphan_time < 0)
			{
				DLOG_ERR("bad max_orphan_time\n");
				exit_clean(1);
			}
			break;
		case 17: /* hostcase */
			dp->hostcase = true;
			params.tamper = true;
			break;
		case 18: /* hostspell */
			if (strlen(optarg) != 4)
			{
				DLOG_ERR("hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			dp->hostcase = true;
			memcpy(dp->hostspell, optarg, 4);
			params.tamper = true;
			break;
		case 19: /* hostdot */
			dp->hostdot = true;
			params.tamper = true;
			break;
		case 20: /* hostnospace */
			dp->hostnospace = true;
			params.tamper = true;
			break;
		case 21: /* hostpad */
			dp->hostpad = atoi(optarg);
			params.tamper = true;
			break;
		case 22: /* domcase */
			dp->domcase = true;
			params.tamper = true;
			break;
		case 23: /* split-http-req */
			DLOG_CONDUP("WARNING ! --split-http-req is deprecated. use --split-pos with markers.\n",MAX_SPLITS);
			if (dp->split_count>=MAX_SPLITS)
			{
				DLOG_ERR("Too much splits. max splits: %u\n",MAX_SPLITS);
				exit_clean(1);
			}
			if (!parse_httpreqpos(optarg, dp->splits + dp->split_count))
			{
				DLOG_ERR("Invalid argument for split-http-req\n");
				exit_clean(1);
			}
			dp->split_count++;
			params.tamper = true;
			break;
		case 24: /* split-tls */
			// obsolete arg
			DLOG_CONDUP("WARNING ! --split-tls is deprecated. use --split-pos with markers.\n",MAX_SPLITS);
			if (dp->split_count>=MAX_SPLITS)
			{
				DLOG_ERR("Too much splits. max splits: %u\n",MAX_SPLITS);
				exit_clean(1);
			}
			if (!parse_tlspos(optarg, dp->splits + dp->split_count))
			{
				DLOG_ERR("Invalid argument for split-tls\n");
				exit_clean(1);
			}
			dp->split_count++;
			params.tamper = true;
			break;
		case 25: /* split-pos */
			{
				int ct;
				if (!parse_split_pos_list(optarg,dp->splits+dp->split_count,MAX_SPLITS-dp->split_count,&ct))
				{
					DLOG_ERR("could not parse split pos list or too much positions (before parsing - %u, max - %u) : %s\n",dp->split_count,MAX_SPLITS,optarg);
					exit_clean(1);
				}
				dp->split_count += ct;
			}
			params.tamper = true;
			break;
		case 26: /* split-any-protocol */
			dp->split_any_protocol = true;
			break;
		case 27: /* disorder */
			if (optarg)
			{
				if (!strcmp(optarg,"http")) dp->disorder_http=true;
				else if (!strcmp(optarg,"tls")) dp->disorder_tls=true;
				else
				{
					DLOG_ERR("Invalid argument for disorder\n");
					exit_clean(1);
				}
			}
			else
				dp->disorder = true;
#ifndef __linux__
			if (!check_oob_disorder(dp))
			{
				DLOG_ERR("--oob and --disorder work simultaneously only in linux. in this system it's guaranteed to fail.\n");
				exit_clean(1);
			}
#endif
			break;
		case 28: /* oob */
			if (optarg)
			{
				if (!strcmp(optarg,"http")) dp->oob_http=true;
				else if (!strcmp(optarg,"tls")) dp->oob_tls=true;
				else
				{
					DLOG_ERR("Invalid argument for oob\n");
					exit_clean(1);
				}
			}
			else
				dp->oob = true;
#ifndef __linux__
			if (!check_oob_disorder(dp))
			{
				DLOG_ERR("--oob and --disorder work simultaneously only in linux. in this system it's guaranteed to fail.\n");
				exit_clean(1);
			}
#endif
			break;
		case 29: /* oob-data */
			{
				size_t l = strlen(optarg);
				unsigned int bt;
				if (l==1) dp->oob_byte = (uint8_t)*optarg;
				else if (l!=4 || sscanf(optarg,"0x%02X",&bt)!=1)
				{
					DLOG_ERR("Invalid argument for oob-data\n");
					exit_clean(1);
				}
				else dp->oob_byte = (uint8_t)bt;
			}
			break;
		case 30: /* methodspace */
			dp->methodspace = true;
			params.tamper = true;
			break;
		case 31: /* methodeol */
			dp->methodeol = true;
			params.tamper = true;
			break;
		case 32: /* hosttab */
			dp->hosttab = true;
			params.tamper = true;
			break;
		case 33: /* unixeol */
			dp->unixeol = true;
			params.tamper = true;
			break;
		case 34: /* tlsrec */
			if (!parse_split_pos(optarg, &dp->tlsrec) && !parse_tlspos(optarg, &dp->tlsrec))
			{
				DLOG_ERR("Invalid argument for tlsrec\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 35: /* tlsrec-pos */
			// obsolete arg
			i = atoi(optarg);
			dp->tlsrec.marker = PM_ABS;
			dp->tlsrec.pos = (int16_t)i;
			if (!dp->tlsrec.pos || i!=dp->tlsrec.pos)
			{
				DLOG_ERR("Invalid argument for tlsrec-pos\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 36: /* hostlist */
			if (bSkip) break;
			if (!RegisterHostlist(dp, false, optarg))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 37: /* hostlist-domains */
			if (bSkip) break;
			if (!anon_hl && !(anon_hl=RegisterHostlist(dp, false, NULL)))
			{
				DLOG_ERR("failed to register anonymous hostlist\n");
				exit_clean(1);
			}
			if (!parse_domain_list(optarg, &anon_hl->hostlist))
			{
				DLOG_ERR("failed to add domains to anonymous hostlist\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 38: /* hostlist-exclude */
			if (bSkip) break;
			if (!RegisterHostlist(dp, true, optarg))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 39: /* hostlist-exclude-domains */
			if (bSkip) break;
			if (!anon_hl_exclude && !(anon_hl_exclude=RegisterHostlist(dp, true, NULL)))
			{
				DLOG_ERR("failed to register anonymous hostlist\n");
				exit_clean(1);
			}
			if (!parse_domain_list(optarg, &anon_hl_exclude->hostlist))
			{
				DLOG_ERR("failed to add domains to anonymous hostlist\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 40: /* hostlist-auto */
			if (bSkip) break;
			if (dp->hostlist_auto)
			{
				DLOG_ERR("only one auto hostlist per profile is supported\n");
				exit_clean(1);
			}
			{
				FILE *F = fopen(optarg,"a+b");
				if (!F)
				{
					DLOG_ERR("cannot create %s\n", optarg);
					exit_clean(1);
				}
				bool bGzip = is_gzip(F);
				fclose(F);
				if (bGzip)
				{
					DLOG_ERR("gzipped auto hostlists are not supported\n");
					exit_clean(1);
				}
			}
			if (!(dp->hostlist_auto=RegisterHostlist(dp, false, optarg)))
			{
				DLOG_ERR("failed to register hostlist '%s'\n", optarg);
				exit_clean(1);
			}
			params.tamper = true; // need to detect blocks and update autohostlist. cannot just slice.
			break;
		case 41: /* hostlist-auto-fail-threshold */
			dp->hostlist_auto_fail_threshold = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_threshold<1 || dp->hostlist_auto_fail_threshold>20)
			{
				DLOG_ERR("auto hostlist fail threshold must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case 42: /* hostlist-auto-fail-time */
			dp->hostlist_auto_fail_time = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_time<1)
			{
				DLOG_ERR("auto hostlist fail time is not valid\n");
				exit_clean(1);
			}
			break;
		case 43: /* hostlist-auto-debug */
			{
				FILE *F = fopen(optarg,"a+t");
				if (!F)
				{
					DLOG_ERR("cannot create %s\n", optarg);
					exit_clean(1);
				}
				fclose(F);
				strncpy(params.hostlist_auto_debuglog, optarg, sizeof(params.hostlist_auto_debuglog));
				params.hostlist_auto_debuglog[sizeof(params.hostlist_auto_debuglog) - 1] = '\0';
			}
			break;
		case 44: /* pidfile */
			strncpy(params.pidfile,optarg,sizeof(params.pidfile));
			params.pidfile[sizeof(params.pidfile)-1]='\0';
			break;
		case 45: /* debug */
			if (optarg)
			{
				if (*optarg=='@')
				{
					strncpy(params.debug_logfile,optarg+1,sizeof(params.debug_logfile));
					params.debug_logfile[sizeof(params.debug_logfile)-1] = 0;
					FILE *F = fopen(params.debug_logfile,"wt");
					if (!F)
					{
						fprintf(stderr, "cannot create %s\n", params.debug_logfile);
						exit_clean(1);
					}
					if (!params.debug) params.debug = 1;
					params.debug_target = LOG_TARGET_FILE;
				}
				else if (!strcmp(optarg,"syslog"))
				{
					if (!params.debug) params.debug = 1;
					params.debug_target = LOG_TARGET_SYSLOG;
					openlog("tpws",LOG_PID,LOG_USER);
				}
				else
				{
					params.debug = atoi(optarg);
					params.debug_target = LOG_TARGET_CONSOLE;
				}
			}
			else
			{
				params.debug = 1;
				params.debug_target = LOG_TARGET_CONSOLE;
			}
			break;
		case 46: /* debug-level */
			params.debug = atoi(optarg);
			break;
		case 47: /* dry-run */
			bDry = true;
			break;
		case 48: /* version */
			exit_clean(0);
			break;
		case 49: /* comment */
			break;
		case 50: /* local-rcvbuf */
#ifdef __linux__
			params.local_rcvbuf = atoi(optarg)/2;
#else
			params.local_rcvbuf = atoi(optarg);
#endif
			break;
		case 51: /* local-sndbuf */
#ifdef __linux__
			params.local_sndbuf = atoi(optarg)/2;
#else
			params.local_sndbuf = atoi(optarg);
#endif
			break;
		case 52: /* remote-rcvbuf */
#ifdef __linux__
			params.remote_rcvbuf = atoi(optarg)/2;
#else
			params.remote_rcvbuf = atoi(optarg);
#endif
			break;
		case 53: /* remote-sndbuf */
#ifdef __linux__
			params.remote_sndbuf = atoi(optarg)/2;
#else
			params.remote_sndbuf = atoi(optarg);
#endif
			break;
		case 54: /* socks */
			params.proxy_type = CONN_TYPE_SOCKS;
			break;
		case 55: /* no-resolve */
			params.no_resolve = true;
			break;
		case 56: /* resolver-threads */
			params.resolver_threads = atoi(optarg);
			if (params.resolver_threads<1 || params.resolver_threads>300)
			{
				DLOG_ERR("resolver-threads must be within 1..300\n");
				exit_clean(1);
			}
			break;
		case 57: /* skip-nodelay */
			params.skip_nodelay = true;
			break;
		case 58: /* tamper-start */
			{
				const char *p=optarg;
				if (*p=='n')
				{
					dp->tamper_start_n=true;
					p++;
				}
				else
					dp->tamper_start_n=false;
				dp->tamper_start = atoi(p);
			}
			params.tamper_lim = true;
			break;
		case 59: /* tamper-cutoff */
			{
				const char *p=optarg;
				if (*p=='n')
				{
					dp->tamper_cutoff_n=true;
					p++;
				}
				else
					dp->tamper_cutoff_n=false;
				dp->tamper_cutoff = atoi(p);
			}
			params.tamper_lim = true;
			break;
		case 60: /* connect-bind-addr */
			{
				char *p = strchr(optarg,'%');
				if (p) *p++=0;
				if (inet_pton(AF_INET, optarg, &params.connect_bind4.sin_addr))
				{
					params.connect_bind4.sin_family = AF_INET;
				}
				else if (inet_pton(AF_INET6, optarg, &params.connect_bind6.sin6_addr))
				{
					params.connect_bind6.sin6_family = AF_INET6;
					if (p && *p)
					{
						// copy interface name for delayed resolution
						strncpy(params.connect_bind6_ifname,p,sizeof(params.connect_bind6_ifname));
						params.connect_bind6_ifname[sizeof(params.connect_bind6_ifname)-1]=0;
					}

				}
				else
				{
					DLOG_ERR("bad bind addr : %s\n", optarg);
					exit_clean(1);
				}
			}
			break;


		case 61: /* new */
			if (bSkip)
			{
				dp_clear(dp);
				dp_init(dp);
				dp->n = desync_profile_count;
				bSkip = false;
			}
			else
			{
				if (!(dpl = dp_list_add(&params.desync_profiles)))
				{
					DLOG_ERR("desync_profile_add: out of memory\n");
					exit_clean(1);
				}
				dp = &dpl->dp;
				dp->n = ++desync_profile_count;
			}
			anon_hl = anon_hl_exclude = NULL;
			anon_ips = anon_ips_exclude = NULL;
			break;
		case 62: /* skip */
			bSkip = true;
			break;
		case 63: /* filter-l3 */
			if (!wf_make_l3(optarg,&dp->filter_ipv4,&dp->filter_ipv6))
			{
				DLOG_ERR("bad value for --filter-l3\n");
				exit_clean(1);
			}
			break;
		case 64: /* filter-tcp */
			if (!parse_pf_list(optarg,&dp->pf_tcp))
			{
				DLOG_ERR("Invalid port filter : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 65: /* filter-l7 */
			if (!parse_l7_list(optarg,&dp->filter_l7))
			{
				DLOG_ERR("Invalid l7 filter : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 66: /* ipset */
			if (bSkip) break;
			if (!RegisterIpset(dp, false, optarg))
			{
				DLOG_ERR("failed to register ipset '%s'\n", optarg);
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 67: /* ipset-ip */
			if (bSkip) break;
			if (!anon_ips && !(anon_ips=RegisterIpset(dp, false, NULL)))
			{
				DLOG_ERR("failed to register anonymous ipset\n");
				exit_clean(1);
			}
			if (!parse_ip_list(optarg, &anon_ips->ipset))
			{
				DLOG_ERR("failed to add subnets to anonymous ipset\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 68: /* ipset-exclude */
			if (bSkip) break;
			if (!RegisterIpset(dp, true, optarg))
			{
				DLOG_ERR("failed to register ipset '%s'\n", optarg);
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 69: /* ipset-exclude-ip */
			if (bSkip) break;
			if (!anon_ips_exclude && !(anon_ips_exclude=RegisterIpset(dp, true, NULL)))
			{
				DLOG_ERR("failed to register anonymous ipset\n");
				exit_clean(1);
			}
			if (!parse_ip_list(optarg, &anon_ips_exclude->ipset))
			{
				DLOG_ERR("failed to add subnets to anonymous ipset\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;

#if defined(__FreeBSD__)
		case 70: /* enable-pf */
			params.pf_enable = true;
			break;
#elif defined(__linux__) || defined(__APPLE__)
		case 70: /* local-tcp-user-timeout */
			params.tcp_user_timeout_local = atoi(optarg);
			if (params.tcp_user_timeout_local<0 || params.tcp_user_timeout_local>86400)
			{
				DLOG_ERR("Invalid argument for tcp user timeout. must be 0..86400\n");
				exit_clean(1);
			}
			break;
		case 71: /* remote-tcp-user-timeout */
			params.tcp_user_timeout_remote = atoi(optarg);
			if (params.tcp_user_timeout_remote<0 || params.tcp_user_timeout_remote>86400)
			{
				DLOG_ERR("Invalid argument for tcp user timeout. must be 0..86400\n");
				exit_clean(1);
			}
			break;
#endif

#if defined(__linux__)
		case 72: /* mss */
			// this option does not work in any BSD and MacOS. OS may accept but it changes nothing
			dp->mss = atoi(optarg);
			if (dp->mss<88 || dp->mss>32767)
			{
				DLOG_ERR("Invalid value for MSS. Linux accepts MSS 88-32767.\n");
				exit_clean(1);
			}
			break;
		case 73: /* fix-seg */
			if (!params.fix_seg_avail)
			{
				DLOG_ERR("--fix-seg is supported since kernel 4.6\n");
				exit_clean(1);
			}
			if (optarg)
			{
				i = atoi(optarg);
				if (i < 0 || i > 1000)
				{
					DLOG_ERR("fix_seg value must be within 0..1000\n");
					exit_clean(1);
				}
				params.fix_seg = i;
			}
			else
				params.fix_seg = FIX_SEG_DEFAULT_MAX_WAIT;
			break;
#ifdef SPLICE_PRESENT
		case 74: /* nosplice */
			params.nosplice = true;
			break;
#endif
#endif
		}
	}
	if (bSkip)
	{
		LIST_REMOVE(dpl,next);
		dp_entry_destroy(dpl);
		desync_profile_count--;
	}

	if (!params.bind_wait_only && !params.port)
	{
		DLOG_ERR("Need port number\n");
		exit_clean(1);
	}
	if (params.binds_last<=0)
	{
		params.binds_last=0; // default bind to all
	}
	if (!params.resolver_threads) params.resolver_threads = 5 + params.maxconn/50;

	VPRINT("adding low-priority default empty desync profile\n");
	// add default empty profile
	if (!(dpl = dp_list_add(&params.desync_profiles)))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}

	DLOG_CONDUP("we have %d user defined desync profile(s) and default low priority profile 0\n",desync_profile_count);

	save_default_ttl();
	if (params.debug_target == LOG_TARGET_FILE && params.droproot && chown(params.debug_logfile, params.uid, -1))
		fprintf(stderr, "could not chown %s. log file may not be writable after privilege drop\n", params.debug_logfile);
	if (params.droproot && *params.hostlist_auto_debuglog && chown(params.hostlist_auto_debuglog, params.uid, -1))
		DLOG_ERR("could not chown %s. auto hostlist debug log may not be writable after privilege drop\n", params.hostlist_auto_debuglog);

#ifdef __linux__
	bool bHasMSS=false, bHasOOB=false, bHasDisorder=false;
#endif
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		dp = &dpl->dp;
		if (params.skip_nodelay && dp->split_count)
		{
			DLOG_ERR("Cannot split with --skip-nodelay\n");
			exit_clean(1);
		}
		if (params.droproot && dp->hostlist_auto && chown(dp->hostlist_auto->filename, params.uid, -1))
			DLOG_ERR("could not chown %s. auto hostlist file may not be writable after privilege drop\n", dp->hostlist_auto->filename);
#ifdef __linux__
		if (dp->mss) bHasMSS=true;
		if (dp->oob || dp->oob_http || dp->oob_tls) bHasOOB=true;
		if (dp->disorder || dp->disorder_http || dp->disorder_tls) bHasDisorder=true;
#endif
	}
#ifdef __linux__
	if (is_wsl()==1)
	{
		if (!params.nosplice) DLOG_CONDUP("WARNING ! WSL1 may have problems with splice. Consider using `--nosplice`.\n");
		if (bHasMSS) DLOG_CONDUP("WARNING ! WSL1 does not support MSS socket option. MSS will likely fail.\n");
		if (bHasOOB) DLOG_CONDUP("WARNING ! WSL1 does not support OOB. OOB will likely fail.\n");
		if (bHasDisorder) DLOG_CONDUP("WARNING ! Windows retransmits whole TCP segment. Disorder will not function properly.\n");
		fflush(stdout);
	}
#endif

	if (!LoadAllHostLists())
	{
		DLOG_ERR("hostlists load failed\n");
		exit_clean(1);
	}
	if (!LoadAllIpsets())
	{
		DLOG_ERR("ipset load failed\n");
		exit_clean(1);
	}

	VPRINT("\nlists summary:\n");
	HostlistsDebug();
	IpsetsDebug();

	VPRINT("\nsplits summary:\n");
	SplitDebug();
	VPRINT("\n");

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	// do not need args from file anymore
	cleanup_args();
#endif
	if (bDry)
	{
		DLOG_CONDUP("command line parameters verified\n");
		exit_clean(0);
	}
}


static bool find_listen_addr(struct sockaddr_storage *salisten, const char *bindiface, bool bind_if6, enum bindll bindll, int *if_index)
{
	struct ifaddrs *addrs,*a;
	bool found=false;
    
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
				         ((!*bindiface && (bindll==prefer || bindll==force)) ||
				          (*bindiface && bind_if6 && !strcmp(a->ifa_name, bindiface)))
				          &&
					 ((bindll==force && is_linklocal((struct sockaddr_in6*)a->ifa_addr)) ||
					  (bindll==prefer && ((pass==0 && is_linklocal((struct sockaddr_in6*)a->ifa_addr)) || (pass==1 && is_private6((struct sockaddr_in6*)a->ifa_addr)) || pass==2)) ||
					  (bindll==no && ((pass==0 && is_private6((struct sockaddr_in6*)a->ifa_addr)) || (pass==1 && !is_linklocal((struct sockaddr_in6*)a->ifa_addr)))) ||
					  (bindll==unwanted && ((pass==0 && is_private6((struct sockaddr_in6*)a->ifa_addr)) || (pass==1 && !is_linklocal((struct sockaddr_in6*)a->ifa_addr)) || pass==2)))
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
	if (n != 1) return false;
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
		fdmax = (rlim_t)(params.nosplice ? 2 : (params.tamper && !params.tamper_lim ? 4 : 6)) * (rlim_t)params.maxconn;
#else
		fdmax = 2 * params.maxconn;
#endif
		fdmax += fdmax/2 + 16;
	}
	else
		fdmax = params.maxfiles;
	fdmin_system = fdmax + 4096;
	DBGPRINT("set_ulimit : fdmax=%ju fdmin_system=%ju\n",(uintmax_t)fdmax,(uintmax_t)fdmin_system);

	if (!read_system_maxfiles(&cur_lim))
		return false;
	DBGPRINT("set_ulimit : current system file-max=%ju\n",(uintmax_t)cur_lim);
	if (cur_lim<fdmin_system)
	{
		DBGPRINT("set_ulimit : system fd limit is too low. trying to increase to %ju\n",(uintmax_t)fdmin_system);
		if (!write_system_maxfiles(fdmin_system))
		{
			DLOG_ERR("could not set system-wide max file descriptors\n");
			return false;
		}
	}

	struct rlimit rlim = {fdmax,fdmax};
	n=setrlimit(RLIMIT_NOFILE, &rlim);
	if (n==-1) DLOG_PERROR("setrlimit");
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

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#if defined(ZAPRET_GH_VER) || defined (ZAPRET_GH_HASH)
#define PRINT_VER printf("github version %s (%s)\n\n", TOSTRING(ZAPRET_GH_VER), TOSTRING(ZAPRET_GH_HASH))
#else
#define PRINT_VER printf("self-built version %s %s\n\n", __DATE__, __TIME__)
#endif

int main(int argc, char *argv[])
{
	int i, listen_fd[MAX_BINDS], yes = 1, retval = 0, if_index, exit_v=EXIT_FAILURE;
	struct salisten_s list[MAX_BINDS];
	char ip_port[48];

	set_console_io_buffering();
	set_env_exedir(argv[0]);
	srand(time(NULL));
	mask_from_preflen6_prepare();

	PRINT_VER;

	parse_params(argc, argv);
	argv=NULL; argc=0;

	if (params.daemon) daemonize();

	if (*params.pidfile && !writepid(params.pidfile))
	{
		DLOG_ERR("could not write pidfile\n");
		goto exiterr;
	}

	memset(&list, 0, sizeof(list));
	for(i=0;i<=params.binds_last;i++) listen_fd[i]=-1;

	for(i=0;i<=params.binds_last;i++)
	{
		VPRINT("Prepare bind %d : addr=%s iface=%s v6=%u link_local=%s wait_ifup=%d wait_ip=%d wait_ip_ll=%d\n",i,
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
					DLOG_CONDUP("waiting for ifup of %s for up to %d second(s)...\n",params.binds[i].bindiface,params.binds[i].bind_wait_ifup);
					do
					{
						sleep(1);
						sec++;
					}
					while (!is_interface_online(params.binds[i].bindiface) && sec<params.binds[i].bind_wait_ifup);
					if (sec>=params.binds[i].bind_wait_ifup)
					{
						DLOG_CONDUP("wait timed out\n");
						goto exiterr;
					}
				}
			}
			if (!(if_index = if_nametoindex(params.binds[i].bindiface)) && params.binds[i].bind_wait_ip<=0)
			{
				DLOG_CONDUP("bad iface %s\n",params.binds[i].bindiface);
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
				DLOG_CONDUP("bad bind addr : %s\n", params.binds[i].bindaddr);
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
					DLOG_CONDUP("waiting for ip on %s for up to %d second(s)...\n", *params.binds[i].bindiface ? params.binds[i].bindiface : "<any>", params.binds[i].bind_wait_ip);
					if (params.binds[i].bind_wait_ip_ll>0)
					{
						if (params.binds[i].bindll==prefer)
							DLOG_CONDUP("during the first %d second(s) accepting only link locals...\n", params.binds[i].bind_wait_ip_ll);
						else if (params.binds[i].bindll==unwanted)
							DLOG_CONDUP("during the first %d second(s) accepting only ipv6 globals...\n", params.binds[i].bind_wait_ip_ll);
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
							DLOG_CONDUP("link local address wait timeout. now accepting globals\n");
						else if (params.binds[i].bindll==unwanted)
							DLOG_CONDUP("global ipv6 address wait timeout. now accepting link locals\n");
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
					DLOG_CONDUP("suitable ip address not found\n");
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
		DLOG_CONDUP("bind wait condition satisfied\n");
		exit_v = 0;
		goto exiterr;
	}

	if (params.proxy_type==CONN_TYPE_TRANSPARENT && !redir_init())
	{
		DLOG_ERR("could not initialize redirector !!!\n");
		goto exiterr;
	}

	for(i=0;i<=params.binds_last;i++)
	{
		if (params.debug)
		{
			ntop46_port((struct sockaddr *)&list[i].salisten, ip_port, sizeof(ip_port));
			VPRINT("Binding %d to %s\n",i,ip_port);
		}

		if ((listen_fd[i] = socket(list[i].salisten.ss_family, SOCK_STREAM, 0)) == -1) {
			DLOG_PERROR("socket");
			goto exiterr;
		}

#ifndef __OpenBSD__
// in OpenBSD always IPV6_ONLY for wildcard sockets
		if ((list[i].salisten.ss_family == AF_INET6) && setsockopt(listen_fd[i], IPPROTO_IPV6, IPV6_V6ONLY, &list[i].ipv6_only, sizeof(int)) == -1)
		{
			DLOG_PERROR("setsockopt (IPV6_ONLY)");
			goto exiterr;
		}
#endif

		if (setsockopt(listen_fd[i], SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
		{
			DLOG_PERROR("setsockopt (SO_REUSEADDR)");
			goto exiterr;
		}
	
		//Mark that this socket can be used for transparent proxying
		//This allows the socket to accept connections for non-local IPs
		if (params.proxy_type==CONN_TYPE_TRANSPARENT)
		{
		#ifdef __linux__
			if (setsockopt(listen_fd[i], SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) == -1)
			{
				DLOG_PERROR("setsockopt (IP_TRANSPARENT)");
				goto exiterr;
			}
		#elif defined(BSD) && defined(SO_BINDANY)
			if (setsockopt(listen_fd[i], SOL_SOCKET, SO_BINDANY, &yes, sizeof(yes)) == -1)
			{
				DLOG_PERROR("setsockopt (SO_BINDANY)");
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
						DLOG_CONDUP("address %s is not available. will retry for %d sec\n",ip_port,list[i].bind_wait_ip_left);
						bBindBug=true;
					}
					sleep(1);
					list[i].bind_wait_ip_left--;
					continue;
				}
				DLOG_PERROR("bind");
				goto exiterr;
			}
			break;
		}
		if (listen(listen_fd[i], BACKLOG) == -1)
		{
			DLOG_PERROR("listen");
			goto exiterr;
		}
	}

	set_ulimit();
	sec_harden();
	if (params.droproot && !droproot(params.uid,params.gid))
		goto exiterr;
#ifdef __linux__
	if (!dropcaps())
		goto exiterr;
#endif
	print_id();
	if (params.droproot && !test_list_files())
		goto exiterr;

	//splice() causes the process to receive the SIGPIPE-signal if one part (for
	//example a socket) is closed during splice(). I would rather have splice()
	//fail and return -1, so blocking SIGPIPE.
	if (block_sigpipe() == -1) {
		DLOG_ERR("Could not block SIGPIPE signal\n");
		goto exiterr;
	}

	DLOG_CONDUP(params.proxy_type==CONN_TYPE_SOCKS ? "socks mode\n" : "transparent proxy mode\n");
	if (!params.tamper) DLOG_CONDUP("TCP proxy mode (no tampering)\n");

	signal(SIGHUP, onhup); 
	signal(SIGUSR2, onusr2);

	retval = event_loop(listen_fd,params.binds_last+1);
	exit_v = retval < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	DLOG_CONDUP("Exiting\n");
	
exiterr:
	redir_close();
	for(i=0;i<=params.binds_last;i++) if (listen_fd[i]!=-1) close(listen_fd[i]);
	cleanup_params();
	return exit_v;
}
