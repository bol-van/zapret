#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
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
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <time.h>

#include "tpws.h"
#include "tpws_conn.h"
#include "hostlist.h"
#include "params.h"
                     
struct params_s params;

bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	if (params.hostlist)
		printf("Will reload hostlist on next request\n");
	bHup = true;
}
// should be called in normal execution
void dohup()
{
	if (bHup)
	{
		if (params.hostlist)
		{
			if (!LoadHostList(&params.hostlist, params.hostfile))
			{
				// what will we do without hostlist ?? sure, gonna die
				exit(1);
			}
		}
		bHup = false;
	}
}



static int8_t block_sigpipe()
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
	ifr.ifr_name[IFNAMSIZ] = 0;
	ioctl(sock, SIOCGIFFLAGS, &ifr);
	close(sock);
	return !!(ifr.ifr_flags & IFF_UP);
}


static void exithelp()
{
	printf(
		" --bind-addr=<ipv4_addr>|<ipv6_addr>\n"
		" --bind-iface4=<interface_name>\t; bind to the first ipv4 addr of interface\n"
		" --bind-iface6=<interface_name>\t; bind to the first ipv6 addr of interface\n"
		" --bind-linklocal=prefer|force\t; prefer or force ipv6 link local\n"
		" --bind-wait-ifup=<sec>\t\t; wait for interface to appear and up\n"
		" --bind-wait-ip=<sec>\t\t; after ifup wait for ip address to appear up to N seconds\n"
		" --bind-wait-ip-linklocal=<sec>\t; accept only link locals first N seconds then any\n"
		" --socks\t\t\t; implement socks4/5 proxy instead of transparent proxy\n"
		" --no-resolve\t\t\t; disable socks5 remote dns ability (resolves are not async, they block all activity)\n"
		" --local-rcvbuf=<bytes>\n"
		" --local-sndbuf=<bytes>\n"
		" --remote-rcvbuf=<bytes>\n"
		" --remote-sndbuf=<bytes>\n"
		" --skip-nodelay\t\t\t; do not set TCP_NODELAY option for outgoing connections (incompatible with split options)\n"
		" --port=<port>\n"
		" --maxconn=<max_connections>\n"
		" --maxfiles=<max_open_files>\t; should be at least (X*connections+16), where X=6 in tcp proxy mode, X=4 in tampering mode\n"
		" --max-orphan-time=<sec>\t; if local leg sends something and closes and remote leg is still connecting then cancel connection attempt after N seconds\n"
		" --daemon\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t; write pid to file\n"
		" --user=<username>\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t; drop root privs\n"
		" --debug=0|1|2\t\t\t; 0(default)=silent 1=verbose 2=debug\n"
		"\nTAMPERING:\n"
		" --hostlist=<filename>\t\t; only act on host in the list (one host per line, subdomains auto apply)\n"
		" --split-http-req=method|host\n"
		" --split-pos=<numeric_offset>\t; split at specified pos. invalidates split-http-req.\n"
		" --hostcase\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostdot\t\t\t; add \".\" after Host: name\n"
		" --hosttab\t\t\t; add tab after Host: name\n"
		" --hostnospace\t\t\t; remove space after Host:\n"
		" --hostpad=<bytes>\t\t; add dummy padding headers before Host:\n"
		" --methodspace\t\t\t; add extra space after method\n"
		" --methodeol\t\t\t; add end-of-line before method\n"
		" --unixeol\t\t\t; replace 0D0A to 0A\n"
	);
	exit(1);
}
static void cleanup_params()
{
	if (params.hostlist)
	{
		StrPoolDestroy(&params.hostlist);
		params.hostlist = NULL;
	}
}
static void exithelp_clean()
{
	cleanup_params();
	exithelp();
}
static void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}
void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	params.maxconn = DEFAULT_MAX_CONN;
	params.max_orphan_time = DEFAULT_MAX_ORPHAN_TIME;

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
		{ "port",required_argument,0,0 },// optidx=9
		{ "daemon",no_argument,0,0 },// optidx=10
		{ "user",required_argument,0,0 },// optidx=11
		{ "uid",required_argument,0,0 },// optidx=12
		{ "maxconn",required_argument,0,0 },// optidx=13
		{ "maxfiles",required_argument,0,0 },// optidx=14
		{ "max-orphan-time",required_argument,0,0 },// optidx=15
		{ "hostcase",no_argument,0,0 },// optidx=16
		{ "hostspell",required_argument,0,0 },// optidx=17
		{ "hostdot",no_argument,0,0 },// optidx=18
		{ "hostnospace",no_argument,0,0 },// optidx=19
		{ "hostpad",required_argument,0,0 },// optidx=20
		{ "split-http-req",required_argument,0,0 },// optidx=21
		{ "split-pos",required_argument,0,0 },// optidx=22
		{ "methodspace",no_argument,0,0 },// optidx=23
		{ "methodeol",no_argument,0,0 },// optidx=24
		{ "hosttab",no_argument,0,0 },// optidx=25
		{ "unixeol",no_argument,0,0 },// optidx=26
		{ "hostlist",required_argument,0,0 },// optidx=27
		{ "pidfile",required_argument,0,0 },// optidx=28
		{ "debug",optional_argument,0,0 },// optidx=29
		{ "local-rcvbuf",required_argument,0,0 },// optidx=30
		{ "local-sndbuf",required_argument,0,0 },// optidx=31
		{ "remote-rcvbuf",required_argument,0,0 },// optidx=32
		{ "remote-sndbuf",required_argument,0,0 },// optidx=33
		{ "socks",no_argument,0,0 },// optidx=34
		{ "no-resolve",no_argument,0,0 },// optidx=35
		{ "skip-nodelay",no_argument,0,0 },// optidx=36
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
			strncpy(params.bindaddr, optarg, sizeof(params.bindaddr));
			params.bindaddr[sizeof(params.bindaddr) - 1] = 0;
			break;
		case 3: /* bind-iface4 */
			params.bind_if6=false;
			strncpy(params.bindiface, optarg, sizeof(params.bindiface));
			params.bindiface[sizeof(params.bindiface) - 1] = 0;
			break;
		case 4: /* bind-iface6 */
			params.bind_if6=true;
			strncpy(params.bindiface, optarg, sizeof(params.bindiface));
			params.bindiface[sizeof(params.bindiface) - 1] = 0;
			break;
		case 5: /* bind-linklocal */
			params.bindll = true;
			if (!strcmp(optarg, "force"))
				params.bindll_force=true;
			else if (strcmp(optarg, "prefer"))
			{
				fprintf(stderr, "invalid parameter in bind-linklocal : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 6: /* bind-wait-ifup */
			params.bind_wait_ifup = atoi(optarg);
			break;
		case 7: /* bind-wait-ip */
			params.bind_wait_ip = atoi(optarg);
			break;
		case 8: /* bind-wait-ip-linklocal */
			params.bind_wait_ip_ll = atoi(optarg);
			break;
		case 9: /* port */
			i = atoi(optarg);
			if (i <= 0 || i > 65535)
			{
				fprintf(stderr, "bad port number\n");
				exit_clean(1);
			}
			params.port = (uint16_t)i;
			break;
		case 10: /* daemon */
			params.daemon = true;
			break;
		case 11: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			break;
		}
		case 12: /* uid */
			params.gid=0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg,"%u:%u",&params.uid,&params.gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 13: /* maxconn */
			params.maxconn = atoi(optarg);
			if (params.maxconn <= 0 || params.maxconn > 10000)
			{
				fprintf(stderr, "bad maxconn\n");
				exit_clean(1);
			}
			break;
		case 14: /* maxfiles */
			params.maxfiles = atoi(optarg);
			if (params.maxfiles < 0)
			{
				fprintf(stderr, "bad maxfiles\n");
				exit_clean(1);
			}
			break;
		case 15: /* max-orphan-time */
			params.max_orphan_time = atoi(optarg);
			if (params.max_orphan_time < 0)
			{
				fprintf(stderr, "bad max_orphan_time\n");
				exit_clean(1);
			}
			break;
		case 16: /* hostcase */
			params.hostcase = true;
			params.tamper = true;
			break;
		case 17: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			params.tamper = true;
			break;
		case 18: /* hostdot */
			params.hostdot = true;
			params.tamper = true;
			break;
		case 19: /* hostnospace */
			params.hostnospace = true;
			params.tamper = true;
			break;
		case 20: /* hostpad */
			params.hostpad = atoi(optarg);
			params.tamper = true;
			break;
		case 21: /* split-http-req */
			if (!strcmp(optarg, "method"))
				params.split_http_req = split_method;
			else if (!strcmp(optarg, "host"))
				params.split_http_req = split_host;
			else
			{
				fprintf(stderr, "Invalid argument for split-http-req\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 22: /* split-pos */
			i = atoi(optarg);
			if (i)
				params.split_pos = i;
			else
			{
				fprintf(stderr, "Invalid argument for split-pos\n");
				exit_clean(1);
			}
			params.tamper = true;
			break;
		case 23: /* methodspace */
			params.methodspace = true;
			params.tamper = true;
			break;
		case 24: /* methodeol */
			params.methodeol = true;
			params.tamper = true;
			break;
		case 25: /* hosttab */
			params.hosttab = true;
			params.tamper = true;
			break;
		case 26: /* unixeol */
			params.unixeol = true;
			params.tamper = true;
			break;
		case 27: /* hostlist */
			if (!LoadHostList(&params.hostlist, optarg))
				exit_clean(1);
			strncpy(params.hostfile,optarg,sizeof(params.hostfile));
			params.hostfile[sizeof(params.hostfile)-1]='\0';
			params.tamper = true;
			break;
		case 28: /* pidfile */
			strncpy(params.pidfile,optarg,sizeof(params.pidfile));
			params.pidfile[sizeof(params.pidfile)-1]='\0';
			break;
		case 29:
			params.debug = optarg ? atoi(optarg) : 1;
			break;
		case 30: /* local-rcvbuf */
			params.local_rcvbuf = atoi(optarg)/2;
			break;
		case 31: /* local-sndbuf */
			params.local_sndbuf = atoi(optarg)/2;
			break;
		case 32: /* remote-rcvbuf */
			params.remote_rcvbuf = atoi(optarg)/2;
			break;
		case 33: /* remote-sndbuf */
			params.remote_sndbuf = atoi(optarg)/2;
			break;
		case 34: /* socks */
			params.proxy_type = CONN_TYPE_SOCKS;
			break;
		case 35: /* no-resolve */
			params.no_resolve = true;
			break;
		case 36: /* skip-nodelay */
			params.skip_nodelay = true;
			break;
		}
	}
	if (!params.port)
	{
		fprintf(stderr, "Need port number\n");
		exit_clean(1);
	}
	if (params.skip_nodelay && (params.split_http_req || params.split_pos))
	{
		fprintf(stderr, "Cannot split with --skip-nodelay\n");
		exit_clean(1);
	}
}

static void daemonize()
{
	int pid,fd;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	/* stdin */
	fd=dup(0);
	/* stdout */
	fd=dup(0);
	/* stderror */
}

static bool setpcap(cap_value_t *caps,int ncaps)
{
	cap_t capabilities;
	
	if (!(capabilities = cap_init()))
		return false;
	
	if (ncaps && (cap_set_flag(capabilities, CAP_PERMITTED, ncaps, caps, CAP_SET) ||
		cap_set_flag(capabilities, CAP_EFFECTIVE, ncaps, caps, CAP_SET)))
	{
		cap_free(capabilities);
		return false;
	}
	if (cap_set_proc(capabilities))
	{
		cap_free(capabilities);
		return false;
	}
	cap_free(capabilities);
	return true;
}
static int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap","r");
	if (F)
	{
		int n=fscanf(F,"%d",&maxcap);
		fclose(F);
	}
	return maxcap;
	
}
static bool dropcaps()
{
	// must have CAP_SETPCAP at the end. its required to clear bounding set
	cap_value_t cap_values[] = {CAP_SETPCAP};
	int capct=sizeof(cap_values)/sizeof(*cap_values);
	int maxcap = getmaxcap();

	if (setpcap(cap_values, capct))
	{
		for(int cap=0;cap<=maxcap;cap++)
		{
			if (cap_drop_bound(cap))
			{
				fprintf(stderr,"could not drop cap %d\n",cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(cap_values, capct - 1))
	{
		perror("setpcap");
		return false;
	}
	return true;
}
static bool droproot()
{
	if (params.uid || params.gid)
	{
		if (prctl(PR_SET_KEEPCAPS, 1L))
		{
			perror("prctl(PR_SET_KEEPCAPS): ");
			return false;
		}
		if (setgid(params.gid))
		{
			perror("setgid: ");
			return false;
		}
		if (setuid(params.uid))
		{
			perror("setuid: ");
			return false;
		}
	}
	return dropcaps();
}


static bool writepid(const char *filename)
{
	FILE *F;
	if (!(F=fopen(filename,"w")))
		return false;
	fprintf(F,"%d",getpid());
	fclose(F);
	return true;
}



static bool find_listen_addr(struct sockaddr_storage *salisten, bool bindll, int *if_index)
{
	struct ifaddrs *addrs,*a;
	bool found=false;
    
	if (getifaddrs(&addrs)<0)
		return false;

	a  = addrs;
	while (a)
	{
		if (a->ifa_addr)
		{
			if (a->ifa_addr->sa_family==AF_INET &&
			    *params.bindiface && !params.bind_if6 && !strcmp(a->ifa_name, params.bindiface))
			{
				salisten->ss_family = AF_INET;
				memcpy(&((struct sockaddr_in*)salisten)->sin_addr, &((struct sockaddr_in*)a->ifa_addr)->sin_addr, sizeof(struct in_addr));
				found=true;
				break;
			}
			// ipv6 links locals are fe80::/10
			else if (a->ifa_addr->sa_family==AF_INET6
			          &&
			         (!*params.bindiface && bindll ||
			          *params.bindiface && params.bind_if6 && !strcmp(a->ifa_name, params.bindiface))
			          &&
				 (!bindll ||
				  ((struct sockaddr_in6*)a->ifa_addr)->sin6_addr.s6_addr[0]==0xFE &&
				  (((struct sockaddr_in6*)a->ifa_addr)->sin6_addr.s6_addr[1] & 0xC0)==0x80))
			{
				salisten->ss_family = AF_INET6;
				memcpy(&((struct sockaddr_in6*)salisten)->sin6_addr, &((struct sockaddr_in6*)a->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
				if (if_index) *if_index = if_nametoindex(a->ifa_name);
				found=true;
				break;
			}
		}
		a = a->ifa_next;
	}
	freeifaddrs(addrs);
	return found;
}

static bool set_ulimit()
{
	FILE *F;
	int fdmax,fdmin_system,n,cur_lim=0;

	if (!params.maxfiles)
	{
		// 4 fds per tamper connection (2 pipe + 2 socket), 6 fds for tcp proxy connection (4 pipe + 2 socket)
		// additional 1/2 for unpaired remote legs sending buffers
		// 16 for listen_fd, epoll, hostlist, ...
		fdmax = (params.tamper ? 4 : 6) * params.maxconn;
		fdmax += fdmax/2 + 16;
	}
	else
		fdmax = params.maxfiles;
	fdmin_system = fdmax + 4096;
	DBGPRINT("set_ulimit : fdmax=%d fdmin_system=%d",fdmax,fdmin_system)

	if (!(F=fopen("/proc/sys/fs/file-max","r")))
		return false;
	n=fscanf(F,"%d",&cur_lim);
	fclose(F);
	if (!n)	return false;
	DBGPRINT("set_ulimit : current system file-max=%d",cur_lim)
	if (cur_lim<fdmin_system)
	{
		DBGPRINT("set_ulimit : system fd limit is too low. trying to increase")
		if (!(F=fopen("/proc/sys/fs/file-max","w")))
		{
			fprintf(stderr,"set_ulimit : could not open /proc/sys/fs/file-max for write\n");
			return false;
		}
		n=fprintf(F,"%d",fdmin_system);
		fclose(F);
		if (!n)
		{
			fprintf(stderr,"set_ulimit : could not write to /proc/sys/fs/file-max\n");
			return false;
		}
	}

	struct rlimit rlim = {fdmax,fdmax};
	n=setrlimit(RLIMIT_NOFILE, &rlim);
	if (n==-1) perror("setrlimit");
	return n!=-1;
}


int main(int argc, char *argv[]) {
	int listen_fd = -1;
	int yes = 1, retval = 0;
	int r;
	struct sockaddr_storage salisten;
	socklen_t salisten_len;
	int ipv6_only=0,if_index=0;

	srand(time(NULL));

	parse_params(argc, argv);

	memset(&salisten, 0, sizeof(salisten));
	if (*params.bindiface)
	{
		if (params.bind_wait_ifup > 0)
		{
			int sec=0;
			if (!is_interface_online(params.bindiface))
			{
				fprintf(stderr,"waiting ifup of %s for up to %d seconds...\n",params.bindiface,params.bind_wait_ifup);
				do
				{
					sleep(1);
					sec++;
				}
				while (!is_interface_online(params.bindiface) && sec<params.bind_wait_ifup);
				if (sec>=params.bind_wait_ifup)
				{
					printf("wait timed out\n");
					goto exiterr;
				}
			}
		}
		if (!(if_index = if_nametoindex(params.bindiface)) && params.bind_wait_ip<=0)
		{
			printf("bad iface %s\n",params.bindiface);
			goto exiterr;
		}
	}
	if (*params.bindaddr)
	{
		if (inet_pton(AF_INET, params.bindaddr, &((struct sockaddr_in*)&salisten)->sin_addr))
		{
			salisten.ss_family = AF_INET;
		}
		else if (inet_pton(AF_INET6, params.bindaddr, &((struct sockaddr_in6*)&salisten)->sin6_addr))
		{
			salisten.ss_family = AF_INET6;
			ipv6_only = 1;
		}
		else
		{
			printf("bad bind addr : %s\n", params.bindaddr);
			goto exiterr;
		}
	}
	else
	{
		if (*params.bindiface || params.bindll)
		{
			bool found;
			int sec=0;
			
			if (params.bind_wait_ip > 0)
			{
				fprintf(stderr,"waiting for ip for %d seconds...\n", params.bind_wait_ip);
				if (params.bindll && !params.bindll_force && params.bind_wait_ip_ll>0)
					fprintf(stderr,"during the first %d seconds accepting only link locals...\n", params.bind_wait_ip_ll);
			}
			
			for(;;)
			{
				found = find_listen_addr(&salisten,params.bindll,&if_index);
				if (found) break;
				
				if (params.bindll && !params.bindll_force && sec>=params.bind_wait_ip_ll)
					if (found = find_listen_addr(&salisten,false,&if_index)) break;
				
				if (sec>=params.bind_wait_ip)
					break;
				
				sleep(1);
				sec++;
			} 

			if (!found)
			{
				printf("suitable ip address not found\n");
				goto exiterr;
			}
			ipv6_only=1;
		}
		else
		{
			salisten.ss_family = AF_INET6;
			// leave sin6_addr zero
		}
	}
	if (salisten.ss_family == AF_INET6)
	{
		salisten_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6*)&salisten)->sin6_port = htons(params.port);
		((struct sockaddr_in6*)&salisten)->sin6_scope_id = if_index;
	}
	else
	{
		salisten_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in*)&salisten)->sin_port = htons(params.port);
	}

	if (params.daemon) daemonize();

	if (*params.pidfile && !writepid(params.pidfile))
	{
		fprintf(stderr,"could not write pidfile\n");
		goto exiterr;
	}

	if ((listen_fd = socket(salisten.ss_family, SOCK_STREAM, 0)) == -1) {
		perror("socket: ");
		goto exiterr;
	}

	if ((salisten.ss_family == AF_INET6) && setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) == -1)
	{
		perror("setsockopt (IPV6_ONLY): ");
		goto exiterr;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (SO_REUSEADDR): ");
		goto exiterr;
	}
	
	//Mark that this socket can be used for transparent proxying
	//This allows the socket to accept connections for non-local IPs
	if (params.proxy_type==CONN_TYPE_TRANSPARENT)
	{
		if (setsockopt(listen_fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) == -1)
		{
			perror("setsockopt (IP_TRANSPARENT): ");
			goto exiterr;
		}
	}

	if (!set_socket_buffers(listen_fd, params.local_rcvbuf, params.local_sndbuf))
		goto exiterr;
	if (!params.local_rcvbuf)
	{
		// HACK : dont know why but if dont set RCVBUF explicitly RCVBUF of accept()-ed socket can be very large. may be linux bug ?
		int v,sz;
		sz=sizeof(int);
		if (!getsockopt(listen_fd,SOL_SOCKET,SO_RCVBUF,&v,&sz))
		{
			v/=2;
			setsockopt(listen_fd,SOL_SOCKET,SO_RCVBUF,&v,sizeof(int));
		}
	}

	if (bind(listen_fd, (struct sockaddr *)&salisten, salisten_len) == -1) {
		perror("bind: ");
		goto exiterr;
	}

	set_ulimit();

	if (!droproot())
	{
		goto exiterr;
	}
	
	fprintf(stderr,"Running as UID=%u GID=%u\n",getuid(),getgid());

	if (listen(listen_fd, BACKLOG) == -1) {
		perror("listen: ");
		goto exiterr;
	}



	//splice() causes the process to receive the SIGPIPE-signal if one part (for
	//example a socket) is closed during splice(). I would rather have splice()
	//fail and return -1, so blocking SIGPIPE.
	if (block_sigpipe() == -1) {
		fprintf(stderr, "Could not block SIGPIPE signal\n");
		goto exiterr;
	}

	fprintf(stderr, "Will listen to port %d\n", params.port);
	fprintf(stderr, params.proxy_type==CONN_TYPE_SOCKS ? "socks mode\n" : "transparent proxy mode\n");
	if (!params.tamper) fprintf(stderr, "TCP proxy mode (no tampering)\n");

	signal(SIGHUP, onhup); 

	retval = event_loop(listen_fd);
	
	close(listen_fd);
	cleanup_params();

	fprintf(stderr, "Will exit\n");

	return retval < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	
exiterr:
	if (listen_fd!=-1) close(listen_fd);
	cleanup_params();
	return EXIT_FAILURE;
}
