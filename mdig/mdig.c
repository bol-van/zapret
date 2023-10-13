// multi thread dns resolver
// domain list <stdin
// ip list >stdout
// errors, verbose >stderr
// transparent for valid ip or ip/subnet of allowed address family

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#ifdef _WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <time.h>

#define RESOLVER_EAGAIN_ATTEMPTS 2

static void trimstr(char *s)
{
	char *p;
	for (p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}

static const char* eai_str(int r)
{
	switch (r)
	{
	case EAI_NONAME:
		return "EAI_NONAME";
	case EAI_AGAIN:
		return "EAI_AGAIN";
#ifdef EAI_ADDRFAMILY
	case EAI_ADDRFAMILY:
		return "EAI_ADDRFAMILY";
#endif
#ifdef EAI_NODATA
	case EAI_NODATA:
		return "EAI_NODATA";
#endif
	case EAI_BADFLAGS:
		return "EAI_BADFLAGS";
	case EAI_FAIL:
		return "EAI_FAIL";
	case EAI_MEMORY:
		return "EAI_MEMORY";
	case EAI_FAMILY:
		return "EAI_FAMILY";
	case EAI_SERVICE:
		return "EAI_SERVICE";
	case EAI_SOCKTYPE:
		return "EAI_SOCKTYPE";
#ifdef EAI_SYSTEM
	case EAI_SYSTEM:
		return "EAI_SYSTEM";
#endif
	default:
		return "UNKNOWN";
	}
}

bool dom_valid(char *dom)
{
	if (!dom || *dom=='.') return false;
	for (; *dom; dom++)
		if (*dom < 0x20 || *dom>0x7F || !(*dom == '.' || *dom == '-' || *dom == '_' || *dom >= '0' && *dom <= '9' || *dom >= 'a' && *dom <= 'z' || *dom >= 'A' && *dom <= 'Z'))
			return false;
	return true;
}
void invalid_domain_beautify(char *dom)
{
	for (int i = 0; *dom && i < 64; i++, dom++)
		if (*dom < 0x20 || *dom>0x7F) *dom = '?';
	if (*dom) *dom = 0;
}

#define FAMILY4 1
#define FAMILY6 2
static struct
{
	char verbose;
	char family;
	int threads;
	time_t start_time;
	pthread_mutex_t flock;
	pthread_mutex_t slock; // stats lock
	int stats_every, stats_ct, stats_ct_ok; // stats
	FILE *F_log_resolved, *F_log_failed;
} glob;

// get next domain. return 0 if failure
static char interlocked_get_dom(char *dom, size_t size)
{
	char *s;
	pthread_mutex_lock(&glob.flock);
	s = fgets(dom, size, stdin);
	pthread_mutex_unlock(&glob.flock);
	if (!s) return 0;
	trimstr(s);
	return 1;
}
static void interlocked_fprintf(FILE *stream, const char * format, ...)
{
	if (stream)
	{
		va_list args;
		va_start(args, format);
		pthread_mutex_lock(&glob.flock);
		vfprintf(stream, format, args);
		pthread_mutex_unlock(&glob.flock);
		va_end(args);
	}
}

#define ELOG(format, ...) interlocked_fprintf(stderr,  "[%d] " format "\n", tid, ##__VA_ARGS__)
#define VLOG(format, ...) {if (glob.verbose) ELOG(format, ##__VA_ARGS__);}

static void print_addrinfo(struct addrinfo *ai)
{
	char str[64];
	while (ai)
	{
		switch (ai->ai_family)
		{
		case AF_INET:
			if (inet_ntop(ai->ai_family, &((struct sockaddr_in*)ai->ai_addr)->sin_addr, str, sizeof(str)))
				interlocked_fprintf(stdout, "%s\n", str);
			break;
		case AF_INET6:
			if (inet_ntop(ai->ai_family, &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr, str, sizeof(str)))
				interlocked_fprintf(stdout, "%s\n", str);
			break;
		}
		ai = ai->ai_next;
	}
}

static void stat_print(int ct, int ct_ok)
{
	if (glob.stats_every > 0)
	{
		time_t tm = time(NULL)-glob.start_time;
		interlocked_fprintf(stderr, "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d\n", tm/3600, (tm/60)%60, tm%60, ct, ct_ok, ct - ct_ok);
	}
}

static void stat_plus(char is_ok)
{
	int ct, ct_ok;
	if (glob.stats_every > 0)
	{
		pthread_mutex_lock(&glob.slock);
		ct = ++glob.stats_ct;
		ct_ok = glob.stats_ct_ok += !!is_ok;
		pthread_mutex_unlock(&glob.slock);

		if (!(ct % glob.stats_every)) stat_print(ct, ct_ok);
	}
}

static uint16_t GetAddrFamily(const char *saddr)
{
	struct in_addr a4;
	struct in6_addr a6;

	if (inet_pton(AF_INET, saddr, &a4))
		return AF_INET;
	else if (inet_pton(AF_INET6, saddr, &a6))
		return AF_INET6;
	return 0;
}

static void *t_resolver(void *arg)
{
	int tid = (int)(size_t)arg;
	int i, r;
	char dom[256], is_ok;
	struct addrinfo hints;
	struct addrinfo *result;

	VLOG("started");

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = (glob.family == FAMILY4) ? AF_INET : (glob.family == FAMILY6) ? AF_INET6 : AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	while (interlocked_get_dom(dom, sizeof(dom)))
	{
		if (*dom)
		{
			is_ok = 0;
			uint16_t family;
			char *s_mask, s_ip[sizeof(dom)];

			strncpy(s_ip, dom, sizeof(s_ip));
			s_mask = strchr(s_ip, '/');
			if (s_mask) *s_mask++ = 0;
			family = GetAddrFamily(s_ip);
			if (family)
			{
				if (family == AF_INET && (glob.family & FAMILY4) || family == AF_INET6 && (glob.family & FAMILY6))
				{
					unsigned int mask;
					bool mask_needed = false;
					if (s_mask)
					{
						if (sscanf(s_mask, "%u", &mask)==1)
						{
							switch (family)
							{
							case AF_INET: is_ok = mask <= 32; mask_needed = mask < 32; break;
							case AF_INET6: is_ok = mask <= 128; mask_needed = mask < 128; break;
							}
						}
					}
					else
						is_ok = 1;
					if (is_ok)
						interlocked_fprintf(stdout, mask_needed ? "%s/%u\n" : "%s\n", s_ip, mask);
					else
						VLOG("bad ip/subnet %s", dom);
				}
				else
					VLOG("wrong address family %s", s_ip);
			}
			else if (dom_valid(dom))
			{
				VLOG("resolving %s", dom);
				for (i = 0; i < RESOLVER_EAGAIN_ATTEMPTS; i++)
				{
					if ((r = getaddrinfo(dom, NULL, &hints, &result)))
					{
						VLOG("failed to resolve %s : result %d (%s)", dom, r, eai_str(r));
						if (r == EAI_AGAIN) continue; // temporary failure. should retry
					}
					else
					{
						print_addrinfo(result);
						freeaddrinfo(result);
						is_ok = 1;
					}
					break;
				}
			}
			else if (glob.verbose)
			{
				char dom2[sizeof(dom)];
				strcpy(dom2,dom);
				invalid_domain_beautify(dom2);
				VLOG("invalid domain : %s", dom2);
			}
			interlocked_fprintf(is_ok ? glob.F_log_resolved : glob.F_log_failed,"%s\n",dom);
		}
		stat_plus(is_ok);
	}
	VLOG("ended");
	return NULL;
}

static int run_threads(void)
{
	int i, thread;
	pthread_t *t;

	glob.stats_ct = glob.stats_ct_ok = 0;
	time(&glob.start_time);
	if (pthread_mutex_init(&glob.flock, NULL) != 0)
	{
		fprintf(stderr, "mutex init failed\n");
		return 10;
	}
	if (pthread_mutex_init(&glob.slock, NULL) != 0)
	{
		fprintf(stderr, "mutex init failed\n");
		pthread_mutex_destroy(&glob.flock);
		return 10;
	}
	t = (pthread_t*)malloc(sizeof(pthread_t)*glob.threads);
	if (!t)
	{
		fprintf(stderr, "out of memory\n");
		pthread_mutex_destroy(&glob.slock);
		pthread_mutex_destroy(&glob.flock);
		return 11;
	}
	for (thread = 0; thread < glob.threads; thread++)
	{
		if (pthread_create(t + thread, NULL, t_resolver, (void*)(size_t)thread))
		{
			interlocked_fprintf(stderr, "failed to create thread #%d\n", thread);
			break;
		}
	}
	for (i = 0; i < thread; i++)
	{
		pthread_join(t[i], NULL);
	}
	free(t);
	stat_print(glob.stats_ct, glob.stats_ct_ok);
	pthread_mutex_destroy(&glob.slock);
	pthread_mutex_destroy(&glob.flock);
	return thread ? 0 : 12;
}

static void exithelp(void)
{
	printf(
		" --threads=<threads_number>\n"
		" --family=<4|6|46>\t; ipv4, ipv6, ipv4+ipv6\n"
		" --verbose\t\t; print query progress to stderr\n"
		" --stats=N\t\t; print resolve stats to stderr every N domains\n"
		" --log-resolved=<file>\t; log successfully resolved domains to a file\n"
		" --log-failed=<file>\t; log failed domains to a file\n"
	);
	exit(1);
}
int main(int argc, char **argv)
{
	int r, v, option_index = 0;
	char fn1[256],fn2[256];

	static const struct option long_options[] = {
			{"help",no_argument,0,0},		// optidx=0
			{"threads",required_argument,0,0},	// optidx=1
			{"family",required_argument,0,0},	// optidx=2
			{"verbose",no_argument,0,0},		// optidx=3
			{"stats",required_argument,0,0},	// optidx=4
			{"log-resolved",required_argument,0,0},	// optidx=5
			{"log-failed",required_argument,0,0},	// optidx=6
			{NULL,0,NULL,0}
	};

	memset(&glob, 0, sizeof(glob));
	*fn1 = *fn2 = 0;
	glob.family = FAMILY4;
	glob.threads = 1;
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* help */
			exithelp();
			break;
		case 1: /* threads */
			glob.threads = optarg ? atoi(optarg) : 0;
			if (glob.threads <= 0 || glob.threads > 100)
			{
				fprintf(stderr, "thread number must be within 1..100\n");
				return 1;
			}
			break;
		case 2: /* family */
			if (!strcmp(optarg, "4"))
				glob.family = FAMILY4;
			else if (!strcmp(optarg, "6"))
				glob.family = FAMILY6;
			else if (!strcmp(optarg, "46"))
				glob.family = FAMILY4 | FAMILY6;
			else
			{
				fprintf(stderr, "ip family must be 4,6 or 46\n");
				return 1;
			}
			break;
		case 3: /* verbose */
			glob.verbose = '\1';
			break;
		case 4: /* stats */
			glob.stats_every = optarg ? atoi(optarg) : 0;
			break;
		case 5: /* log-resolved */
			strncpy(fn1,optarg,sizeof(fn1));
			fn1[sizeof(fn1)-1] = 0;
			break;
		case 6: /* log-failed */
			strncpy(fn2,optarg,sizeof(fn2));
			fn2[sizeof(fn2)-1] = 0;
			break;
		}
	}

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		fprintf(stderr,"WSAStartup failed\n");
		return 4;
	}
#endif

	if (*fn1)
	{
		glob.F_log_resolved = fopen(fn1,"wt");
		if (!glob.F_log_resolved)
		{
			fprintf(stderr,"failed to create %s\n",fn1);
			r=5; goto ex;
		}
	}
	if (*fn2)
	{
		glob.F_log_failed = fopen(fn2,"wt");
		if (!glob.F_log_failed)
		{
			fprintf(stderr,"failed to create %s\n",fn2);
			r=5; goto ex;
		}
	}

	r = run_threads();

ex:
	if (glob.F_log_resolved) fclose(glob.F_log_resolved);
	if (glob.F_log_failed) fclose(glob.F_log_failed);

	return r;
}
