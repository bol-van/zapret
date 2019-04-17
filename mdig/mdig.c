// multi thread dns resolver
// domain list <stdin
// ip list >stdout
// errors, verbose >stderr

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define RESOLVER_EAGAIN_ATTEMPTS 3

void trimstr(char *s)
{
	char *p;
	for (p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}

const char* eai_str(int r)
{
	switch (r)
	{
	case EAI_NONAME:
		return "EAI_NONAME";
	case EAI_AGAIN:
		return "EAI_AGAIN";
	case EAI_ADDRFAMILY:
		return "EAI_ADDRFAMILY";
	case EAI_BADFLAGS:
		return "EAI_BADFLAGS";
	case EAI_FAIL:
		return "EAI_FAIL";
	case EAI_MEMORY:
		return "EAI_MEMORY";
	case EAI_FAMILY:
		return "EAI_FAMILY";
	case EAI_NODATA:
		return "EAI_NODATA";
	case EAI_SERVICE:
		return "EAI_SERVICE";
	case EAI_SOCKTYPE:
		return "EAI_SOCKTYPE";
	case EAI_SYSTEM:
		return "EAI_SYSTEM";
	default:
		return "UNKNOWN";
	}
}

#define FAMILY4 1
#define FAMILY6 2
static struct
{
	char verbose;
	char family;
	int threads;
	pthread_mutex_t flock;
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
	va_list args;
	va_start(args, format);
	pthread_mutex_lock(&glob.flock);
	vfprintf(stream, format, args);
	pthread_mutex_unlock(&glob.flock);
	va_end(args);
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

static void *t_resolver(void *arg)
{
	int tid = (int)(size_t)arg;
	int i,r;
	char dom[256];
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
			VLOG("resolving %s", dom);
			for (i = 0; i < RESOLVER_EAGAIN_ATTEMPTS; i++)
			{
				if (r = getaddrinfo(dom, NULL, &hints, &result))
				{
					ELOG("failed to resolve %s : result %d (%s)", dom, r, eai_str(r));
					if (r == EAI_AGAIN) continue; // temporary failure. should retry
				}
				else
				{
					print_addrinfo(result);
					freeaddrinfo(result);
				}
				break;
			}
		}
	}
	VLOG("ended");
	return NULL;
}

static int run_threads()
{
	int i, thread;
	pthread_t *t;

	if (pthread_mutex_init(&glob.flock, NULL) != 0)
	{
		fprintf(stderr, "mutex init failed\n");
		return 10;
	}
	t = (pthread_t*)malloc(sizeof(pthread_t)*glob.threads);
	if (!t)
	{
		fprintf(stderr, "out of memory\n");
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
	pthread_mutex_destroy(&glob.flock);
	return thread ? 0 : 12;
}

static void exithelp()
{
	printf(
		" --threads=<threads_number>\n"
		" --family=<4|6|46>\t; ipv4, ipv6, ipv4+ipv6\n"
		" --verbose\t\t; print query progress to stderr\n"
	);
	exit(1);
}
int main(int argc, char **argv)
{
	int ret, v, option_index = 0;

	static const struct option long_options[] = {
			{"threads",required_argument,0,0},	// optidx=0
			{"family",required_argument,0,0},	// optidx=1
			{"verbose",no_argument,0,0},	// optidx=2
			{"help",no_argument,0,0},	// optidx=3
			{NULL,0,NULL,0}
	};

	glob.verbose = '\0';
	glob.family = FAMILY4;
	glob.threads = 1;
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* threads */
			glob.threads = optarg ? atoi(optarg) : 0;
			if (glob.threads <= 0 || glob.threads > 100)
			{
				fprintf(stderr, "thread number must be within 1..100\n");
				return 1;
			}
			break;
		case 1: /* family */
			if (!strcmp(optarg, "4"))
				glob.family = FAMILY4;
			else if (!strcmp(optarg, "6"))
				glob.family = FAMILY6;
			else if (!strcmp(optarg, "46"))
				glob.family = FAMILY4 | FAMILY6;
			else
			{
				fprintf(stderr, "ip family must be 4,6 or 46\n");
				return 1;;
			}
			break;
		case 2: /* verbose */
			glob.verbose = '\1';
			break;
		case 3: /* help */
			exithelp();
			break;
		}
	}
	return run_threads();
}
