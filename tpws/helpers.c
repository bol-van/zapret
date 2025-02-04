#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef __ANDROID__
#include "andr/ifaddrs.h"
#else
#include <ifaddrs.h>
#endif

#include "helpers.h"
#ifdef __linux__
#include <linux/tcp.h>
#endif
#include "linux_compat.h"

int unique_size_t(size_t *pu, int ct)
{
	int i, j, u;
	for (i = j = 0; j < ct; i++)
	{
		u = pu[j++];
		for (; j < ct && pu[j] == u; j++);
		pu[i] = u;
	}
	return i;
}
static int cmp_size_t(const void * a, const void * b)
{
	return *(size_t*)a < *(size_t*)b ? -1 : *(size_t*)a > *(size_t*)b;
}
void qsort_size_t(size_t *array, size_t ct)
{
	qsort(array, ct, sizeof(*array), cmp_size_t);
}


void rtrim(char *s)
{
	if (s)
		for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}

void replace_char(char *s, char from, char to)
{
	for (; *s; s++) if (*s == from) *s = to;
}

char *strncasestr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0')
	{
		len = strlen(find);
		do
		{
			do
			{
				if (slen-- < 1 || (sc = *s++) == '\0') return NULL;
			} while (toupper(c) != toupper(sc));
			if (len > slen)	return NULL;
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return (char *)s;
}

bool load_file(const char *filename, void *buffer, size_t *buffer_size)
{
	FILE *F;

	F = fopen(filename, "rb");
	if (!F) return false;

	*buffer_size = fread(buffer, 1, *buffer_size, F);
	if (ferror(F))
	{
		fclose(F);
		return false;
	}

	fclose(F);
	return true;
}

bool append_to_list_file(const char *filename, const char *s)
{
	FILE *F = fopen(filename, "at");
	if (!F) return false;
	bool bOK = fprintf(F, "%s\n", s) > 0;
	fclose(F);
	return bOK;
}

void ntop46(const struct sockaddr *sa, char *str, size_t len)
{
	if (!len) return;
	*str = 0;
	switch (sa->sa_family)
	{
	case AF_INET:
		inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, str, len);
		break;
	case AF_INET6:
		inet_ntop(sa->sa_family, &((struct sockaddr_in6*)sa)->sin6_addr, str, len);
		break;
	default:
		snprintf(str, len, "UNKNOWN_FAMILY_%d", sa->sa_family);
	}
}
void ntop46_port(const struct sockaddr *sa, char *str, size_t len)
{
	char ip[40];
	ntop46(sa, ip, sizeof(ip));
	switch (sa->sa_family)
	{
	case AF_INET:
		snprintf(str, len, "%s:%u", ip, ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		snprintf(str, len, "[%s]:%u", ip, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		snprintf(str, len, "%s", ip);
	}
}
void print_sockaddr(const struct sockaddr *sa)
{
	char ip_port[48];

	ntop46_port(sa, ip_port, sizeof(ip_port));
	printf("%s", ip_port);
}

// -1 = error,  0 = not local, 1 = local
bool check_local_ip(const struct sockaddr *saddr)
{
	struct ifaddrs *addrs, *a;

	if (is_localnet(saddr))
		return true;

	if (getifaddrs(&addrs) < 0) return false;
	a = addrs;

	bool bres = false;
	while (a)
	{
		if (a->ifa_addr && sacmp(a->ifa_addr, saddr))
		{
			bres = true;
			break;
		}
		a = a->ifa_next;
	}

	freeifaddrs(addrs);
	return bres;
}
void print_addrinfo(const struct addrinfo *ai)
{
	char str[64];
	while (ai)
	{
		switch (ai->ai_family)
		{
		case AF_INET:
			if (inet_ntop(ai->ai_family, &((struct sockaddr_in*)ai->ai_addr)->sin_addr, str, sizeof(str)))
				printf("%s\n", str);
			break;
		case AF_INET6:
			if (inet_ntop(ai->ai_family, &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr, str, sizeof(str)))
				printf("%s\n", str);
			break;
		}
		ai = ai->ai_next;
	}
}



bool saismapped(const struct sockaddr_in6 *sa)
{
	// ::ffff:1.2.3.4
	return !memcmp(sa->sin6_addr.s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12);
}
bool samappedcmp(const struct sockaddr_in *sa1, const struct sockaddr_in6 *sa2)
{
	return saismapped(sa2) && !memcmp(sa2->sin6_addr.s6_addr + 12, &sa1->sin_addr.s_addr, 4);
}
bool sacmp(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	return (sa1->sa_family == AF_INET && sa2->sa_family == AF_INET && !memcmp(&((struct sockaddr_in*)sa1)->sin_addr, &((struct sockaddr_in*)sa2)->sin_addr, sizeof(struct in_addr))) ||
		(sa1->sa_family == AF_INET6 && sa2->sa_family == AF_INET6 && !memcmp(&((struct sockaddr_in6*)sa1)->sin6_addr, &((struct sockaddr_in6*)sa2)->sin6_addr, sizeof(struct in6_addr))) ||
		(sa1->sa_family == AF_INET && sa2->sa_family == AF_INET6 && samappedcmp((struct sockaddr_in*)sa1, (struct sockaddr_in6*)sa2)) ||
		(sa1->sa_family == AF_INET6 && sa2->sa_family == AF_INET && samappedcmp((struct sockaddr_in*)sa2, (struct sockaddr_in6*)sa1));
}
uint16_t saport(const struct sockaddr *sa)
{
	return htons(sa->sa_family == AF_INET ? ((struct sockaddr_in*)sa)->sin_port :
		sa->sa_family == AF_INET6 ? ((struct sockaddr_in6*)sa)->sin6_port : 0);
}
bool saconvmapped(struct sockaddr_storage *a)
{
	if ((a->ss_family == AF_INET6) && saismapped((struct sockaddr_in6*)a))
	{
		uint32_t ip4 = IN6_EXTRACT_MAP4(((struct sockaddr_in6*)a)->sin6_addr.s6_addr);
		uint16_t port = ((struct sockaddr_in6*)a)->sin6_port;
		a->ss_family = AF_INET;
		((struct sockaddr_in*)a)->sin_addr.s_addr = ip4;
		((struct sockaddr_in*)a)->sin_port = port;
		return true;
	}
	return false;
}

void sacopy(struct sockaddr_storage *sa_dest, const struct sockaddr *sa)
{
	switch (sa->sa_family)
	{
	case AF_INET:
		memcpy(sa_dest, sa, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		memcpy(sa_dest, sa, sizeof(struct sockaddr_in6));
		break;
	default:
		sa_dest->ss_family = 0;
	}
}
void sa46copy(sockaddr_in46 *sa_dest, const struct sockaddr *sa)
{
	sacopy((struct sockaddr_storage*)sa_dest, sa);
}

bool is_localnet(const struct sockaddr *a)
{
	// match 127.0.0.0/8, 0.0.0.0, ::1, ::0, :ffff:127.0.0.0/104, :ffff:0.0.0.0
	return (a->sa_family == AF_INET && (IN_LOOPBACK(ntohl(((struct sockaddr_in *)a)->sin_addr.s_addr)) ||
		INADDR_ANY == ntohl((((struct sockaddr_in *)a)->sin_addr.s_addr)))) ||
		(a->sa_family == AF_INET6 && (IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)a)->sin6_addr) ||
			IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)a)->sin6_addr) ||
			(IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)a)->sin6_addr) && (IN_LOOPBACK(ntohl(IN6_EXTRACT_MAP4(((struct sockaddr_in6*)a)->sin6_addr.s6_addr))) ||
				INADDR_ANY == ntohl(IN6_EXTRACT_MAP4(((struct sockaddr_in6*)a)->sin6_addr.s6_addr))))));
}
bool is_linklocal(const struct sockaddr_in6 *a)
{
	// fe80::/10
	return a->sin6_addr.s6_addr[0] == 0xFE && (a->sin6_addr.s6_addr[1] & 0xC0) == 0x80;
}
bool is_private6(const struct sockaddr_in6* a)
{
	// fc00::/7
	return (a->sin6_addr.s6_addr[0] & 0xFE) == 0xFC;
}



bool set_keepalive(int fd)
{
	int yes = 1;
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) != -1;
}
bool set_ttl(int fd, int ttl)
{
	return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != -1;
}
bool set_hl(int fd, int hl)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hl, sizeof(hl)) != -1;
}
bool set_ttl_hl(int fd, int ttl)
{
	bool b1, b2;
	// try to set both but one may fail if family is wrong
	b1 = set_ttl(fd, ttl);
	b2 = set_hl(fd, ttl);
	return b1 || b2;
}
int get_so_error(int fd)
{
	// getsockopt(SO_ERROR) clears error
	int errn;
	socklen_t optlen = sizeof(errn);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errn, &optlen) == -1)
		errn = errno;
	return errn;
}

int fprint_localtime(FILE *F)
{
	struct tm t;
	time_t now;

	time(&now);
	localtime_r(&now, &t);
	return fprintf(F, "%02d.%02d.%04d %02d:%02d:%02d", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min, t.tm_sec);
}

time_t file_mod_time(const char *filename)
{
	struct stat st;
	return stat(filename, &st) == -1 ? 0 : st.st_mtime;
}
bool file_mod_signature(const char *filename, file_mod_sig *ms)
{
	struct stat st;
	if (stat(filename,&st)==-1)
	{
		FILE_MOD_RESET(ms);
		return false;
	}
	ms->mod_time=st.st_mtime;
	ms->size=st.st_size;
	return true;
}

bool file_open_test(const char *filename, int flags)
{
	int fd = open(filename,flags);
	if (fd>=0)
	{
		close(fd);
		return true;
	}
	return false;
}

bool pf_in_range(uint16_t port, const port_filter *pf)
{
	return port && (((!pf->from && !pf->to) || (port >= pf->from && port <= pf->to)) ^ pf->neg);
}
bool pf_parse(const char *s, port_filter *pf)
{
	unsigned int v1, v2;
	char c;

	if (!s) return false;
	if (*s == '*' && s[1] == 0)
	{
		pf->from = 1; pf->to = 0xFFFF;
		return true;
	}
	if (*s == '~')
	{
		pf->neg = true;
		s++;
	}
	else
		pf->neg = false;
	if (sscanf(s, "%u-%u%c", &v1, &v2, &c) == 2)
	{
		if (v1 > 65535 || v2 > 65535 || v1 > v2) return false;
		pf->from = (uint16_t)v1;
		pf->to = (uint16_t)v2;
	}
	else if (sscanf(s, "%u%c", &v1, &c) == 1)
	{
		if (v1 > 65535) return false;
		pf->to = pf->from = (uint16_t)v1;
	}
	else
		return false;
	// deny all case
	if (!pf->from && !pf->to) pf->neg = true;
	return true;
}
bool pf_is_empty(const port_filter *pf)
{
	return !pf->neg && !pf->from && !pf->to;
}


bool set_env_exedir(const char *argv0)
{
	char *s, *d;
	bool bOK = false;
	if ((s = strdup(argv0)))
	{
		if ((d = dirname(s)))
			setenv("EXEDIR", s, 1);
		free(s);
	}
	return bOK;
}


static void mask_from_preflen6_make(uint8_t plen, struct in6_addr *a)
{
	if (plen >= 128)
		memset(a->s6_addr, 0xFF, 16);
	else
	{
		uint8_t n = plen >> 3;
		memset(a->s6_addr, 0xFF, n);
		memset(a->s6_addr + n, 0x00, 16 - n);
		a->s6_addr[n] = (uint8_t)(0xFF00 >> (plen & 7));
	}
}
struct in6_addr ip6_mask[129];
void mask_from_preflen6_prepare(void)
{
	for (int plen = 0; plen <= 128; plen++) mask_from_preflen6_make(plen, ip6_mask + plen);
}

#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize("no-strict-aliasing")))
#endif
void ip6_and(const struct in6_addr * restrict a, const struct in6_addr * restrict b, struct in6_addr * restrict result)
{
	// int 128 can cause alignment segfaults because sin6_addr in struct sockaddr_in6 is 8-byte aligned, not 16-byte
	((uint64_t*)result->s6_addr)[0] = ((uint64_t*)a->s6_addr)[0] & ((uint64_t*)b->s6_addr)[0];
	((uint64_t*)result->s6_addr)[1] = ((uint64_t*)a->s6_addr)[1] & ((uint64_t*)b->s6_addr)[1];
}

void str_cidr4(char *s, size_t s_len, const struct cidr4 *cidr)
{
	char s_ip[16];
	*s_ip = 0;
	inet_ntop(AF_INET, &cidr->addr, s_ip, sizeof(s_ip));
	snprintf(s, s_len, cidr->preflen < 32 ? "%s/%u" : "%s", s_ip, cidr->preflen);
}
void print_cidr4(const struct cidr4 *cidr)
{
	char s[19];
	str_cidr4(s, sizeof(s), cidr);
	printf("%s", s);
}
void str_cidr6(char *s, size_t s_len, const struct cidr6 *cidr)
{
	char s_ip[40];
	*s_ip = 0;
	inet_ntop(AF_INET6, &cidr->addr, s_ip, sizeof(s_ip));
	snprintf(s, s_len, cidr->preflen < 128 ? "%s/%u" : "%s", s_ip, cidr->preflen);
}
void print_cidr6(const struct cidr6 *cidr)
{
	char s[44];
	str_cidr6(s, sizeof(s), cidr);
	printf("%s", s);
}
bool parse_cidr4(char *s, struct cidr4 *cidr)
{
	char *p, d;
	bool b;
	unsigned int plen;

	if ((p = strchr(s, '/')))
	{
		if (sscanf(p + 1, "%u", &plen) != 1 || plen > 32)
			return false;
		cidr->preflen = (uint8_t)plen;
		d = *p; *p = 0; // backup char
	}
	else
		cidr->preflen = 32;
	b = (inet_pton(AF_INET, s, &cidr->addr) == 1);
	if (p) *p = d; // restore char
	return b;
}
bool parse_cidr6(char *s, struct cidr6 *cidr)
{
	char *p, d;
	bool b;
	unsigned int plen;

	if ((p = strchr(s, '/')))
	{
		if (sscanf(p + 1, "%u", &plen) != 1 || plen > 128)
			return false;
		cidr->preflen = (uint8_t)plen;
		d = *p; *p = 0; // backup char
	}
	else
		cidr->preflen = 128;
	b = (inet_pton(AF_INET6, s, &cidr->addr) == 1);
	if (p) *p = d; // restore char
	return b;
}


void msleep(unsigned int ms)
{
	struct timespec time = {
		 .tv_nsec = (ms % 1000) * 1000000,
		 .tv_sec = ms / 1000
	};
	nanosleep(&time, 0);
}

#ifdef __linux__
bool socket_supports_notsent()
{
	int sfd;
	struct tcp_info_new tcpi;

	sfd = socket(AF_INET,SOCK_STREAM,0);
	if (sfd<0) return false;

	socklen_t ts = sizeof(tcpi);
	if (getsockopt(sfd, IPPROTO_TCP, TCP_INFO, (char *)&tcpi, &ts) < 0)
	{
		close(sfd);
		return false;
	}
	close(sfd);

	return ts>=((char *)&tcpi.tcpi_notsent_bytes - (char *)&tcpi + sizeof(tcpi.tcpi_notsent_bytes));
}
bool socket_has_notsent(int sfd)
{
	struct tcp_info_new tcpi;
	socklen_t ts = sizeof(tcpi);

	if (getsockopt(sfd, IPPROTO_TCP, TCP_INFO, (char *)&tcpi, &ts) < 0)
		return false;
	if (tcpi.tcpi_state != 1) // TCP_ESTABLISHED
		return false;
	size_t s = (char *)&tcpi.tcpi_notsent_bytes - (char *)&tcpi + sizeof(tcpi.tcpi_notsent_bytes);
	if (ts < s)
		// old structure version
		return false;
	return !!tcpi.tcpi_notsent_bytes;
}
bool socket_wait_notsent(int sfd, unsigned int delay_ms, unsigned int *wasted_ms)
{
	struct timespec tres;
	unsigned int mtick;

	if (wasted_ms) *wasted_ms=0;
	if (!socket_has_notsent(sfd)) return true;

	if (clock_getres(CLOCK_MONOTONIC,&tres))
	{
		tres.tv_nsec = 10000000;
		tres.tv_sec = 0;
	}
	mtick = (unsigned int)(tres.tv_sec*1000) + (unsigned int)(tres.tv_nsec/1000000);
	if (mtick<1) mtick=1;
	for(;;)
	{
		msleep(mtick);
		if (wasted_ms) *wasted_ms+=mtick;
		if (!socket_has_notsent(sfd)) return true;
		if (delay_ms<=mtick) break;
		delay_ms-=mtick;
	}
	return false;
}
#endif
