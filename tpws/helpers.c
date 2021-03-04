#define _GNU_SOURCE

#include "helpers.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

char *strncasestr(const char *s,const char *find, size_t slen)
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

void print_sockaddr(const struct sockaddr *sa)
{
	char str[64];
	switch (sa->sa_family)
	{
	case AF_INET:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in*)sa)->sin_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		if (inet_ntop(sa->sa_family, &((struct sockaddr_in6*)sa)->sin6_addr, str, sizeof(str)))
			printf("%s:%d", str, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		printf("UNKNOWN_FAMILY_%d", sa->sa_family);
	}
}


// -1 = error,  0 = not local, 1 = local
bool check_local_ip(const struct sockaddr *saddr)
{
	struct ifaddrs *addrs,*a;
    
	if (getifaddrs(&addrs)<0) return false;
	a  = addrs;

	bool bres=false;
	while (a)
	{
		if (a->ifa_addr && sacmp(a->ifa_addr,saddr))
		{
			bres=true;
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
				printf( "%s\n", str);
			break;
		}
		ai = ai->ai_next;
	}
}



bool saismapped(const struct sockaddr_in6 *sa)
{
	// ::ffff:1.2.3.4
	return !memcmp(sa->sin6_addr.s6_addr,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",12);
}
bool samappedcmp(const struct sockaddr_in *sa1,const struct sockaddr_in6 *sa2)
{
	return saismapped(sa2) && !memcmp(sa2->sin6_addr.s6_addr+12,&sa1->sin_addr.s_addr,4);
}
bool sacmp(const struct sockaddr *sa1,const struct sockaddr *sa2)
{
	return sa1->sa_family==AF_INET && sa2->sa_family==AF_INET && !memcmp(&((struct sockaddr_in*)sa1)->sin_addr,&((struct sockaddr_in*)sa2)->sin_addr,sizeof(struct in_addr)) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET6 && !memcmp(&((struct sockaddr_in6*)sa1)->sin6_addr,&((struct sockaddr_in6*)sa2)->sin6_addr,sizeof(struct in6_addr)) ||
		sa1->sa_family==AF_INET && sa2->sa_family==AF_INET6 && samappedcmp((struct sockaddr_in*)sa1,(struct sockaddr_in6*)sa2) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET && samappedcmp((struct sockaddr_in*)sa2,(struct sockaddr_in6*)sa1);
}
uint16_t saport(const struct sockaddr *sa)
{
	return htons(sa->sa_family==AF_INET ? ((struct sockaddr_in*)sa)->sin_port :
		     sa->sa_family==AF_INET6 ? ((struct sockaddr_in6*)sa)->sin6_port : 0);
}
bool saconvmapped(struct sockaddr_storage *a)
{
	if ((a->ss_family == AF_INET6) && saismapped((struct sockaddr_in6*)a))
	{
		uint32_t ip4 = *(uint32_t*)(((struct sockaddr_in6*)a)->sin6_addr.s6_addr+12);
		uint16_t port = ((struct sockaddr_in6*)a)->sin6_port;
		a->ss_family = AF_INET;
		((struct sockaddr_in*)a)->sin_addr.s_addr = ip4;
		((struct sockaddr_in*)a)->sin_port = port;
		return true;
	}
	return false;
}



int set_keepalive(int fd)
{
	int yes=1;
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int))!=-1;
}
int get_so_error(int fd)
{
	// getsockopt(SO_ERROR) clears error
	int errn;
	socklen_t optlen = sizeof(errn);
	if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &errn, &optlen) == -1)
		errn=errno;
	return errn;
}
