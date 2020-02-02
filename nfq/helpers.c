#include "helpers.h"
#include <string.h>
#include <stdio.h>

const uint8_t *find_bin_const(const uint8_t *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data++;
		len--;
	}
	return NULL;
}
uint8_t *find_bin(uint8_t *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data++;
		len--;
	}
	return NULL;
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
