#define _GNU_SOURCE

#include "helpers.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit)
{
	size_t k;
	bool bcut=false;
	if (size>limit)
	{
		size=limit;
		bcut = true;
	}
	if (!size) return;
	for (k=0;k<size;k++) DLOG("%02X ",data[k]);
	DLOG(bcut ? "... : " : ": ");
	for (k=0;k<size;k++) DLOG("%c",data[k]>=0x20 && data[k]<=0x7F ? (char)data[k] : '.');
	if (bcut) DLOG(" ...");
}

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

bool load_file(const char *filename,void *buffer,size_t *buffer_size)
{
	FILE *F;

	F = fopen(filename,"rb");
	if (!F) return false;

	*buffer_size = fread(buffer,1,*buffer_size,F);
	if (ferror(F))
	{
		fclose(F);
		return false;
	}

	fclose(F);
	return true;
}
bool load_file_nonempty(const char *filename,void *buffer,size_t *buffer_size)
{
	bool b = load_file(filename,buffer,buffer_size);
	return b && *buffer_size;
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
			printf("[%s]:%d", str, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		printf("UNKNOWN_FAMILY_%d", sa->sa_family);
	}
}

void dbgprint_socket_buffers(int fd)
{
	if (params.debug)
	{
		int v;
		socklen_t sz;
		sz=sizeof(int);
		if (!getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&v,&sz))
			DLOG("fd=%d SO_RCVBUF=%d\n",fd,v)
		sz=sizeof(int);
		if (!getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&v,&sz))
			DLOG("fd=%d SO_SNDBUF=%d\n",fd,v)
	}
}
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)
{
	DLOG("set_socket_buffers fd=%d rcvbuf=%d sndbuf=%d\n",fd,rcvbuf,sndbuf)
	if (rcvbuf && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) <0)
	{
		perror("setsockopt (SO_RCVBUF): ");
		close(fd);
		return false;
	}
	if (sndbuf && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) <0)
	{
		perror("setsockopt (SO_SNDBUF): ");
		close(fd);
		return false;
	}
	dbgprint_socket_buffers(fd);
	return true;
}
