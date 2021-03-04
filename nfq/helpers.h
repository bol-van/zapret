#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>

#include "params.h"

void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit);
char *strncasestr(const char *s,const char *find, size_t slen);
bool load_file(const char *filename,void *buffer,size_t *buffer_size);
bool load_file_nonempty(const char *filename,void *buffer,size_t *buffer_size);

void print_sockaddr(const struct sockaddr *sa);
void dbgprint_socket_buffers(int fd);
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);
