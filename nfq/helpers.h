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
bool save_file(const char *filename, const void *buffer, size_t buffer_size);

void print_sockaddr(const struct sockaddr *sa);
void ntop46(const struct sockaddr *sa, char *str, size_t len);
void ntop46_port(const struct sockaddr *sa, char *str, size_t len);

void dbgprint_socket_buffers(int fd);
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);

uint64_t pntoh64(const void *p);
void phton64(uint8_t *p, uint64_t v);
