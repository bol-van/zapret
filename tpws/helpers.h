#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

char *strncasestr(const char *s,const char *find, size_t slen);

void print_sockaddr(const struct sockaddr *sa);
void print_addrinfo(const struct addrinfo *ai);
bool check_local_ip(const struct sockaddr *saddr);

bool saismapped(const struct sockaddr_in6 *sa);
bool samappedcmp(const struct sockaddr_in *sa1,const struct sockaddr_in6 *sa2);
bool sacmp(const struct sockaddr *sa1,const struct sockaddr *sa2);
uint16_t saport(const struct sockaddr *sa);
// true = was converted
bool saconvmapped(struct sockaddr_storage *a);

int set_keepalive(int fd);
int get_so_error(int fd);
