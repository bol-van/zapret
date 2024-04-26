#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>

char *strncasestr(const char *s,const char *find, size_t slen);

bool append_to_list_file(const char *filename, const char *s);

void ntop46(const struct sockaddr *sa, char *str, size_t len);
void ntop46_port(const struct sockaddr *sa, char *str, size_t len);
void print_sockaddr(const struct sockaddr *sa);
void print_addrinfo(const struct addrinfo *ai);
bool check_local_ip(const struct sockaddr *saddr);

bool saismapped(const struct sockaddr_in6 *sa);
bool samappedcmp(const struct sockaddr_in *sa1,const struct sockaddr_in6 *sa2);
bool sacmp(const struct sockaddr *sa1,const struct sockaddr *sa2);
uint16_t saport(const struct sockaddr *sa);
// true = was converted
bool saconvmapped(struct sockaddr_storage *a);

bool is_localnet(const struct sockaddr *a);
bool is_linklocal(const struct sockaddr_in6* a);
bool is_private6(const struct sockaddr_in6* a);

bool set_keepalive(int fd);
bool set_ttl(int fd, int ttl);
bool set_hl(int fd, int hl);
bool set_ttl_hl(int fd, int ttl);
int get_so_error(int fd);

// alignment-safe functions
static inline uint16_t pntoh16(const uint8_t *p) {
	return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline void phton16(uint8_t *p, uint16_t v) {
	p[0] = (uint8_t)(v>>8);
	p[1] = (uint8_t)v;
}

int fprint_localtime(FILE *F);

time_t file_mod_time(const char *filename);

typedef struct
{
	uint16_t from,to;
	bool neg;
} port_filter;
bool pf_in_range(uint16_t port, const port_filter *pf);
bool pf_parse(const char *s, port_filter *pf);
