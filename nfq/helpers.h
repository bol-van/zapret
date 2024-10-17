#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// this saves memory. sockaddr_storage is larger than required. it can be 128 bytes. sockaddr_in6 is 28 bytes.
typedef union
{
	struct sockaddr_in sa4;		// size 16
	struct sockaddr_in6 sa6;	// size 28
	char _align[32];		// force 16-byte alignment for ip6_and int128 ops
} sockaddr_in46;

void rtrim(char *s);

void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit);
char *strncasestr(const char *s,const char *find, size_t slen);
bool load_file(const char *filename,void *buffer,size_t *buffer_size);
bool load_file_nonempty(const char *filename,void *buffer,size_t *buffer_size);
bool save_file(const char *filename, const void *buffer, size_t buffer_size);
bool append_to_list_file(const char *filename, const char *s);

void print_sockaddr(const struct sockaddr *sa);
void ntop46(const struct sockaddr *sa, char *str, size_t len);
void ntop46_port(const struct sockaddr *sa, char *str, size_t len);
bool pton4_port(const char *s, struct sockaddr_in *sa);
bool pton6_port(const char *s, struct sockaddr_in6 *sa);

uint16_t saport(const struct sockaddr *sa);

bool seq_within(uint32_t s, uint32_t s1, uint32_t s2);

void dbgprint_socket_buffers(int fd);
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);

uint64_t pntoh64(const void *p);
void phton64(uint8_t *p, uint64_t v);

bool ipv6_addr_is_zero(const struct in6_addr *a);

static inline uint16_t pntoh16(const uint8_t *p) {
	return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline void phton16(uint8_t *p, uint16_t v) {
	p[0] = (uint8_t)(v >> 8);
	p[1] = v & 0xFF;
}
static inline uint32_t pntoh32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool parse_hex_str(const char *s, uint8_t *pbuf, size_t *size);
void fill_pattern(uint8_t *buf,size_t bufsize,const void *pattern,size_t patsize);

int fprint_localtime(FILE *F);

time_t file_mod_time(const char *filename);

typedef struct
{
	uint16_t from,to;
	bool neg;
} port_filter;
bool pf_in_range(uint16_t port, const port_filter *pf);
bool pf_parse(const char *s, port_filter *pf);
bool pf_is_empty(const port_filter *pf);

void fill_random_bytes(uint8_t *p,size_t sz);
void fill_random_az(uint8_t *p,size_t sz);
void fill_random_az09(uint8_t *p,size_t sz);

bool cd_to_exe_dir(const char *argv0);


struct cidr4
{
	struct in_addr addr;
	uint8_t	preflen;
};
struct cidr6
{
	struct in6_addr addr;
	uint8_t	preflen;
};
void str_cidr4(char *s, size_t s_len, const struct cidr4 *cidr);
void print_cidr4(const struct cidr4 *cidr);
void str_cidr6(char *s, size_t s_len, const struct cidr6 *cidr);
void print_cidr6(const struct cidr6 *cidr);
bool parse_cidr4(char *s, struct cidr4 *cidr);
bool parse_cidr6(char *s, struct cidr6 *cidr);

static inline uint32_t mask_from_preflen(uint32_t preflen)
{
	return preflen ? preflen<32 ? ~((1 << (32-preflen)) - 1) : 0xFFFFFFFF : 0;
}
void ip6_and(const struct in6_addr * restrict a, const struct in6_addr * restrict b, struct in6_addr * restrict result);
extern struct in6_addr ip6_mask[129];
void mask_from_preflen6_prepare(void);
static inline const struct in6_addr *mask_from_preflen6(uint8_t preflen)
{
	return ip6_mask+preflen;
}
