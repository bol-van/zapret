#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <sys/utsname.h>

// this saves memory. sockaddr_storage is larger than required. it can be 128 bytes. sockaddr_in6 is 28 bytes.
typedef union
{
	sa_family_t sa_family;
	struct sockaddr_in sa4;		// size 16
	struct sockaddr_in6 sa6;	// size 28
} sockaddr_in46;

int unique_size_t(size_t *pu, int ct);
void qsort_size_t(size_t *array,size_t ct);

void rtrim(char *s);
void replace_char(char *s, char from, char to);
char *strncasestr(const char *s,const char *find, size_t slen);

bool str_ends_with(const char *s, const char *suffix);

bool load_file(const char *filename,void *buffer,size_t *buffer_size);
bool append_to_list_file(const char *filename, const char *s);

void expand_bits(void *target, const void *source, unsigned int source_bitlen, unsigned int target_bytelen);

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

void sacopy(struct sockaddr_storage *sa_dest, const struct sockaddr *sa);
void sa46copy(sockaddr_in46 *sa_dest, const struct sockaddr *sa);

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

typedef struct
{
	time_t mod_time;
	off_t size;
} file_mod_sig;
#define FILE_MOD_COMPARE(ms1,ms2) (((ms1)->mod_time==(ms2)->mod_time) && ((ms1)->size==(ms2)->size))
#define FILE_MOD_RESET(ms) memset(ms,0,sizeof(file_mod_sig))
bool file_mod_signature(const char *filename, file_mod_sig *ms);
time_t file_mod_time(const char *filename);
bool file_open_test(const char *filename, int flags);

typedef struct
{
	uint16_t from,to;
	bool neg;
} port_filter;
bool pf_in_range(uint16_t port, const port_filter *pf);
bool pf_parse(const char *s, port_filter *pf);
bool pf_is_empty(const port_filter *pf);

void set_console_io_buffering(void);
bool set_env_exedir(const char *argv0);

#ifndef IN_LOOPBACK
#define IN_LOOPBACK(a)          ((((uint32_t) (a)) & 0xff000000) == 0x7f000000)
#endif

#ifdef __GNUC__
#define IN6_EXTRACT_MAP4(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      (((const uint32_t *) (__a))[3]); }))
#else
#define IN6_EXTRACT_MAP4(a)	(((const uint32_t *) (a))[3])
#endif


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

void msleep(unsigned int ms);
#ifdef __linux__
bool socket_supports_notsent();
bool socket_has_notsent(int sfd);
bool socket_wait_notsent(int sfd, unsigned int delay_ms, unsigned int *wasted_ms);

int is_wsl();
#endif
