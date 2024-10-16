#pragma once

#include <stdbool.h>
#include <ctype.h>
#include <sys/queue.h>
#include <time.h>

#include "helpers.h"

//#define HASH_BLOOM 20
#define HASH_NONFATAL_OOM 1
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

typedef struct strpool {
    char *str;		/* key */
    UT_hash_handle hh;	/* makes this structure hashable */
} strpool;

void StrPoolDestroy(strpool **pp);
bool StrPoolAddStr(strpool **pp,const char *s);
bool StrPoolAddStrLen(strpool **pp,const char *s,size_t slen);
bool StrPoolCheckStr(strpool *p,const char *s);

struct str_list {
	char *str;
	LIST_ENTRY(str_list) next;
};
LIST_HEAD(str_list_head, str_list);

typedef struct hostfail_pool {
    char *str;		/* key */
    int counter;	/* value */
    time_t expire;	/* when to expire record (unixtime) */
    UT_hash_handle hh;	/* makes this structure hashable */
} hostfail_pool;

void HostFailPoolDestroy(hostfail_pool **pp);
hostfail_pool *HostFailPoolAdd(hostfail_pool **pp,const char *s,int fail_time);
hostfail_pool *HostFailPoolFind(hostfail_pool *p,const char *s);
void HostFailPoolDel(hostfail_pool **pp, hostfail_pool *elem);
void HostFailPoolPurge(hostfail_pool **pp);
void HostFailPoolPurgeRateLimited(hostfail_pool **pp);
void HostFailPoolDump(hostfail_pool *p);

bool strlist_add(struct str_list_head *head, const char *filename);
void strlist_destroy(struct str_list_head *head);


typedef struct ipset4 {
	struct cidr4 cidr;	/* key */
	UT_hash_handle hh;	/* makes this structure hashable */
} ipset4;
typedef struct ipset6 {
	struct cidr6 cidr;	/* key */
	UT_hash_handle hh;	/* makes this structure hashable */
} ipset6;
// combined ipset ipv4 and ipv6
typedef struct ipset {
	ipset4 *ips4;
	ipset6 *ips6;
} ipset;

#define IPSET_EMPTY(ips) (!(ips)->ips4 && !(ips)->ips6)

void ipset4Destroy(ipset4 **ipset);
bool ipset4Add(ipset4 **ipset, const struct in_addr *a, uint8_t preflen);
static inline bool ipset4AddCidr(ipset4 **ipset, const struct cidr4 *cidr)
{
	return ipset4Add(ipset,&cidr->addr,cidr->preflen);
}
bool ipset4Check(ipset4 *ipset, const struct in_addr *a, uint8_t preflen);
void ipset4Print(ipset4 *ipset);

void ipset6Destroy(ipset6 **ipset);
bool ipset6Add(ipset6 **ipset, const struct in6_addr *a, uint8_t preflen);
static inline bool ipset6AddCidr(ipset6 **ipset, const struct cidr6 *cidr)
{
	return ipset6Add(ipset,&cidr->addr,cidr->preflen);
}
bool ipset6Check(ipset6 *ipset, const struct in6_addr *a, uint8_t preflen);
void ipset6Print(ipset6 *ipset);

void ipsetDestroy(ipset *ipset);
void ipsetPrint(ipset *ipset);
