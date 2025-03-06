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

#define HOSTLIST_POOL_FLAG_STRICT_MATCH		1

typedef struct hostlist_pool {
	char *str;		/* key */
	uint32_t flags;		/* custom data */
	UT_hash_handle hh;	/* makes this structure hashable */
} hostlist_pool;

void HostlistPoolDestroy(hostlist_pool **pp);
bool HostlistPoolAddStr(hostlist_pool **pp, const char *s, uint32_t flags);
bool HostlistPoolAddStrLen(hostlist_pool **pp, const char *s, size_t slen, uint32_t flags);
hostlist_pool *HostlistPoolGetStr(hostlist_pool *p, const char *s);

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



struct hostlist_file {
	char *filename;
	file_mod_sig mod_sig;
	hostlist_pool *hostlist;
	LIST_ENTRY(hostlist_file) next;
};
LIST_HEAD(hostlist_files_head, hostlist_file);

struct hostlist_file *hostlist_files_add(struct hostlist_files_head *head, const char *filename);
void hostlist_files_destroy(struct hostlist_files_head *head);
struct hostlist_file *hostlist_files_search(struct hostlist_files_head *head, const char *filename);
void hostlist_files_reset_modtime(struct hostlist_files_head *list);

struct hostlist_item {
	struct hostlist_file *hfile;
	LIST_ENTRY(hostlist_item) next;
};
LIST_HEAD(hostlist_collection_head, hostlist_item);
struct hostlist_item *hostlist_collection_add(struct hostlist_collection_head *head, struct hostlist_file *hfile);
void hostlist_collection_destroy(struct hostlist_collection_head *head);
struct hostlist_item *hostlist_collection_search(struct hostlist_collection_head *head, const char *filename);
bool hostlist_collection_is_empty(const struct hostlist_collection_head *head);


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


struct ipset_file {
	char *filename;
	file_mod_sig mod_sig;
	ipset ipset;
	LIST_ENTRY(ipset_file) next;
};
LIST_HEAD(ipset_files_head, ipset_file);

struct ipset_file *ipset_files_add(struct ipset_files_head *head, const char *filename);
void ipset_files_destroy(struct ipset_files_head *head);
struct ipset_file *ipset_files_search(struct ipset_files_head *head, const char *filename);
void ipset_files_reset_modtime(struct ipset_files_head *list);

struct ipset_item {
	struct ipset_file *hfile;
	LIST_ENTRY(ipset_item) next;
};
LIST_HEAD(ipset_collection_head, ipset_item);
struct ipset_item * ipset_collection_add(struct ipset_collection_head *head, struct ipset_file *hfile);
void ipset_collection_destroy(struct ipset_collection_head *head);
struct ipset_item *ipset_collection_search(struct ipset_collection_head *head, const char *filename);
bool ipset_collection_is_empty(const struct ipset_collection_head *head);


struct port_filter_item {
	port_filter pf;
	LIST_ENTRY(port_filter_item) next;
};
LIST_HEAD(port_filters_head, port_filter_item);
bool port_filter_add(struct port_filters_head *head, const port_filter *pf);
void port_filters_destroy(struct port_filters_head *head);
bool port_filters_in_range(const struct port_filters_head *head, uint16_t port);
bool port_filters_deny_if_empty(struct port_filters_head *head);
