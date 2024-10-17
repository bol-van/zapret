#define _GNU_SOURCE
#include "pools.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DESTROY_STR_POOL(etype, ppool) \
	etype *elem, *tmp; \
	HASH_ITER(hh, *ppool, elem, tmp) { \
		free(elem->str); \
		HASH_DEL(*ppool, elem); \
		free(elem); \
	}
	
#define ADD_STR_POOL(etype, ppool, keystr, keystr_len) \
	etype *elem; \
	if (!(elem = (etype*)malloc(sizeof(etype)))) \
		return false; \
	if (!(elem->str = malloc(keystr_len + 1))) \
	{ \
		free(elem); \
		return false; \
	} \
	memcpy(elem->str, keystr, keystr_len); \
	elem->str[keystr_len] = 0; \
	oom = false; \
	HASH_ADD_KEYPTR(hh, *ppool, elem->str, strlen(elem->str), elem); \
	if (oom) \
	{ \
		free(elem->str); \
		free(elem); \
		return false; \
	}


#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)
static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

// for not zero terminated strings
bool StrPoolAddStrLen(strpool **pp, const char *s, size_t slen)
{
	ADD_STR_POOL(strpool, pp, s, slen)
	return true;
}
// for zero terminated strings
bool StrPoolAddStr(strpool **pp, const char *s)
{
	return StrPoolAddStrLen(pp, s, strlen(s));
}

bool StrPoolCheckStr(strpool *p, const char *s)
{
	strpool *elem;
	HASH_FIND_STR(p, s, elem);
	return elem != NULL;
}

void StrPoolDestroy(strpool **pp)
{
	DESTROY_STR_POOL(strpool, pp)
}



void HostFailPoolDestroy(hostfail_pool **pp)
{
	DESTROY_STR_POOL(hostfail_pool, pp)
}
hostfail_pool * HostFailPoolAdd(hostfail_pool **pp,const char *s,int fail_time)
{
	size_t slen = strlen(s);
	ADD_STR_POOL(hostfail_pool, pp, s, slen)
	elem->expire = time(NULL) + fail_time;
	elem->counter = 0;
	return elem;
}
hostfail_pool *HostFailPoolFind(hostfail_pool *p,const char *s)
{
	hostfail_pool *elem;
	HASH_FIND_STR(p, s, elem);
	return elem;
}
void HostFailPoolDel(hostfail_pool **p, hostfail_pool *elem)
{
	HASH_DEL(*p, elem);
	free(elem);
}
void HostFailPoolPurge(hostfail_pool **pp)
{
	hostfail_pool *elem, *tmp;
	time_t now = time(NULL);
	HASH_ITER(hh, *pp, elem, tmp)
	{
		if (now >= elem->expire)
		{
			free(elem->str);
			HASH_DEL(*pp, elem);
			free(elem);
		}
	}
}
static time_t host_fail_purge_prev=0;
void HostFailPoolPurgeRateLimited(hostfail_pool **pp)
{
	time_t now = time(NULL);
	// do not purge too often to save resources
	if (host_fail_purge_prev != now)
	{
		HostFailPoolPurge(pp);
		host_fail_purge_prev = now;
	}
}
void HostFailPoolDump(hostfail_pool *p)
{
	hostfail_pool *elem, *tmp;
	time_t now = time(NULL);
	HASH_ITER(hh, p, elem, tmp)
		printf("host=%s counter=%d time_left=%lld\n",elem->str,elem->counter,(long long int)elem->expire-now);
}


bool strlist_add(struct str_list_head *head, const char *filename)
{
	struct str_list *entry = malloc(sizeof(struct str_list));
	if (!entry) return false;
	entry->str = strdup(filename);
	if (!entry->str)
	{
		free(entry);
		return false;
	}
	LIST_INSERT_HEAD(head, entry, next);
	return true;
}
static void strlist_entry_destroy(struct str_list *entry)
{
	if (entry->str)	free(entry->str);
	free(entry);
}
void strlist_destroy(struct str_list_head *head)
{
	struct str_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		strlist_entry_destroy(entry);
	}
}



void ipset4Destroy(ipset4 **ipset)
{
	ipset4 *elem, *tmp;
	HASH_ITER(hh, *ipset, elem, tmp)
	{
		HASH_DEL(*ipset, elem);
		free(elem);
	}
}
bool ipset4Check(ipset4 *ipset, const struct in_addr *a, uint8_t preflen)
{
	uint32_t ip = ntohl(a->s_addr);
	struct cidr4 cidr;
	ipset4 *ips_found;

	// zero alignment bytes
	memset(&cidr,0,sizeof(cidr));
	cidr.preflen = preflen+1;
	do
	{
		cidr.preflen--;
		cidr.addr.s_addr = htonl(ip & mask_from_preflen(cidr.preflen));
		HASH_FIND(hh, ipset, &cidr, sizeof(cidr), ips_found);
		if (ips_found) return true;
	} while(cidr.preflen);

	return false;
}
bool ipset4Add(ipset4 **ipset, const struct in_addr *a, uint8_t preflen)
{
	if (preflen>32) return false;

	// avoid dups
	if (ipset4Check(*ipset, a, preflen)) return true; // already included

	struct ipset4 *entry = calloc(1,sizeof(ipset4));
	if (!entry) return false;

	entry->cidr.addr.s_addr = htonl(ntohl(a->s_addr) & mask_from_preflen(preflen));
	entry->cidr.preflen = preflen;
	oom = false;
	HASH_ADD(hh, *ipset, cidr, sizeof(entry->cidr), entry);
	if (oom) { free(entry); return false; }

	return true;
}
void ipset4Print(ipset4 *ipset)
{
	ipset4 *ips, *tmp;
	HASH_ITER(hh, ipset , ips, tmp)
	{
		print_cidr4(&ips->cidr);
		printf("\n");
	}
}

void ipset6Destroy(ipset6 **ipset)
{
	ipset6 *elem, *tmp;
	HASH_ITER(hh, *ipset, elem, tmp)
	{
		HASH_DEL(*ipset, elem);
		free(elem);
	}
}
bool ipset6Check(ipset6 *ipset, const struct in6_addr *a, uint8_t preflen)
{
	struct cidr6 cidr;
	ipset6 *ips_found;

	// zero alignment bytes
	memset(&cidr,0,sizeof(cidr));
	cidr.preflen = preflen+1;
	do
	{
		cidr.preflen--;
		ip6_and(a, mask_from_preflen6(cidr.preflen), &cidr.addr);
		HASH_FIND(hh, ipset, &cidr, sizeof(cidr), ips_found);
		if (ips_found) return true;
	} while(cidr.preflen);

	return false;
}
bool ipset6Add(ipset6 **ipset, const struct in6_addr *a, uint8_t preflen)
{
	if (preflen>128) return false;

	// avoid dups
	if (ipset6Check(*ipset, a, preflen)) return true; // already included

	struct ipset6 *entry = calloc(1,sizeof(ipset6));
	if (!entry) return false;

	ip6_and(a, mask_from_preflen6(preflen), &entry->cidr.addr);
	entry->cidr.preflen = preflen;
	oom = false;
	HASH_ADD(hh, *ipset, cidr, sizeof(entry->cidr), entry);
	if (oom) { free(entry); return false; }

	return true;
}
void ipset6Print(ipset6 *ipset)
{
	ipset6 *ips, *tmp;
	HASH_ITER(hh, ipset , ips, tmp)
	{
		print_cidr6(&ips->cidr);
		printf("\n");
	}
}

void ipsetDestroy(ipset *ipset)
{
	ipset4Destroy(&ipset->ips4);
	ipset6Destroy(&ipset->ips6);
}
void ipsetPrint(ipset *ipset)
{
	ipset4Print(ipset->ips4);
	ipset6Print(ipset->ips6);
}
