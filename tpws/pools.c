#define _GNU_SOURCE
#include "pools.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

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
#define ADD_HOSTLIST_POOL(etype, ppool, keystr, keystr_len, flg) \
	ADD_STR_POOL(etype,ppool,keystr,keystr_len); \
	elem->flags = flg;


#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)
static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

// for not zero terminated strings
bool HostlistPoolAddStrLen(hostlist_pool **pp, const char *s, size_t slen, uint32_t flags)
{
	ADD_HOSTLIST_POOL(hostlist_pool, pp, s, slen, flags)
	return true;
}
// for zero terminated strings
bool HostlistPoolAddStr(hostlist_pool **pp, const char *s, uint32_t flags)
{
	return HostlistPoolAddStrLen(pp, s, strlen(s), flags);
}

hostlist_pool *HostlistPoolGetStr(hostlist_pool *p, const char *s)
{
	hostlist_pool *elem;
	HASH_FIND_STR(p, s, elem);
	return elem;
}
bool HostlistPoolCheckStr(hostlist_pool *p, const char *s)
{
	return !!HostlistPoolGetStr(p,s);
}

void HostlistPoolDestroy(hostlist_pool **pp)
{
	DESTROY_STR_POOL(hostlist_pool, pp)
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
	free(entry->str);
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



struct hostlist_file *hostlist_files_add(struct hostlist_files_head *head, const char *filename)
{
	struct hostlist_file *entry = malloc(sizeof(struct hostlist_file));
	if (entry)
	{
		if (filename)
		{
			if (!(entry->filename = strdup(filename)))
			{
				free(entry);
				return false;
			}
		}
		else
			entry->filename = NULL;
		FILE_MOD_RESET(&entry->mod_sig);
		entry->hostlist = NULL;
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
static void hostlist_files_entry_destroy(struct hostlist_file *entry)
{
	free(entry->filename);
	HostlistPoolDestroy(&entry->hostlist);
	free(entry);
}
void hostlist_files_destroy(struct hostlist_files_head *head)
{
	struct hostlist_file *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		hostlist_files_entry_destroy(entry);
	}
}
struct hostlist_file *hostlist_files_search(struct hostlist_files_head *head, const char *filename)
{
	struct hostlist_file *hfile;

	LIST_FOREACH(hfile, head, next)
	{
		if (hfile->filename && !strcmp(hfile->filename,filename))
			return hfile;
	}
	return NULL;
}
void hostlist_files_reset_modtime(struct hostlist_files_head *list)
{
	struct hostlist_file *hfile;

	LIST_FOREACH(hfile, list, next)
		FILE_MOD_RESET(&hfile->mod_sig);
}

struct hostlist_item *hostlist_collection_add(struct hostlist_collection_head *head, struct hostlist_file *hfile)
{
	struct hostlist_item *entry = malloc(sizeof(struct hostlist_item));
	if (entry)
	{
		entry->hfile = hfile;
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
void hostlist_collection_destroy(struct hostlist_collection_head *head)
{
	struct hostlist_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
struct hostlist_item *hostlist_collection_search(struct hostlist_collection_head *head, const char *filename)
{
	struct hostlist_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->filename && !strcmp(item->hfile->filename,filename))
			return item;
	}
	return NULL;
}
bool hostlist_collection_is_empty(const struct hostlist_collection_head *head)
{
	const struct hostlist_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->hostlist)
			return false;
	}
	return true;
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


struct ipset_file *ipset_files_add(struct ipset_files_head *head, const char *filename)
{
	struct ipset_file *entry = malloc(sizeof(struct ipset_file));
	if (entry)
	{
		if (filename)
		{
			if (!(entry->filename = strdup(filename)))
			{
				free(entry);
				return false;
			}
		}
		else
			entry->filename = NULL;
		FILE_MOD_RESET(&entry->mod_sig);
		memset(&entry->ipset,0,sizeof(entry->ipset));
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
static void ipset_files_entry_destroy(struct ipset_file *entry)
{
	free(entry->filename);
	ipsetDestroy(&entry->ipset);
	free(entry);
}
void ipset_files_destroy(struct ipset_files_head *head)
{
	struct ipset_file *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		ipset_files_entry_destroy(entry);
	}
}
struct ipset_file *ipset_files_search(struct ipset_files_head *head, const char *filename)
{
	struct ipset_file *hfile;

	LIST_FOREACH(hfile, head, next)
	{
		if (hfile->filename && !strcmp(hfile->filename,filename))
			return hfile;
	}
	return NULL;
}
void ipset_files_reset_modtime(struct ipset_files_head *list)
{
	struct ipset_file *hfile;

	LIST_FOREACH(hfile, list, next)
		FILE_MOD_RESET(&hfile->mod_sig);
}

struct ipset_item *ipset_collection_add(struct ipset_collection_head *head, struct ipset_file *hfile)
{
	struct ipset_item *entry = malloc(sizeof(struct ipset_item));
	if (entry)
	{
		entry->hfile = hfile;
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
void ipset_collection_destroy(struct ipset_collection_head *head)
{
	struct ipset_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
struct ipset_item *ipset_collection_search(struct ipset_collection_head *head, const char *filename)
{
	struct ipset_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->filename && !strcmp(item->hfile->filename,filename))
			return item;
	}
	return NULL;
}
bool ipset_collection_is_empty(const struct ipset_collection_head *head)
{
	const struct ipset_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (!IPSET_EMPTY(&item->hfile->ipset))
			return false;
	}
	return true;
}


bool port_filter_add(struct port_filters_head *head, const port_filter *pf)
{
	struct port_filter_item *entry = malloc(sizeof(struct port_filter_item));
	if (entry)
	{
		entry->pf = *pf;
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
void port_filters_destroy(struct port_filters_head *head)
{
	struct port_filter_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
bool port_filters_in_range(const struct port_filters_head *head, uint16_t port)
{
	const struct port_filter_item *item;

	if (!LIST_FIRST(head)) return true;
	LIST_FOREACH(item, head, next)
	{
		if (pf_in_range(port, &item->pf))
			return true;
	}
	return false;
}
bool port_filters_deny_if_empty(struct port_filters_head *head)
{
	port_filter pf;
	if (LIST_FIRST(head)) return true;
	return pf_parse("0",&pf) && port_filter_add(head,&pf);
}



struct blob_item *blob_collection_add(struct blob_collection_head *head)
{
	struct blob_item *entry = calloc(1,sizeof(struct blob_item));
	if (entry)
	{
		// insert to the end
		struct blob_item *itemc,*iteml=LIST_FIRST(head);
		if (iteml)
		{
			while ((itemc=LIST_NEXT(iteml,next))) iteml = itemc;
			LIST_INSERT_AFTER(iteml, entry, next);
		}
		else
			LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
struct blob_item *blob_collection_add_blob(struct blob_collection_head *head, const void *data, size_t size, size_t size_reserve)
{
	struct blob_item *entry = calloc(1,sizeof(struct blob_item));
	if (!entry) return NULL;
	if (!(entry->data = malloc(size+size_reserve))) 
	{
		free(entry);
		return NULL;
	}
	if (data) memcpy(entry->data,data,size);
	entry->size = size;
	entry->size_buf = size+size_reserve;

	// insert to the end
	struct blob_item *itemc,*iteml=LIST_FIRST(head);
	if (iteml)
	{
		while ((itemc=LIST_NEXT(iteml,next))) iteml = itemc;
		LIST_INSERT_AFTER(iteml, entry, next);
	}
	else
		LIST_INSERT_HEAD(head, entry, next);

	return entry;
}

void blob_collection_destroy(struct blob_collection_head *head)
{
	struct blob_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry->extra);
		free(entry->extra2);
		free(entry->data);
		free(entry);
	}
}
bool blob_collection_empty(const struct blob_collection_head *head)
{
	return !LIST_FIRST(head);
}



static void ipcache_item_touch(ip_cache_item *item)
{
	time(&item->last);
}
static void ipcache_item_init(ip_cache_item *item)
{
	ipcache_item_touch(item);
	item->hostname = NULL;
}
static void ipcache_item_destroy(ip_cache_item *item)
{
	free(item->hostname);
}

static void ipcache4Destroy(ip_cache4 **ipcache)
{
	ip_cache4 *elem, *tmp;
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		HASH_DEL(*ipcache, elem);
		ipcache_item_destroy(&elem->data);
		free(elem);
	}
}
static void ipcache4Key(ip4if *key, const struct in_addr *a)
{
	memset(key,0,sizeof(*key)); // make sure everything is zero
	key->addr = *a;
}
static ip_cache4 *ipcache4Find(ip_cache4 *ipcache, const struct in_addr *a)
{
	ip_cache4 *entry;
	struct ip4if key;

	ipcache4Key(&key,a);
	HASH_FIND(hh, ipcache, &key, sizeof(key), entry);
	return entry;
}
static ip_cache4 *ipcache4Add(ip_cache4 **ipcache, const struct in_addr *a)
{
	// avoid dups
	ip_cache4 *entry = ipcache4Find(*ipcache,a);
	if (entry) return entry; // already included

	entry = malloc(sizeof(ip_cache4));
	if (!entry) return NULL;
	ipcache4Key(&entry->key,a);

	oom = false;
	HASH_ADD(hh, *ipcache, key, sizeof(entry->key), entry);
	if (oom) { free(entry); return NULL; }

	ipcache_item_init(&entry->data);

	return entry;
}
static void ipcache4Print(ip_cache4 *ipcache)
{
	char s_ip[16];
	time_t now;
	ip_cache4 *ipc, *tmp;

	time(&now);
	HASH_ITER(hh, ipcache , ipc, tmp)
	{
		*s_ip=0;
		inet_ntop(AF_INET, &ipc->key.addr, s_ip, sizeof(s_ip));
		printf("%s : hostname=%s now=last+%llu\n", s_ip, ipc->data.hostname ? ipc->data.hostname : "", (unsigned long long)(now-ipc->data.last));
	}
}

static void ipcache6Destroy(ip_cache6 **ipcache)
{
	ip_cache6 *elem, *tmp;
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		HASH_DEL(*ipcache, elem);
		ipcache_item_destroy(&elem->data);
		free(elem);
	}
}
static void ipcache6Key(ip6if *key, const struct in6_addr *a)
{
	memset(key,0,sizeof(*key)); // make sure everything is zero
	key->addr = *a;
}
static ip_cache6 *ipcache6Find(ip_cache6 *ipcache, const struct in6_addr *a)
{
	ip_cache6 *entry;
	ip6if key;

	ipcache6Key(&key,a);
	HASH_FIND(hh, ipcache, &key, sizeof(key), entry);
	return entry;
}
static ip_cache6 *ipcache6Add(ip_cache6 **ipcache, const struct in6_addr *a)
{
	// avoid dups
	ip_cache6 *entry = ipcache6Find(*ipcache,a);
	if (entry) return entry; // already included

	entry = malloc(sizeof(ip_cache6));
	if (!entry) return NULL;
	ipcache6Key(&entry->key,a);

	oom = false;
	HASH_ADD(hh, *ipcache, key, sizeof(entry->key), entry);
	if (oom) { free(entry); return NULL; }

	ipcache_item_init(&entry->data);

	return entry;
}
static void ipcache6Print(ip_cache6 *ipcache)
{
	char s_ip[40];
	time_t now;
	ip_cache6 *ipc, *tmp;

	time(&now);
	HASH_ITER(hh, ipcache , ipc, tmp)
	{
		*s_ip=0;
		inet_ntop(AF_INET6, &ipc->key.addr, s_ip, sizeof(s_ip));
		printf("%s : hostname=%s now=last+%llu\n", s_ip, ipc->data.hostname ? ipc->data.hostname : "", (unsigned long long)(now-ipc->data.last));
	}
}

void ipcacheDestroy(ip_cache *ipcache)
{
	ipcache4Destroy(&ipcache->ipcache4);
	ipcache6Destroy(&ipcache->ipcache6);
}
void ipcachePrint(ip_cache *ipcache)
{
	ipcache4Print(ipcache->ipcache4);
	ipcache6Print(ipcache->ipcache6);
}

ip_cache_item *ipcacheTouch(ip_cache *ipcache, const struct in_addr *a4, const struct in6_addr *a6)
{
	ip_cache4 *ipcache4;
	ip_cache6 *ipcache6;
	if (a4)
	{
		if ((ipcache4 = ipcache4Add(&ipcache->ipcache4,a4)))
		{
			ipcache_item_touch(&ipcache4->data);
			return &ipcache4->data;
		}
	}
	else if (a6)
	{
		if ((ipcache6 = ipcache6Add(&ipcache->ipcache6,a6)))
		{
			ipcache_item_touch(&ipcache6->data);
			return &ipcache6->data;
		}
	}
	return NULL;
}

static void ipcache4_purge(ip_cache4 **ipcache, time_t lifetime)
{
	ip_cache4 *elem, *tmp;
	time_t now = time(NULL);
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		if (now >= (elem->data.last + lifetime))
		{
			HASH_DEL(*ipcache, elem);
			ipcache_item_destroy(&elem->data);
			free(elem);
		}
	}
}
static void ipcache6_purge(ip_cache6 **ipcache, time_t lifetime)
{
	ip_cache6 *elem, *tmp;
	time_t now = time(NULL);
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		if (now >= (elem->data.last + lifetime))
		{
			HASH_DEL(*ipcache, elem);
			ipcache_item_destroy(&elem->data);
			free(elem);
		}
	}
}
static void ipcache_purge(ip_cache *ipcache, time_t lifetime)
{
	if (lifetime) // 0 = no expire
	{
		ipcache4_purge(&ipcache->ipcache4, lifetime);
		ipcache6_purge(&ipcache->ipcache6, lifetime);
	}
}
static time_t ipcache_purge_prev=0;
void ipcachePurgeRateLimited(ip_cache *ipcache, time_t lifetime)
{
	time_t now = time(NULL);
	// do not purge too often to save resources
	if (ipcache_purge_prev != now)
	{
		ipcache_purge(ipcache, lifetime);
		ipcache_purge_prev = now;
	}
}
