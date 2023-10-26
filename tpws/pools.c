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
