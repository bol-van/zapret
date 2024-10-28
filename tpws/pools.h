#pragma once

#include <stdbool.h>
#include <ctype.h>
#include <sys/queue.h>
#include <time.h>

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
