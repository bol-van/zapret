#include "strpool.h"
#include <string.h>
#include <stdlib.h>

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom=false;
static void ut_oom_recover(strpool *elem)
{
 oom=true;
}

// for zero terminated strings
bool StrPoolAddStr(strpool **pp,const char *s)
{
 strpool *elem;
 if (!(elem = (strpool*)malloc(sizeof(strpool))))
  return false;
 if (!(elem->str = strdup(s)))
 {
  free(elem);
  return false;
 }
 oom = false;
 HASH_ADD_KEYPTR( hh, *pp, elem->str, strlen(elem->str), elem );
 if (oom)
 {
  free(elem->str);
  free(elem);
  return false;
 }
 return true;
}
// for not zero terminated strings
bool StrPoolAddStrLen(strpool **pp,const char *s,size_t slen)
{
 strpool *elem;
 if (!(elem = (strpool*)malloc(sizeof(strpool))))
  return false;
 if (!(elem->str = malloc(slen+1)))
 {
  free(elem);
  return false;
 }
 memcpy(elem->str,s,slen);
 elem->str[slen]=0;
 oom = false;
 HASH_ADD_KEYPTR( hh, *pp, elem->str, strlen(elem->str), elem );
 if (oom)
 {
  free(elem->str);
  free(elem);
  return false;
 }
 return true;
}

bool StrPoolCheckStr(strpool *p,const char *s)
{
 strpool *elem;
 HASH_FIND_STR( p, s, elem);
 return elem!=NULL;
}

void StrPoolDestroy(strpool **p)
{
 strpool *elem,*tmp;
 HASH_ITER(hh, *p, elem, tmp) {
   free(elem->str);
   HASH_DEL(*p, elem);
   free(elem);
 }
 *p = NULL;
}
