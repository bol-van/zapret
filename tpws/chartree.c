#include "chartree.h"
#include <string.h>
#include <stdlib.h>

static cptr *CharTreeInit(char c)
{
 cptr *p;
 p=(cptr *)calloc(1,sizeof(cptr));
 if (p) p->chr = c;
 return p;
}
void CharTreeDestroy(cptr *p)
{
 cptr *p2;
 while (p)
 {
   CharTreeDestroy(p->leaf);
   p2 = p;
   p = p->next;
   free(p2);
 }
}
static cptr *CharTreeFindChar(cptr *p,char c)
{
 while (p)
 {
  if (p->chr==c) return p;
  p = p->next;
 }
 return NULL;
}
bool CharTreeAddStr(cptr **pp,const char *s)
{
 cptr *p;
 if (*pp)
 {
  if (!(p=CharTreeFindChar(*pp,*s)))
  {
   // already present. append to list head
   if (!(p = CharTreeInit(*s)))
    return false;
   p->next = *pp;
   *pp = p;
  }
 }
 else
  if (!(p = *pp = CharTreeInit(*s))) return false;
 if (!*s) return true;
 return CharTreeAddStr(&p->leaf,s+1);
}
bool CharTreeCheckStr(cptr *p,const char *s)
{
 p = CharTreeFindChar(p,*s);
 if (!p) return false;
 if (!*s) return true;
 return CharTreeCheckStr(p->leaf,s+1);
}

static char *DupLower(const char *s)
{
 char *sp,*sl = strdup(s);
 if (!sl) return false;
 for(sp=sl;*sp;sp++) *sp=tolower(*sp);
 return sl;
}
bool CharTreeAddStrLower(cptr **pp,const char *s)
{
 bool b;
 char *sl = DupLower(s);
 if (!sl) return false;
 b=CharTreeAddStr(pp,sl);
 free(sl);
 return b;
}
bool CharTreeCheckStrLower(cptr *pp,const char *s)
{
 bool b;
 char *sl = DupLower(s);
 if (!sl) return false;
 b=CharTreeCheckStr(pp,sl);
 free(sl);
 return b;
}
