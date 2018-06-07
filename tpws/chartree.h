#pragma once

#include <stdbool.h>
#include <ctype.h>

typedef struct cptr
{
  char chr;
  struct cptr *leaf,*next;
} cptr;

void CharTreeDestroy(cptr *p);
bool CharTreeAddStr(cptr **pp,const char *s);
bool CharTreeAddStrLower(cptr **pp,const char *s);
bool CharTreeCheckStr(cptr *p,const char *s);
bool CharTreeCheckStrLower(cptr *pp,const char *s);
