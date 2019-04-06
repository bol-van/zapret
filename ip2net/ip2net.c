// group ip list from stdout into subnets
// ip list must be pre-uniqued

#include <stdio.h>
#include <stdlib.h>
#include "qsort.h"

#define ALLOC_STEP 16384

// minimum subnet fill percent is  PCTMULT/PCTDIV  (for example 3/4)
#define PCTMULT	3
#define PCTDIV	4

typedef unsigned int uint;
typedef unsigned char uchar;

int ucmp (const void * a,const void * b, void *arg)
{
   if (*(uint*)a < *(uint*)b)
    return -1;
   else if (*(uint*)a > *(uint*)b)
    return 1;
   else
    return 0;
}

uint mask_from_bitcount(uint zct)
{
 return ~((1<<zct)-1);
}

int main()
{
 uint u1,u2,u3,u4,ip;
 uint ipct=0,iplist_size=0,*iplist=NULL,*iplist_new;
 uint pos=0,p;
 uint i,zct,subnet_ct,end_ip;
 
 while (!feof(stdin))
  if (scanf("%u.%u.%u.%u",&u1,&u2,&u3,&u4)==4 && !(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00))
  {
   ip = u1<<24 | u2<<16 | u3<<8 | u4;
   if (ipct>=iplist_size)
   {
     iplist_size += ALLOC_STEP;
     iplist_new = (uint*)(iplist ? realloc(iplist,sizeof(*iplist)*iplist_size) : malloc(sizeof(*iplist)*iplist_size));
     if (!iplist_new)
     {
       free(iplist);
       fprintf(stderr,"out of memory\n");
       return 100;
     }
     iplist = iplist_new;
   }
   iplist[ipct++]= ip;
  }

  gnu_quicksort(iplist,ipct,sizeof(*iplist),ucmp,NULL);

  while(pos<ipct)
  {
   uchar subnet_ok=0;
   uint mask,ip_start,ip_end,ip_ct,subnet_ct,pos_end;

   for(zct=10, pos_end=pos+1 ; zct>=2 ; zct--)
   {
    mask = mask_from_bitcount(zct);
    ip_start = iplist[pos] & mask;
    subnet_ct = ~mask+1;
    if (iplist[pos]>(ip_start+subnet_ct*(PCTDIV-PCTMULT)/PCTDIV)) continue;
    ip_end = ip_start | ~mask;
    for(p=pos, ip_ct=0 ; p<ipct && iplist[p]<=ip_end; p++) ip_ct++;
    if (ip_ct>=(subnet_ct*PCTMULT/PCTDIV))
    {
    	subnet_ok=1;
    	pos_end = p;
    	break;
    }
   }
   if (!subnet_ok) zct=0,ip_start=iplist[pos];

   u1 = ip_start>>24;
   u2 = (ip_start>>16) & 0xFF;
   u3 = (ip_start>>8) & 0xFF;
   u4 = ip_start & 0xFF;
   if (zct)
    printf("%u.%u.%u.%u/%u\n",u1,u2,u3,u4,32-zct);
   else
    printf("%u.%u.%u.%u\n",u1,u2,u3,u4);

   pos = pos_end;
  }

  free(iplist);
  return 0;
}
