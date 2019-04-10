// group ipv4 list from stdout into subnets
// each line must contain either ipv4 or ipv4/bitcount
// valid ipv4/bitcount are passed through without modification
// ipv4 are groupped into subnets

#include <stdio.h>
#include <stdlib.h>
#include "qsort.h"

#define ALLOC_STEP 16384

// minimum subnet fill percent is  PCTMULT/PCTDIV  (for example 3/4)
#define PCTMULT	3
#define PCTDIV	4
// subnet search range in "zero bit count"
// means search start from /(32-ZCT_MAX) to /(32-ZCT_MIN)
#define ZCT_MAX 10
#define ZCT_MIN 2

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

// make presorted array unique. return number of unique items.
// 1,1,2,3,3,0,0,0 (ct=8) => 1,2,3,0 (ct=4)
uint unique(uint *pu,uint ct)
{
 uint i,j,u;
 for(i=j=0 ; j<ct ; i++)
 {
  u = pu[j++];
  for(; j<ct && pu[j]==u ; j++);
  pu[i] = u;
 }
 return i;
}

int main()
{
 uint u1,u2,u3,u4,ip;
 uint ipct=0,iplist_size=0,*iplist=NULL,*iplist_new;
 uint pos=0,p;
 uint i,zct,subnet_ct,end_ip;
 char str[256];

 while (fgets(str,sizeof(str),stdin))
 {
  if ((i=sscanf(str,"%u.%u.%u.%u/%u",&u1,&u2,&u3,&u4,&zct))>=4 && !(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00))
  {
   if (i==5 && zct!=32)
   {
    // we have subnet x.x.x.x/y
    // output it as is if valid, ignore otherwise
    if (zct<32)
     printf("%u.%u.%u.%u/%u\n",u1,u2,u3,u4,zct);
   }
   else
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
  }
 }

 gnu_quicksort(iplist,ipct,sizeof(*iplist),ucmp,NULL);
 ipct = unique(iplist,ipct);

 while(pos<ipct)
 {
  uint mask,ip_start,ip_end,ip_ct,subnet_ct,pos_end;
 
  // find largest possible network with enough ip coverage
  for(zct=ZCT_MAX ; zct>=ZCT_MIN ; zct--)
  {
    mask = mask_from_bitcount(zct);
    ip_start = iplist[pos] & mask;
    subnet_ct = ~mask+1;
    if (iplist[pos]>(ip_start+subnet_ct*(PCTDIV-PCTMULT)/PCTDIV))
	continue; // ip is higher than (1-PCT). definitely coverage is not enough. skip searching
    ip_end = ip_start | ~mask;
    for(p=pos, ip_ct=0 ; p<ipct && iplist[p]<=ip_end; p++) ip_ct++; // count ips within subnet range
    if (ip_ct>=(subnet_ct*PCTMULT/PCTDIV))
    {
	// network found
	pos_end = p;
        break;
    }
  }
  if (zct<ZCT_MIN) zct=0, ip_start=iplist[pos], pos_end=pos+1; // network not found, use single ip

  u1 = ip_start>>24;
  u2 = (ip_start>>16) & 0xFF;
  u3 = (ip_start>>8) & 0xFF;
  u4 = ip_start & 0xFF;
  printf(zct ? "%u.%u.%u.%u/%u\n" : "%u.%u.%u.%u\n", u1, u2, u3, u4, 32-zct);

  pos = pos_end;
 }

 free(iplist);
 return 0;
}
