// group ipv4/ipv6 list from stdout into subnets
// each line must contain either ip or ip/bitcount
// valid ip/bitcount and ip1-ip2 are passed through without modification
// ips are groupped into subnets

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "qsort.h"

#define ALLOC_STEP 16384

// minimum subnet fill percent is  PCTMULT/PCTDIV  (for example 3/4)
#define DEFAULT_PCTMULT	3
#define DEFAULT_PCTDIV	4
// subnet search range in "zero bit count"
// means search start from /(32-ZCT_MAX) to /(32-ZCT_MIN)
#define DEFAULT_V4_ZCT_MAX 10 //   /22
#define DEFAULT_V4_ZCT_MIN 2  //   /30
#define DEFAULT_V6_ZCT_MAX 72 //   /56
#define DEFAULT_V6_ZCT_MIN 64 //   /64
// must be no less than N ipv6 in subnet
#define DEFAULT_V6_THRESHOLD	5

static int ucmp(const void * a, const void * b, void *arg)
{
	if (*(uint32_t*)a < *(uint32_t*)b)
		return -1;
	else if (*(uint32_t*)a > *(uint32_t*)b)
		return 1;
	else
		return 0;
}
static uint32_t mask_from_bitcount(uint32_t zct)
{
	return ~((1 << zct) - 1);
}
// make presorted array unique. return number of unique items.
// 1,1,2,3,3,0,0,0 (ct=8) => 1,2,3,0 (ct=4)
static uint32_t unique(uint32_t *pu, uint32_t ct)
{
	uint32_t i, j, u;
	for (i = j = 0; j < ct; i++)
	{
		u = pu[j++];
		for (; j < ct && pu[j] == u; j++);
		pu[i] = u;
	}
	return i;
}



static int cmp6(const void * a, const void * b, void *arg)
{
	for (uint8_t i = 0; i < sizeof(((struct in6_addr *)0)->s6_addr); i++)
	{
		if (((struct in6_addr *)a)->s6_addr[i] < ((struct in6_addr *)b)->s6_addr[i])
			return -1;
		else if (((struct in6_addr *)a)->s6_addr[i] > ((struct in6_addr *)b)->s6_addr[i])
			return 1;
	}
	return 0;
}
// make presorted array unique. return number of unique items.
static uint32_t unique6(struct in6_addr *pu, uint32_t ct)
{
	uint32_t i, j, k;
	for (i = j = 0; j < ct; i++)
	{
		for (k = j++; j < ct && !memcmp(pu + j, pu + k, sizeof(struct in6_addr)); j++);
		pu[i] = pu[k];
	}
	return i;
}
static void mask_from_bitcount6(uint32_t zct, struct in6_addr *a)
{
	if (zct >= 128)
		memset(a->s6_addr,0x00,16);
	else
	{
		int32_t n = (127 - zct) >> 3;
		memset(a->s6_addr,0xFF,n);
		memset(a->s6_addr+n,0x00,16-n);
		a->s6_addr[n] = ~((1 << (zct & 7)) - 1);
	}
}
// result = a & b
static void ip6_and(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *result)
{
	((uint64_t*)result->s6_addr)[0] = ((uint64_t*)a->s6_addr)[0] & ((uint64_t*)b->s6_addr)[0];
	((uint64_t*)result->s6_addr)[1] = ((uint64_t*)a->s6_addr)[1] & ((uint64_t*)b->s6_addr)[1];
}

static void rtrim(char *s)
{
	if (s)
		for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}


static struct params_s
{
	bool ipv6;
	uint32_t pctmult, pctdiv; // for v4
	uint32_t zct_min, zct_max; // for v4 and v6
	uint32_t v6_threshold; // for v6
} params;


static void exithelp()
{
	printf(
		" -4\t\t\t\t; ipv4 list (default)\n"
		" -6\t\t\t\t; ipv6 list\n"
		" --prefix-length=min[-max]\t; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)\n"
		" --v4-threshold=mul/div\t\t; ipv4 only : include subnets with more than mul/div ips. example : 3/4\n"
		" --v6-threshold=N\t\t; ipv6 only : include subnets with more than N v6 ips. example : 5\n"
	);
	exit(1);
}

static void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;
	uint32_t plen1=-1, plen2=-1;

	memset(&params, 0, sizeof(params));
	params.pctmult = DEFAULT_PCTMULT;
	params.pctdiv = DEFAULT_PCTDIV;
	params.v6_threshold = DEFAULT_V6_THRESHOLD;

	const struct option long_options[] = {
		{ "help",no_argument,0,0 },// optidx=0
		{ "h",no_argument,0,0 },// optidx=1
		{ "4",no_argument,0,0 },// optidx=2
		{ "6",no_argument,0,0 },// optidx=3
		{ "prefix-length",required_argument,0,0 },// optidx=4
		{ "v4-threshold",required_argument,0,0 },// optidx=5
		{ "v6-threshold",required_argument,0,0 },// optidx=6
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0:
		case 1:
			exithelp();
			break;
		case 2:
			params.ipv6 = false;
			break;
		case 3:
			params.ipv6 = true;
			break;
		case 4:
			i = sscanf(optarg,"%u-%u",&plen1,&plen2);
			if (i == 1) plen2 = plen1;
			if (!i || plen2<plen1 || !plen1 || !plen2)
			{
				fprintf(stderr, "invalid parameter for prefix-length : %s\n", optarg);
				exit(1);
			}
			break;
		case 5:
			i = sscanf(optarg, "%u/%u", &params.pctmult, &params.pctdiv);
			if (i!=2 || params.pctdiv<2 || params.pctmult<1 || params.pctmult>=params.pctdiv)
			{
				fprintf(stderr, "invalid parameter for v4-threshold : %s\n", optarg);
				exit(1);
			}
			break;
		case 6:
			i = sscanf(optarg, "%u", &params.v6_threshold);
			if (i != 1 || params.v6_threshold<1)
			{
				fprintf(stderr, "invalid parameter for v6-threshold : %s\n", optarg);
				exit(1);
			}
			break;
		}
	}
	if (plen1 != -1 && (!params.ipv6 && (plen1>31 || plen2>31) || params.ipv6 && (plen1>127 || plen2>127)))
	{
		fprintf(stderr, "invalid parameter for prefix-length\n");
		exit(1);
	}
	params.zct_min = params.ipv6 ? plen2==-1 ? DEFAULT_V6_ZCT_MIN : 128-plen2 : plen2==-1 ? DEFAULT_V4_ZCT_MIN : 32-plen2;
	params.zct_max = params.ipv6 ? plen1==-1 ? DEFAULT_V6_ZCT_MAX : 128-plen1 : plen1==-1 ? DEFAULT_V4_ZCT_MAX : 32-plen1;
}


int main(int argc, char **argv)
{
	char str[256],d;
	uint32_t ipct = 0, iplist_size = 0, pos = 0, p, zct, ip_ct, pos_end;

	parse_params(argc, argv);

	if (params.ipv6) // ipv6
	{
		char *s;
		struct in6_addr a, *iplist = NULL, *iplist_new;

		while (fgets(str, sizeof(str), stdin))
		{
			rtrim(str);
			d = 0;
			if ((s = strchr(str, '/')) || (s = strchr(str, '-')))
			{
				d = *s;
				*s = '\0';
			}
			if (inet_pton(AF_INET6, str, &a))
			{
				if (d=='/')
				{
					// we have subnet ip6/y
					// output it as is
					*s = d;
					if (sscanf(s + 1, "%u", &zct) && zct!=128)
					{
						if (zct<128) printf("%s\n", str);
						continue;
					}
				}
				else if (d=='-')
				{
					*s = d;
					if (inet_pton(AF_INET6, s+1, &a)) printf("%s\n", str);
					continue;
				}
				if (ipct >= iplist_size)
				{
					iplist_size += ALLOC_STEP;
					iplist_new = (struct in6_addr*)(iplist ? realloc(iplist, sizeof(*iplist)*iplist_size) : malloc(sizeof(*iplist)*iplist_size));
					if (!iplist_new)
					{
						free(iplist);
						fprintf(stderr, "out of memory\n");
						return 100;
					}
					iplist = iplist_new;
				}
				iplist[ipct++] = a;
			}
		}
		gnu_quicksort(iplist, ipct, sizeof(*iplist), cmp6, NULL);
		ipct = unique6(iplist, ipct);

		/*
		for(uint32_t i=0;i<ipct;i++)
		 if (inet_ntop(AF_INET6,iplist+i,str,256))
		  printf("%s\n",str);
		printf("\n");
		*/
		while (pos < ipct)
		{
			struct in6_addr mask, ip_start, ip;
			uint32_t ip_ct_best = 0, zct_best = 0;

			pos_end = pos + 1;
			// find smallest network with maximum ip coverage with no less than ip6_subnet_threshold addresses
			for (zct = params.zct_max; zct >= params.zct_min; zct--)
			{
				mask_from_bitcount6(zct, &mask);
				ip6_and(iplist + pos, &mask, &ip_start);
				for (p = pos + 1, ip_ct = 1; p < ipct; p++, ip_ct++)
				{
					ip6_and(iplist + p, &mask, &ip);
					if (memcmp(&ip_start, &ip, sizeof(ip)))
						break;
				}
				if (ip_ct == 1) break;
				if (ip_ct >= params.v6_threshold)
				{
					// network found. but is there smaller network with the same ip_ct ? dont do carpet bombing if possible, use smaller subnets
					if (!ip_ct_best || ip_ct == ip_ct_best)
					{
						ip_ct_best = ip_ct;
						zct_best = zct;
						pos_end = p;
					}
					else
						break;
				}
			}
			if (!zct_best) ip_start = iplist[pos], pos_end = pos + 1; // network not found, use single ip
			inet_ntop(AF_INET6, &ip_start, str, sizeof(str));
			printf(zct_best ? "%s/%u\n" : "%s\n", str, 128 - zct_best);

			pos = pos_end;
		}

		free(iplist);
	}
	else // ipv4
	{
		uint32_t u1,u2,u3,u4, u11,u22,u33,u44, ip;
		uint32_t *iplist = NULL, *iplist_new;
		uint32_t i, subnet_ct, end_ip;

		while (fgets(str, sizeof(str), stdin))
		{
			if ((i = sscanf(str, "%u.%u.%u.%u-%u.%u.%u.%u", &u1, &u2, &u3, &u4, &u11, &u22, &u33, &u44)) >= 8 && 
				!(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00) &&
				!(u11 & 0xFFFFFF00) && !(u22 & 0xFFFFFF00) && !(u33 & 0xFFFFFF00) && !(u44 & 0xFFFFFF00))
			{
				printf("%u.%u.%u.%u-%u.%u.%u.%u\n", u1, u2, u3, u4, u11, u22, u33, u44);
			}
			else
			if ((i = sscanf(str, "%u.%u.%u.%u/%u", &u1, &u2, &u3, &u4, &zct)) >= 4 &&
				!(u1 & 0xFFFFFF00) && !(u2 & 0xFFFFFF00) && !(u3 & 0xFFFFFF00) && !(u4 & 0xFFFFFF00))
			{
				if (i == 5 && zct != 32)
				{
					// we have subnet x.x.x.x/y
					// output it as is if valid, ignore otherwise
					if (zct < 32)
						printf("%u.%u.%u.%u/%u\n", u1, u2, u3, u4, zct);
				}
				else
				{
					ip = u1 << 24 | u2 << 16 | u3 << 8 | u4;
					if (ipct >= iplist_size)
					{
						iplist_size += ALLOC_STEP;
						iplist_new = (uint32_t*)(iplist ? realloc(iplist, sizeof(*iplist)*iplist_size) : malloc(sizeof(*iplist)*iplist_size));
						if (!iplist_new)
						{
							free(iplist);
							fprintf(stderr, "out of memory\n");
							return 100;
						}
						iplist = iplist_new;
					}
					iplist[ipct++] = ip;
				}
			}
		}

		gnu_quicksort(iplist, ipct, sizeof(*iplist), ucmp, NULL);
		ipct = unique(iplist, ipct);

		while (pos < ipct)
		{
			uint32_t mask, ip_start, ip_end, subnet_ct;
			uint32_t ip_ct_best = 0, zct_best = 0;

			// find smallest network with maximum ip coverage with no less than mul/div percent addresses
			for (zct = params.zct_max; zct >= params.zct_min; zct--)
			{
				mask = mask_from_bitcount(zct);
				ip_start = iplist[pos] & mask;
				subnet_ct = ~mask + 1;
				if (iplist[pos] > (ip_start + subnet_ct*(params.pctdiv - params.pctmult) / params.pctdiv))
					continue; // ip is higher than (1-PCT). definitely coverage is not enough. skip searching
				ip_end = ip_start | ~mask;
				for (p=pos+1, ip_ct=1; p < ipct && iplist[p] <= ip_end; p++) ip_ct++; // count ips within subnet range
				if (ip_ct == 1) break;
				if (ip_ct >= (subnet_ct*params.pctmult / params.pctdiv))
				{
					// network found. but is there smaller network with the same ip_ct ? dont do carpet bombing if possible, use smaller subnets
					if (!ip_ct_best || ip_ct == ip_ct_best)
					{
						ip_ct_best = ip_ct;
						zct_best = zct;
						pos_end = p;
					}
					else
						break;
				}
			}
			if (!zct_best) ip_start = iplist[pos], pos_end = pos + 1; // network not found, use single ip

			u1 = ip_start >> 24;
			u2 = (ip_start >> 16) & 0xFF;
			u3 = (ip_start >> 8) & 0xFF;
			u4 = ip_start & 0xFF;
			printf(zct_best ? "%u.%u.%u.%u/%u\n" : "%u.%u.%u.%u\n", u1, u2, u3, u4, 32 - zct_best);

			pos = pos_end;
		}

		free(iplist);
	}

	return 0;
}
