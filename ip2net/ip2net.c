// group ipv4/ipv6 list from stdout into subnets
// each line must contain either ip or ip/bitcount
// valid ip/bitcount and ip1-ip2 are passed through without modification
// ips are groupped into subnets

// can be compiled in mingw. msvc not supported because of absent getopt

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
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
	return zct<32 ? ~((1 << zct) - 1) : 0;
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



#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static int cmp6(const void * a, const void * b, void *arg)
{
	// this function is critical for sort performance
	// on big endian systems cpu byte order is equal to network byte order
	// no conversion required. it's possible to improve speed by using big size compares
	// on little endian systems byte conversion also gives better result than byte comparision
	// 64-bit archs often have cpu command to reverse byte order
	// assume that a and b are properly aligned

#if defined(__BYTE_ORDER__) && ((__BYTE_ORDER__==__ORDER_BIG_ENDIAN__) || (__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__))

	uint64_t aa,bb;
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
	aa = __builtin_bswap64(((uint64_t*)((struct in6_addr *)a)->s6_addr)[0]);
	bb = __builtin_bswap64(((uint64_t*)((struct in6_addr *)b)->s6_addr)[0]);
#else
	aa = ((uint64_t*)((struct in6_addr *)a)->s6_addr)[0];
	bb = ((uint64_t*)((struct in6_addr *)b)->s6_addr)[0];
#endif
	if (aa < bb)
		return -1;
	else if (aa > bb)
		return 1;
	else
	{
#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
		aa = __builtin_bswap64(((uint64_t*)((struct in6_addr *)a)->s6_addr)[1]);
		bb = __builtin_bswap64(((uint64_t*)((struct in6_addr *)b)->s6_addr)[1]);
#else
		aa = ((uint64_t*)((struct in6_addr *)a)->s6_addr)[1];
		bb = ((uint64_t*)((struct in6_addr *)b)->s6_addr)[1];
#endif
		return aa < bb ? -1 : aa > bb ? 1 : 0;
	}
	
#else
	// fallback case
	for (uint8_t i = 0; i < sizeof(((struct in6_addr *)0)->s6_addr); i++)
	{
		if (((struct in6_addr *)a)->s6_addr[i] < ((struct in6_addr *)b)->s6_addr[i])
			return -1;
		else if (((struct in6_addr *)a)->s6_addr[i] > ((struct in6_addr *)b)->s6_addr[i])
			return 1;
	}
	return 0;
#endif
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
static void mask_from_bitcount6_make(uint32_t zct, struct in6_addr *a)
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
static struct in6_addr ip6_mask[129];
static void mask_from_bitcount6_prepare(void)
{
	for (int zct=0;zct<=128;zct++) mask_from_bitcount6_make(zct, ip6_mask+zct);
}
static inline const struct in6_addr *mask_from_bitcount6(uint32_t zct)
{
	return ip6_mask+zct;
}


/*
// this is "correct" solution for strict aliasing feature
// but I don't like this style of coding
// write what I don't mean to force smart optimizer to do what it's best
// it produces better code sometimes but not on all compilers/versions/archs
// sometimes it even generates real memcpy calls (mips32,arm32)
// so I will not do it

static void ip6_and(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *result)
{
	uint64_t a_addr[2], b_addr[2];
	memcpy(a_addr, a->s6_addr, 16);
	memcpy(b_addr, b->s6_addr, 16);
	a_addr[0] &= b_addr[0];
	a_addr[1] &= b_addr[1];
	memcpy(result->s6_addr, a_addr, 16);
}
*/

// YES, from my point of view C should work as a portable assembler. It must do what I instruct it to do.
// that's why I disable strict aliasing for this function. I observed gcc can miscompile with O2/O3 setting if inlined and not coded "correct"
// result = a & b
// assume that a and b are properly aligned
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
static void ip6_and(const struct in6_addr * restrict a, const struct in6_addr * restrict b, struct in6_addr * restrict result)
{
#ifdef __SIZEOF_INT128__
	// gcc and clang have 128 bit int types on some 64-bit archs. take some advantage
	*((unsigned __int128*)result->s6_addr) = *((unsigned __int128*)a->s6_addr) & *((unsigned __int128*)b->s6_addr);
#else
	((uint64_t*)result->s6_addr)[0] = ((uint64_t*)a->s6_addr)[0] & ((uint64_t*)b->s6_addr)[0];
	((uint64_t*)result->s6_addr)[1] = ((uint64_t*)a->s6_addr)[1] & ((uint64_t*)b->s6_addr)[1];
#endif
}

static void rtrim(char *s)
{
	if (s)
		for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t'); p--) *p = '\0';
}


static struct params_s
{
	bool ipv6;
	uint32_t pctmult, pctdiv; // for v4
	uint32_t zct_min, zct_max; // for v4 and v6
	uint32_t v6_threshold; // for v6
} params;


static void exithelp(void)
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

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#if defined(ZAPRET_GH_VER) || defined (ZAPRET_GH_HASH)
#define PRINT_VER printf("github version %s (%s)\n\n", TOSTRING(ZAPRET_GH_VER), TOSTRING(ZAPRET_GH_HASH))
#else
#define PRINT_VER printf("self-built version %s %s\n\n", __DATE__, __TIME__)
#endif

enum opt_indices {
	IDX_HELP,
	IDX_H,
	IDX_4,
	IDX_6,
	IDX_PREFIX_LENGTH,
	IDX_V4_THRESHOLD,
	IDX_V6_THRESHOLD,
	IDX_LAST,
};

static const struct option long_options[] = {
	[IDX_HELP] = {"help", no_argument, 0, 0},
	[IDX_H] = {"h", no_argument, 0, 0},
	[IDX_4] = {"4", no_argument, 0, 0},
	[IDX_6] = {"6", no_argument, 0, 0},
	[IDX_PREFIX_LENGTH] = {"prefix-length", required_argument, 0, 0},
	[IDX_V4_THRESHOLD] = {"v4-threshold", required_argument, 0, 0},
	[IDX_V6_THRESHOLD] = {"v6-threshold", required_argument, 0, 0},
	[IDX_LAST] = {NULL, 0, NULL, 0},
};

static void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;
	uint32_t plen1=-1, plen2=-1;

	memset(&params, 0, sizeof(params));
	params.pctmult = DEFAULT_PCTMULT;
	params.pctdiv = DEFAULT_PCTDIV;
	params.v6_threshold = DEFAULT_V6_THRESHOLD;

	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case IDX_HELP:
		case IDX_H:
			PRINT_VER;
			exithelp();
			break;
		case IDX_4:
			params.ipv6 = false;
			break;
		case IDX_6:
			params.ipv6 = true;
			break;
		case IDX_PREFIX_LENGTH:
			i = sscanf(optarg,"%u-%u",&plen1,&plen2);
			if (i == 1) plen2 = plen1;
			if (i<=0 || plen2<plen1 || !plen1 || !plen2)
			{
				fprintf(stderr, "invalid parameter for prefix-length : %s\n", optarg);
				exit(1);
			}
			break;
		case IDX_V4_THRESHOLD:
			i = sscanf(optarg, "%u/%u", &params.pctmult, &params.pctdiv);
			if (i!=2 || params.pctdiv<2 || params.pctmult<1 || params.pctmult>=params.pctdiv)
			{
				fprintf(stderr, "invalid parameter for v4-threshold : %s\n", optarg);
				exit(1);
			}
			break;
		case IDX_V6_THRESHOLD:
			i = sscanf(optarg, "%u", &params.v6_threshold);
			if (i != 1 || params.v6_threshold<1)
			{
				fprintf(stderr, "invalid parameter for v6-threshold : %s\n", optarg);
				exit(1);
			}
			break;
		}
	}
	if (plen1 != -1 && ((!params.ipv6 && (plen1>31 || plen2>31)) || (params.ipv6 && (plen1>127 || plen2>127))))
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
					if (sscanf(s + 1, "%u", &zct)==1 && zct!=128)
					{
						if (zct<128) printf("%s/%u\n", str, zct);
						continue;
					}
				}
				else if (d=='-')
				{
					if (inet_pton(AF_INET6, s+1, &a)) printf("%s-%s\n", str, s+1);
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
		mask_from_bitcount6_prepare();

		/*
		for(uint32_t i=0;i<ipct;i++)
		 if (inet_ntop(AF_INET6,iplist+i,str,sizeof(str)))
		  printf("%s\n",str);
		printf("\n");
		*/
		while (pos < ipct)
		{
			const struct in6_addr *mask;
			struct in6_addr ip_start, ip;
			uint32_t ip_ct_best = 0, zct_best = 0;

			pos_end = pos + 1;
			// find smallest network with maximum ip coverage with no less than ip6_subnet_threshold addresses
			for (zct = params.zct_max; zct >= params.zct_min; zct--)
			{
				mask = mask_from_bitcount6(zct);
				ip6_and(iplist + pos, mask, &ip_start);
				for (p = pos + 1, ip_ct = 1; p < ipct; p++, ip_ct++)
				{
					ip6_and(iplist + p, mask, &ip);
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
			if (zct_best)
				// network was found
				ip6_and(iplist + pos, mask_from_bitcount6(zct_best), &ip_start);
			else
				ip_start = iplist[pos], pos_end = pos + 1; // network not found, use single ip
			inet_ntop(AF_INET6, &ip_start, str, sizeof(str));
			printf(zct_best ? "%s/%u\n" : "%s\n", str, 128 - zct_best);

			pos = pos_end;
		}

		free(iplist);
	}
	else // ipv4
	{
		uint32_t u1,u2,u3,u4, u11,u22,u33,u44, ip;
		uint32_t *iplist = NULL, *iplist_new, i;

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
			if (zct_best)
				ip_start = iplist[pos] & mask_from_bitcount(zct_best);
			else
				ip_start = iplist[pos], pos_end = pos + 1; // network not found, use single ip

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
