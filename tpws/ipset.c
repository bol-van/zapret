#include <stdio.h>
#include "ipset.h"
#include "gzip.h"
#include "helpers.h"

// inplace tolower() and add to pool
static bool addpool(ipset *ips, char **s, const char *end, int *ct)
{
	char *p, cidr[128];
	size_t l;
	struct cidr4 c4;
	struct cidr6 c6;

	// advance until eol
	for (p=*s; p<end && *p && *p!='\r' && *p != '\n'; p++);

	// comment line
	if (!(**s == '#' || **s == ';' || **s == '/' || **s == '\r' || **s == '\n' ))
	{
		l = p-*s;
		if (l>=sizeof(cidr)) l=sizeof(cidr)-1;
		memcpy(cidr,*s,l);
		cidr[l]=0;
		rtrim(cidr);

		if (parse_cidr4(cidr,&c4))
		{
			if (!ipset4AddCidr(&ips->ips4, &c4))
			{
				ipsetDestroy(ips);
				return false;
			}
			(*ct)++;
		}
		else if (parse_cidr6(cidr,&c6))
		{
			if (!ipset6AddCidr(&ips->ips6, &c6))
			{
				ipsetDestroy(ips);
				return false;
			}
			(*ct)++;
		}
		else
			DLOG_ERR("bad ip or subnet : %s\n",cidr);
	}

	// advance to the next line
	for (; p<end && (!*p || *p=='\r' || *p=='\n') ; p++);
	*s = p;
	return true;

}

static bool AppendIpset(ipset *ips, const char *filename)
{
	char *p, *e, s[256], *zbuf;
	size_t zsize;
	int ct = 0;
	FILE *F;
	int r;

	DLOG_CONDUP("Loading ipset %s\n",filename);

	if (!(F = fopen(filename, "rb")))
	{
		DLOG_ERR("Could not open %s\n", filename);
		return false;
	}

	if (is_gzip(F))
	{
		r = z_readfile(F,&zbuf,&zsize);
		fclose(F);
		if (r==Z_OK)
		{
			DLOG_CONDUP("zlib compression detected. uncompressed size : %zu\n", zsize);
			
			p = zbuf;
			e = zbuf + zsize;
			while(p<e)
			{
				if (!addpool(ips,&p,e,&ct))
				{
					DLOG_ERR("Not enough memory to store ipset : %s\n", filename);
					free(zbuf);
					return false;
				}
			}
			free(zbuf);
		}
		else
		{
			DLOG_ERR("zlib decompression failed : result %d\n",r);
			return false;
		}
	}
	else
	{
		DLOG_CONDUP("loading plain text list\n");
		
		while (fgets(s, sizeof(s)-1, F))
		{
			p = s;
			if (!addpool(ips,&p,p+strlen(p),&ct))
			{
				DLOG_ERR("Not enough memory to store ipset : %s\n", filename);
				fclose(F);
				return false;
			}
		}
		fclose(F);
	}

	DLOG_CONDUP("Loaded %d ip/subnets from %s\n", ct, filename);
	return true;
}

static bool LoadIpsets(ipset *ips, struct str_list_head *file_list)
{
	struct str_list *file;

	ipsetDestroy(ips);

	LIST_FOREACH(file, file_list, next)
	{
		if (!AppendIpset(ips, file->str)) return false;
	}
	return true;
}

bool LoadIncludeIpsets()
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
		if (!LoadIpsets(&dpl->dp.ips, &dpl->dp.ipset_files))
			return false;
	return true;
}
bool LoadExcludeIpsets()
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
		if (!LoadIpsets(&dpl->dp.ips_exclude, &dpl->dp.ipset_exclude_files))
			return false;
	return true;
}

bool SearchIpset(const ipset *ips, const struct in_addr *ipv4, const struct in6_addr *ipv6)
{
	char s_ip[40];
	bool bInSet=false;

	if (!!ipv4 != !!ipv6)
	{
		*s_ip=0;
		if (ipv4)
		{
			if (params.debug) inet_ntop(AF_INET, ipv4, s_ip, sizeof(s_ip));
			if (ips->ips4) bInSet = ipset4Check(ips->ips4, ipv4, 32);
		}
		if (ipv6)
		{
			if (params.debug) inet_ntop(AF_INET6, ipv6, s_ip, sizeof(s_ip));
			if (ips->ips6) bInSet = ipset6Check(ips->ips6, ipv6, 128);
		}
		VPRINT("ipset check for %s : %s\n", s_ip, bInSet ? "positive" : "negative");
	}
	else
		// ipv4 and ipv6 are both empty or non-empty
		VPRINT("ipset check error !!!!!!!! ipv4=%p ipv6=%p\n",ipv4,ipv6);
	return bInSet;
}

static bool IpsetCheck_(const ipset *ips, const ipset *ips_exclude, const struct in_addr *ipv4, const struct in6_addr *ipv6)
{
	if (!IPSET_EMPTY(ips_exclude))
	{
		VPRINT("exclude ");
		if (SearchIpset(ips_exclude, ipv4, ipv6))
			return false;
	}
	if (!IPSET_EMPTY(ips))
	{
		VPRINT("include ");
		return SearchIpset(ips, ipv4, ipv6);
	}
	return true;
}

bool IpsetCheck(struct desync_profile *dp, const struct in_addr *ipv4, const struct in6_addr *ipv6)
{
	if (!PROFILE_IPSETS_EMPTY(dp)) VPRINT("* ipset check for profile %d\n",dp->n);
	return IpsetCheck_(&dp->ips,&dp->ips_exclude,ipv4,ipv6);
}
