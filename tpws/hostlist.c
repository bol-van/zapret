#include <stdio.h>
#include "hostlist.h"
#include "gzip.h"
#include "params.h"
#include "helpers.h"

// inplace tolower() and add to pool
static bool addpool(strpool **hostlist, char **s, const char *end, int *ct)
{
	char *p=*s;

	// comment line
	if ( *p == '#' || *p == ';' || *p == '/' || *p == '\r' || *p == '\n')
	{
		// advance until eol
		for (; p<end && *p && *p!='\r' && *p != '\n'; p++);
	}
	else
	{
		// advance until eol lowering all chars
		for (; p<end && *p && *p!='\r' && *p != '\n'; p++) *p=tolower(*p);
		if (!StrPoolAddStrLen(hostlist, *s, p-*s))
		{
			StrPoolDestroy(hostlist);
			*hostlist = NULL;
			return false;
		}
		(*ct)++;
	}
	// advance to the next line
	for (; p<end && (!*p || *p=='\r' || *p=='\n') ; p++);
	*s = p;
	return true;
}

bool AppendHostList(strpool **hostlist, const char *filename)
{
	char *p, *e, s[256], *zbuf;
	size_t zsize;
	int ct = 0;
	FILE *F;
	int r;

	DLOG_CONDUP("Loading hostlist %s\n",filename);

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
				if (!addpool(hostlist,&p,e,&ct))
				{
					DLOG_ERR("Not enough memory to store host list : %s\n", filename);
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
		
		while (fgets(s, sizeof(s), F))
		{
			p = s;
			if (!addpool(hostlist,&p,p+strlen(p),&ct))
			{
				DLOG_ERR("Not enough memory to store host list : %s\n", filename);
				fclose(F);
				return false;
			}
		}
		fclose(F);
	}

	DLOG_CONDUP("Loaded %d hosts from %s\n", ct, filename);
	return true;
}

bool LoadHostLists(strpool **hostlist, struct str_list_head *file_list)
{
	struct str_list *file;

	if (*hostlist)
	{
		StrPoolDestroy(hostlist);
		*hostlist = NULL;
	}

	LIST_FOREACH(file, file_list, next)
	{
		if (!AppendHostList(hostlist, file->str)) return false;
	}
	return true;
}

bool NonEmptyHostlist(strpool **hostlist)
{
	// add impossible hostname if the list is empty
	return *hostlist ? true : StrPoolAddStrLen(hostlist, "@&()", 4);
}


bool SearchHostList(strpool *hostlist, const char *host)
{
	if (hostlist)
	{
		const char *p = host;
		bool bInHostList;
		while (p)
		{
			bInHostList = StrPoolCheckStr(hostlist, p);
			VPRINT("Hostlist check for %s : %s\n", p, bInHostList ? "positive" : "negative");
			if (bInHostList) return true;
			p = strchr(p, '.');
			if (p) p++;
		}
	}
	return false;
}

// return : true = apply fooling, false = do not apply
static bool HostlistCheck_(strpool *hostlist, strpool *hostlist_exclude, const char *host, bool *excluded)
{
	if (excluded) *excluded = false;
	if (hostlist_exclude)
	{
		VPRINT("Checking exclude hostlist\n");
		if (SearchHostList(hostlist_exclude, host))
		{
			if (excluded) *excluded = true;
			return false;
		}
	}
	if (hostlist)
	{
		VPRINT("Checking include hostlist\n");
		return SearchHostList(hostlist, host);
	}
	return true;
}

static bool LoadIncludeHostListsForProfile(struct desync_profile *dp)
{
	if (!LoadHostLists(&dp->hostlist, &dp->hostlist_files))
		return false;
	if (*dp->hostlist_auto_filename)
	{
		dp->hostlist_auto_mod_time = file_mod_time(dp->hostlist_auto_filename);
		NonEmptyHostlist(&dp->hostlist);
	}
	return true;
}

bool HostlistCheck(struct desync_profile *dp, const char *host, bool *excluded)
{
	VPRINT("* hostlist check for profile %d\n",dp->n);
	if (*dp->hostlist_auto_filename)
	{
		time_t t = file_mod_time(dp->hostlist_auto_filename);
		if (t!=dp->hostlist_auto_mod_time)
		{
			DLOG_CONDUP("Autohostlist '%s' from profile %d was modified. Reloading include hostlists for this profile.\n",dp->hostlist_auto_filename, dp->n);
			if (!LoadIncludeHostListsForProfile(dp))
			{
				// what will we do without hostlist ?? sure, gonna die
				exit(1);
			}
			dp->hostlist_auto_mod_time = t;
			NonEmptyHostlist(&dp->hostlist);
		}
	}
	return HostlistCheck_(dp->hostlist, dp->hostlist_exclude, host, excluded);
}

bool LoadIncludeHostLists()
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
		if (!LoadIncludeHostListsForProfile(&dpl->dp))
			return false;
	return true;
}
bool LoadExcludeHostLists()
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
		if (!LoadHostLists(&dpl->dp.hostlist_exclude, &dpl->dp.hostlist_exclude_files))
			return false;
	return true;
}
