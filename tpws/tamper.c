#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include "tamper.h"
#include "hostlist.h"
#include "ipset.h"
#include "protocol.h"
#include "helpers.h"

#define PKTDATA_MAXDUMP 32

void packet_debug(const uint8_t *data, size_t sz)
{
	hexdump_limited_dlog(data, sz, PKTDATA_MAXDUMP); VPRINT("\n");
}

static bool dp_match(struct desync_profile *dp, const struct sockaddr *dest, const char *hostname, t_l7proto l7proto)
{
	bool bHostlistsEmpty;

	if (!HostlistsReloadCheckForProfile(dp)) return false;

	if ((dest->sa_family==AF_INET && !dp->filter_ipv4) || (dest->sa_family==AF_INET6 && !dp->filter_ipv6))
		// L3 filter does not match
		return false;
	if (!port_filters_in_range(&dp->pf_tcp,saport(dest)))
		// L4 filter does not match
		return false;
	if (dp->filter_l7 && !l7_proto_match(l7proto, dp->filter_l7))
		// L7 filter does not match
		return false;
	bHostlistsEmpty = PROFILE_HOSTLISTS_EMPTY(dp);
	if (!dp->hostlist_auto && !hostname && !bHostlistsEmpty)
		// avoid cpu consuming ipset check. profile cannot win if regular hostlists are present without auto hostlist and hostname is unknown.
		return false;
	if (!IpsetCheck(dp, dest->sa_family==AF_INET ? &((struct sockaddr_in*)dest)->sin_addr : NULL, dest->sa_family==AF_INET6 ? &((struct sockaddr_in6*)dest)->sin6_addr : NULL))
		// target ip does not match
		return false;

	// autohostlist profile matching l3/l4/l7 filter always win
	if (dp->hostlist_auto) return true;

	if (bHostlistsEmpty)
		// profile without hostlist filter wins
		return true;
	else if (hostname)
		// if hostlists are present profile matches only if hostname is known and satisfy profile hostlists
		return HostlistCheck(dp, hostname, NULL, true);

	return false;
}
static struct desync_profile *dp_find(struct desync_profile_list_head *head, const struct sockaddr *dest, const char *hostname, t_l7proto l7proto)
{
	struct desync_profile_list *dpl;
	if (params.debug)
	{
		char ip_port[48];
		ntop46_port(dest, ip_port,sizeof(ip_port));
		VPRINT("desync profile search for tcp target=%s l7proto=%s hostname='%s'\n", ip_port, l7proto_str(l7proto), hostname ? hostname : "");
	}
	LIST_FOREACH(dpl, head, next)
	{
		if (dp_match(&dpl->dp,dest,hostname,l7proto))
		{
			VPRINT("desync profile %d matches\n",dpl->dp.n);
			return &dpl->dp;
		}
	}
	VPRINT("desync profile not found\n");
	return NULL;
}
void apply_desync_profile(t_ctrack *ctrack, const struct sockaddr *dest)
{
	ctrack->dp = dp_find(&params.desync_profiles, dest, ctrack->hostname, ctrack->l7proto);
}



// segment buffer has at least 5 extra bytes to extend data block
void tamper_out(t_ctrack *ctrack, const struct sockaddr *dest, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *multisplit_pos, int *multisplit_count, uint8_t *split_flags)
{
	uint8_t *p, *pp, *pHost = NULL;
	size_t method_len = 0, pos, tpos, orig_size=*size;
	const char *method;
	bool bHaveHost = false;
	char *pc, Host[256];
	t_l7proto l7proto;

	DBGPRINT("tamper_out\n");

	if (!ctrack->dp) return;

	if (params.debug)
	{
		char ip_port[48];
		ntop46_port(dest,ip_port,sizeof(ip_port));
		VPRINT("tampering tcp segment with size %zu to %s\n", *size, ip_port);
		if (ctrack->dp) VPRINT("using cached desync profile %d\n",ctrack->dp->n);
		if (ctrack->hostname) VPRINT("connection hostname: %s\n", ctrack->hostname);
	}
		
	if (dest->sa_family!=AF_INET && dest->sa_family!=AF_INET6)
	{
		DLOG_ERR("tamper_out dest family unknown\n");
		return;
	}

	if (multisplit_count) *multisplit_count=0;
	if (split_flags) *split_flags=0;

	if ((method = HttpMethod(segment,*size)))
	{
		method_len = strlen(method)-2;
		VPRINT("Data block looks like http request start : %s\n", method);
		l7proto=HTTP;
		if (HttpFindHost(&pHost,segment,*size))
		{
			p = pHost + 5;
			while (p < (segment + *size) && (*p == ' ' || *p == '\t')) p++;
			pp = p;
			while (pp < (segment + *size) && (pp - p) < (sizeof(Host) - 1) && *pp != '\r' && *pp != '\n') pp++;
			memcpy(Host, p, pp - p);
			Host[pp - p] = '\0';
			bHaveHost = true;
			for(pc = Host; *pc; pc++) *pc=tolower(*pc);
		}
	}
	else if (IsTLSClientHello(segment,*size,false))
	{
		VPRINT("Data block contains TLS ClientHello\n");
		l7proto=TLS;
		bHaveHost=TLSHelloExtractHost((uint8_t*)segment,*size,Host,sizeof(Host),false);
	}
	else
	{
		VPRINT("Data block contains unknown payload\n");
		l7proto = UNKNOWN;
	}

	if (bHaveHost)
		VPRINT("request hostname: %s\n", Host);

	bool bDiscoveredL7 = ctrack->l7proto==UNKNOWN && l7proto!=UNKNOWN;
	if (bDiscoveredL7)
	{
		VPRINT("discovered l7 protocol\n");
		ctrack->l7proto=l7proto;
	}

	bool bDiscoveredHostname = bHaveHost && !ctrack->hostname;
	if (bDiscoveredHostname)
	{
		VPRINT("discovered hostname\n");
		if (!(ctrack->hostname=strdup(Host)))
		{
			DLOG_ERR("strdup hostname : out of memory\n");
			return;
		}
	}

	if (bDiscoveredL7 || bDiscoveredHostname)
	{
		struct desync_profile *dp_prev = ctrack->dp;
		apply_desync_profile(ctrack, dest);
		if (ctrack->dp!=dp_prev)
		{
			VPRINT("desync profile changed by revealed l7 protocol or hostname !\n");
			ctrack->b_host_checked = ctrack->b_ah_check = false;
		}
	}

	if (l7proto!=UNKNOWN && ctrack->dp->hostlist_auto)
	{
		if (bHaveHost && !ctrack->b_host_checked)
		{
			bool bHostExcluded;
			ctrack->b_host_matches = HostlistCheck(ctrack->dp, Host, &bHostExcluded, false);
			ctrack->b_host_checked = true;
			if (!ctrack->b_host_matches)
				ctrack->b_ah_check = !bHostExcluded;
		}
		if (!ctrack->b_host_matches)
		{
			VPRINT("Not acting on this request\n");
			return;
		}
	}
	switch(l7proto)
	{
		case HTTP:
			if (ctrack->dp->unixeol)
			{
				p = pp = segment;
				while ((p = memmem(p, segment + *size - p, "\r\n", 2)))
				{
					*p = '\n'; p++;
					memmove(p, p + 1, segment + *size - p - 1);
					(*size)--;
					if (pp == (p - 1))
					{
						// probably end of http headers
						VPRINT("Found double EOL at pos %td. Stop replacing.\n", pp - segment);
						break;
					}
					pp = p;
				}
				pHost = NULL; // invalidate
			}
			if (ctrack->dp->methodeol && (*size+1+!ctrack->dp->unixeol)<=segment_buffer_size)
			{
				VPRINT("Adding EOL before method\n");
				if (ctrack->dp->unixeol)
				{
					memmove(segment + 1, segment, *size);
					(*size)++;;
					segment[0] = '\n';
				}
				else
				{
					memmove(segment + 2, segment, *size);
					*size += 2;
					segment[0] = '\r';
					segment[1] = '\n';
				}
				pHost = NULL; // invalidate
			}
			if (ctrack->dp->methodspace && *size<segment_buffer_size)
			{
				// we only work with data blocks looking as HTTP query, so method is at the beginning
				VPRINT("Adding extra space after method\n");
				p = segment + method_len + 1;
				pos = method_len + 1;
				memmove(p + 1, p, *size - pos);
				*p = ' '; // insert extra space
				(*size)++; // block will grow by 1 byte
				if (pHost) pHost++; // Host: position will move by 1 byte
			}
			if ((ctrack->dp->hostdot || ctrack->dp->hosttab) && *size<segment_buffer_size && HttpFindHost(&pHost,segment,*size))
			{
				p = pHost + 5;
				while (p < (segment + *size) && *p != '\r' && *p != '\n') p++;
				if (p < (segment + *size))
				{
					pos = p - segment;
					VPRINT("Adding %s to host name at pos %zu\n", ctrack->dp->hostdot ? "dot" : "tab", pos);
					memmove(p + 1, p, *size - pos);
					*p = ctrack->dp->hostdot ? '.' : '\t'; // insert dot or tab
					(*size)++; // block will grow by 1 byte
				}
			}
			if (ctrack->dp->domcase && HttpFindHost(&pHost,segment,*size))
			{
				p = pHost + 5;
				pos = p - segment;
				VPRINT("Mixing domain case at pos %zu\n",pos);
				for (; p < (segment + *size) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
			}
			if (ctrack->dp->hostnospace && HttpFindHost(&pHost,segment,*size) && (pHost+5)<(segment+*size) && pHost[5] == ' ')
			{
				p = pHost + 6;
				pos = p - segment;
				VPRINT("Removing space before host name at pos %zu\n", pos);
				memmove(p - 1, p, *size - pos);
				(*size)--; // block will shrink by 1 byte
			}
			if (ctrack->dp->hostcase && HttpFindHost(&pHost,segment,*size))
			{
				VPRINT("Changing 'Host:' => '%c%c%c%c:' at pos %td\n", ctrack->dp->hostspell[0], ctrack->dp->hostspell[1], ctrack->dp->hostspell[2], ctrack->dp->hostspell[3], pHost - segment);
				memcpy(pHost, ctrack->dp->hostspell, 4);
			}
			if (ctrack->dp->hostpad && HttpFindHost(&pHost,segment,*size))
			{
				//  add :  XXXXX: <padding?[\r\n|\n]
				char s[8];
				size_t hsize = ctrack->dp->unixeol ? 8 : 9;
				size_t hostpad = ctrack->dp->hostpad<hsize ? hsize : ctrack->dp->hostpad;

				if ((hsize+*size)>segment_buffer_size)
					VPRINT("could not add host padding : buffer too small\n");
				else
				{
					if ((hostpad+*size)>segment_buffer_size)
					{
						hostpad=segment_buffer_size-*size;
						VPRINT("host padding reduced to %zu bytes : buffer too small\n", hostpad);
					}
					else
						VPRINT("host padding with %zu bytes\n", hostpad);
					
					p = pHost;
					pos = p - segment;
					memmove(p + hostpad, p, *size - pos);
					(*size) += hostpad;
					while(hostpad)
					{
						#define MAX_HDR_SIZE	2048
						size_t padsize = hostpad > hsize ? hostpad-hsize : 0;
						if (padsize>MAX_HDR_SIZE) padsize=MAX_HDR_SIZE;
						// if next header would be too small then add extra padding to the current one
						if ((hostpad-padsize-hsize)<hsize) padsize+=hostpad-padsize-hsize;
						snprintf(s,sizeof(s),"%c%04x: ", 'a'+rand()%('z'-'a'+1), rand() & 0xFFFF);
						memcpy(p,s,7);
						p+=7;
						memset(p,'a'+rand()%('z'-'a'+1),padsize);
						p+=padsize;
						if (ctrack->dp->unixeol)
							*p++='\n';
						else
						{
							*p++='\r';
							*p++='\n';
						}
						hostpad-=hsize+padsize;
					}
					pHost = NULL; // invalidate
				}
			}
			if (multisplit_pos) ResolveMultiPos(segment, *size, l7proto, ctrack->dp->splits, ctrack->dp->split_count, multisplit_pos, multisplit_count);
			if (split_flags)
			{
				if (ctrack->dp->disorder_http) *split_flags |= SPLIT_FLAG_DISORDER;
				if (ctrack->dp->oob_http) *split_flags |= SPLIT_FLAG_OOB;
			}
			break;

		case TLS:
			if (multisplit_pos) ResolveMultiPos(segment, *size, l7proto, ctrack->dp->splits, ctrack->dp->split_count, multisplit_pos, multisplit_count);
			if ((5+*size)<=segment_buffer_size)
			{
				tpos = ResolvePos(segment, *size, l7proto, &ctrack->dp->tlsrec);
				if (tpos>5)
				{
					// construct 2 TLS records from one
					uint16_t l = pntoh16(segment+3); // length
					if (l>=2)
					{
						int i;
						size_t dlen;
						// length is checked in IsTLSClientHello and cannot exceed buffer size
						if ((tpos-5)>=l) tpos=5+1;
						VPRINT("making 2 TLS records at pos %zu\n",tpos);
						memmove(segment+tpos+5,segment+tpos,*size-tpos);
						segment[tpos] = segment[0];
						segment[tpos+1] = segment[1];
						segment[tpos+2] = segment[2];
						phton16(segment+tpos+3,l-(tpos-5));
						phton16(segment+3,tpos-5);
						*size += 5;
						VPRINT("-2nd TLS record: ");
						dlen = tpos<16 ? tpos : 16;
						packet_debug(segment+tpos-dlen,dlen);
						VPRINT("+2nd TLS record: ");
						packet_debug(segment+tpos,*size-tpos);
						// fix split positions after tlsrec. increase split pos by tlsrec header size (5 bytes)
						if (multisplit_pos)
							for(i=0;i<*multisplit_count;i++)
								if (multisplit_pos[i]>tpos) multisplit_pos[i]+=5;
					}
				}
			}
			if (split_flags)
			{
				if (ctrack->dp->disorder_tls) *split_flags |= SPLIT_FLAG_DISORDER;
				if (ctrack->dp->oob_tls) *split_flags |= SPLIT_FLAG_OOB;
			}
			break;

		default:
			if (multisplit_pos && ctrack->dp->split_any_protocol)
				ResolveMultiPos(segment, *size, l7proto, ctrack->dp->splits, ctrack->dp->split_count, multisplit_pos, multisplit_count);
	}

	if (split_flags)
	{
		if (ctrack->dp->disorder) *split_flags |= SPLIT_FLAG_DISORDER;
		if (ctrack->dp->oob) *split_flags |= SPLIT_FLAG_OOB;
	}
	if (orig_size!=*size)
	{
		VPRINT("segment size changed: %zu -> %zu\n", orig_size, *size);
	}
	if (params.debug && multisplit_count && *multisplit_count)
	{
		VPRINT("multisplit pos: ");
		for (int i=0;i<*multisplit_count;i++) VPRINT("%zu ",multisplit_pos[i]);
		VPRINT("\n");
	}
}

static void auto_hostlist_reset_fail_counter(struct desync_profile *dp, const char *hostname, const char *client_ip_port, t_l7proto l7proto)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;
	
		fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
			VPRINT("auto hostlist (profile %d) : %s : fail counter reset. website is working.\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : fail counter reset. website is working.", hostname, dp->n, client_ip_port, l7proto_str(l7proto));
		}
	}
}

static void auto_hostlist_failed(struct desync_profile *dp, const char *hostname, const char *client_ip_port, t_l7proto l7proto)
{
	hostfail_pool *fail_counter;

	fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
	if (!fail_counter)
	{
		fail_counter = HostFailPoolAdd(&dp->hostlist_auto_fail_counters, hostname, dp->hostlist_auto_fail_time);
		if (!fail_counter)
		{
			DLOG_ERR("HostFailPoolAdd: out of memory\n");
			return;
		}
	}
	fail_counter->counter++;
	VPRINT("auto hostlist (profile %d) : %s : fail counter %d/%d\n", dp->n , hostname, fail_counter->counter, dp->hostlist_auto_fail_threshold);
	HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : fail counter %d/%d", hostname, dp->n, client_ip_port, l7proto_str(l7proto), fail_counter->counter, dp->hostlist_auto_fail_threshold);
	if (fail_counter->counter >= dp->hostlist_auto_fail_threshold)
	{
		VPRINT("auto hostlist (profile %d) : fail threshold reached. adding %s to auto hostlist\n", dp->n , hostname);
		HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
		
		VPRINT("auto hostlist (profile %d) : rechecking %s to avoid duplicates\n", dp->n, hostname);
		bool bExcluded=false;
		if (!HostlistCheck(dp, hostname, &bExcluded, false) && !bExcluded)
		{
			VPRINT("auto hostlist (profile %d) : adding %s to %s\n", dp->n, hostname, dp->hostlist_auto->filename);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : adding to %s", hostname, dp->n, client_ip_port, l7proto_str(l7proto), dp->hostlist_auto->filename);
			if (!HostlistPoolAddStr(&dp->hostlist_auto->hostlist, hostname, 0))
			{
				DLOG_ERR("StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(dp->hostlist_auto->filename, hostname))
			{
				DLOG_PERROR("write to auto hostlist:");
				return;
			}
			if (!file_mod_signature(dp->hostlist_auto->filename, &dp->hostlist_auto->mod_sig))
				DLOG_PERROR("file_mod_signature");
		}
		else
		{
			VPRINT("auto hostlist (profile %d) : NOT adding %s\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : NOT adding, duplicate detected", hostname, dp->n, client_ip_port, l7proto_str(l7proto));
		}
	}
}

void tamper_in(t_ctrack *ctrack, const struct sockaddr *client, uint8_t *segment,size_t segment_buffer_size,size_t *size)
{
	DBGPRINT("tamper_in hostname=%s\n", ctrack->hostname);

	bool bFail=false;

	char client_ip_port[48];
	if (*params.hostlist_auto_debuglog)
		ntop46_port((struct sockaddr*)client,client_ip_port,sizeof(client_ip_port));
	else
		*client_ip_port=0;

	if (ctrack->dp && ctrack->b_ah_check)
	{
		HostFailPoolPurgeRateLimited(&ctrack->dp->hostlist_auto_fail_counters);

		if (ctrack->l7proto==HTTP && ctrack->hostname)
		{
			if (IsHttpReply(segment,*size))
			{
				VPRINT("incoming HTTP reply detected for hostname %s\n", ctrack->hostname);
				bFail = HttpReplyLooksLikeDPIRedirect(segment, *size, ctrack->hostname);
				if (bFail)
				{
					VPRINT("redirect to another domain detected. possibly DPI redirect.\n");
					HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : redirect to another domain", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
				}
				else
					VPRINT("local or in-domain redirect detected. it's not a DPI redirect.\n");
			}
			else
			{
				// received not http reply. do not monitor this connection anymore
				VPRINT("incoming unknown HTTP data detected for hostname %s\n", ctrack->hostname);
			}
			if (bFail) auto_hostlist_failed(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
		}
		if (!bFail) auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
	}
	ctrack->bTamperInCutoff = true;
}

void rst_in(t_ctrack *ctrack, const struct sockaddr *client)
{
	DBGPRINT("rst_in hostname=%s\n", ctrack->hostname);

	char client_ip_port[48];
	if (*params.hostlist_auto_debuglog)
		ntop46_port((struct sockaddr*)client,client_ip_port,sizeof(client_ip_port));
	else
		*client_ip_port=0;

	if (ctrack->dp && ctrack->b_ah_check)
	{
		HostFailPoolPurgeRateLimited(&ctrack->dp->hostlist_auto_fail_counters);

		if (!ctrack->bTamperInCutoff && ctrack->hostname)
		{
			VPRINT("incoming RST detected for hostname %s\n", ctrack->hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : incoming RST", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
			auto_hostlist_failed(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
		}
	}
}
void hup_out(t_ctrack *ctrack, const struct sockaddr *client)
{
	DBGPRINT("hup_out hostname=%s\n", ctrack->hostname);
	
	char client_ip_port[48];
	if (*params.hostlist_auto_debuglog)
		ntop46_port((struct sockaddr*)client,client_ip_port,sizeof(client_ip_port));
	else
		*client_ip_port=0;

	if (ctrack->dp && ctrack->b_ah_check)
	{
		HostFailPoolPurgeRateLimited(&ctrack->dp->hostlist_auto_fail_counters);

		if (!ctrack->bTamperInCutoff && ctrack->hostname)
		{
			// local leg dropped connection after first request. probably due to timeout.
			VPRINT("local leg closed connection after first request (timeout ?). hostname: %s\n", ctrack->hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client %s : proto %s : client closed connection without server reply", ctrack->hostname, ctrack->dp->n, client_ip_port, l7proto_str(ctrack->l7proto));
			auto_hostlist_failed(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
		}
	}
}
