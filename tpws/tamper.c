#define _GNU_SOURCE

#include "tamper.h"
#include "hostlist.h"
#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <stdio.h>

static bool dp_match_l3l4(struct desync_profile *dp, bool ipv6, uint16_t tcp_port)
{
	return \
		((!ipv6 && dp->filter_ipv4) || (ipv6 && dp->filter_ipv6)) &&
		(!tcp_port || pf_in_range(tcp_port,&dp->pf_tcp));
}
static bool dp_match(struct desync_profile *dp, bool ipv6, uint16_t tcp_port, const char *hostname)
{
	if (dp_match_l3l4(dp,ipv6,tcp_port))
	{
		// autohostlist profile matching l3/l4 filter always win
		if (*dp->hostlist_auto_filename) return true;

		if (dp->hostlist || dp->hostlist_exclude)
		{
			// without known hostname first profile matching l3/l4 filter and without hostlist filter wins
			if (hostname)
				return HostlistCheck(dp, hostname, NULL);
		}
		else
			// profile without hostlist filter wins
			return true;
	}
	return false;
}
static struct desync_profile *dp_find(struct desync_profile_list_head *head, bool ipv6, uint16_t tcp_port, const char *hostname)
{
	struct desync_profile_list *dpl;
	VPRINT("desync profile search for hostname='%s' ipv6=%u tcp_port=%u\n", hostname ? hostname : "", ipv6, tcp_port);
	LIST_FOREACH(dpl, head, next)
	{
		if (dp_match(&dpl->dp,ipv6,tcp_port,hostname))
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
	ctrack->dp = dp_find(&params.desync_profiles, dest->sa_family==AF_INET6, saport(dest), ctrack->hostname);
}



// segment buffer has at least 5 extra bytes to extend data block
void tamper_out(t_ctrack *ctrack, const struct sockaddr *dest, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *split_pos, uint8_t *split_flags)
{
	uint8_t *p, *pp, *pHost = NULL;
	size_t method_len = 0, pos;
	size_t tpos, spos;
	const char *method;
	bool bHaveHost = false;
	char *pc, Host[256];
	t_l7proto l7proto;

	DBGPRINT("tamper_out\n");

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

	*split_pos=0;
	*split_flags=0;

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

	if (ctrack->l7proto==UNKNOWN) ctrack->l7proto=l7proto;

	if (bHaveHost)
	{
		VPRINT("request hostname: %s\n", Host);
		if (!ctrack->hostname)
		{
			if (!(ctrack->hostname=strdup(Host)))
			{
				DLOG_ERR("strdup hostname : out of memory\n");
				return;
			}

			struct desync_profile *dp_prev = ctrack->dp;
			apply_desync_profile(ctrack, dest);
			if (ctrack->dp!=dp_prev)
				VPRINT("desync profile changed by revealed hostname !\n");
			else if (*ctrack->dp->hostlist_auto_filename)
			{
				bool bHostExcluded;
				if (!HostlistCheck(ctrack->dp, Host, &bHostExcluded))
				{
					ctrack->b_ah_check = !bHostExcluded;
					VPRINT("Not acting on this request\n");
					return;
				}
			}
		}
	}
	
	if (!ctrack->dp) return;

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
			*split_pos = HttpPos(ctrack->dp->split_http_req, ctrack->dp->split_pos, segment, *size);
			if (ctrack->dp->disorder_http) *split_flags |= SPLIT_FLAG_DISORDER;
			if (ctrack->dp->oob_http) *split_flags |= SPLIT_FLAG_OOB;
			break;

		case TLS:
			spos = TLSPos(ctrack->dp->split_tls, ctrack->dp->split_pos, segment, *size, 0);
			if ((5+*size)<=segment_buffer_size)
			{
				tpos = TLSPos(ctrack->dp->tlsrec, ctrack->dp->tlsrec_pos+5, segment, *size, 0);
				if (tpos>5)
				{
					// construct 2 TLS records from one
					uint16_t l = pntoh16(segment+3); // length
					if (l>=2)
					{
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
						// split pos present and it is not before tlsrec split. increase split pos by tlsrec header size (5 bytes)
						if (spos && spos>=tpos) spos+=5;
					}
				}
			}

			if (spos && spos < *size)
				*split_pos = spos;

			if (ctrack->dp->disorder_tls) *split_flags |= SPLIT_FLAG_DISORDER;
			if (ctrack->dp->oob_tls) *split_flags |= SPLIT_FLAG_OOB;
			
			break;

		default:
			if (ctrack->dp->split_any_protocol && ctrack->dp->split_pos < *size)
				*split_pos = ctrack->dp->split_pos;
	}
		
	if (ctrack->dp->disorder) *split_flags |= SPLIT_FLAG_DISORDER;
	if (ctrack->dp->oob) *split_flags |= SPLIT_FLAG_OOB;
}

static void auto_hostlist_reset_fail_counter(struct desync_profile *dp, const char *hostname)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;
	
		fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
			VPRINT("auto hostlist (profile %d) : %s : fail counter reset. website is working.\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : fail counter reset. website is working.", hostname, dp->n);
		}
	}
}

static void auto_hostlist_failed(struct desync_profile *dp, const char *hostname)
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
	HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : fail counter %d/%d", hostname, dp->n, fail_counter->counter, dp->hostlist_auto_fail_threshold);
	if (fail_counter->counter >= dp->hostlist_auto_fail_threshold)
	{
		VPRINT("auto hostlist (profile %d) : fail threshold reached. adding %s to auto hostlist\n", dp->n , hostname);
		HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
		
		VPRINT("auto hostlist (profile %d) : rechecking %s to avoid duplicates\n", dp->n, hostname);
		bool bExcluded=false;
		if (!HostlistCheck(dp, hostname, &bExcluded) && !bExcluded)
		{
			VPRINT("auto hostlist (profile %d) : adding %s to %s\n", dp->n, hostname, dp->hostlist_auto_filename);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : adding to %s", hostname, dp->n, dp->hostlist_auto_filename);
			if (!StrPoolAddStr(&dp->hostlist, hostname))
			{
				DLOG_ERR("StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(dp->hostlist_auto_filename, hostname))
			{
				DLOG_PERROR("write to auto hostlist:");
				return;
			}
			dp->hostlist_auto_mod_time = file_mod_time(dp->hostlist_auto_filename);
		}
		else
		{
			VPRINT("auto hostlist (profile %d) : NOT adding %s\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : NOT adding, duplicate detected", hostname, dp->n);
		}
	}
}

void tamper_in(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size)
{
	bool bFail=false;

	DBGPRINT("tamper_in hostname=%s\n", ctrack->hostname);

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
					HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : redirect to another domain", ctrack->hostname, ctrack->dp->n);
				}
				else
					VPRINT("local or in-domain redirect detected. it's not a DPI redirect.\n");
			}
			else
			{
				// received not http reply. do not monitor this connection anymore
				VPRINT("incoming unknown HTTP data detected for hostname %s\n", ctrack->hostname);
			}
			if (bFail) auto_hostlist_failed(ctrack->dp, ctrack->hostname);
		}
		if (!bFail) auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname);
	}
	ctrack->bTamperInCutoff = true;
}

void rst_in(t_ctrack *ctrack)
{
	DBGPRINT("rst_in hostname=%s\n", ctrack->hostname);

	if (ctrack->dp && ctrack->b_ah_check)
	{
		HostFailPoolPurgeRateLimited(&ctrack->dp->hostlist_auto_fail_counters);

		if (!ctrack->bTamperInCutoff && ctrack->hostname)
		{
			VPRINT("incoming RST detected for hostname %s\n", ctrack->hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : incoming RST", ctrack->hostname, ctrack->dp->n);
			auto_hostlist_failed(ctrack->dp, ctrack->hostname);
		}
	}
}
void hup_out(t_ctrack *ctrack)
{
	DBGPRINT("hup_out hostname=%s\n", ctrack->hostname);
	
	if (ctrack->dp && ctrack->b_ah_check)
	{
		HostFailPoolPurgeRateLimited(&ctrack->dp->hostlist_auto_fail_counters);

		if (!ctrack->bTamperInCutoff && ctrack->hostname)
		{
			// local leg dropped connection after first request. probably due to timeout.
			VPRINT("local leg closed connection after first request (timeout ?). hostname: %s\n", ctrack->hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %d : client closed connection without server reply", ctrack->hostname, ctrack->dp->n);
			auto_hostlist_failed(ctrack->dp, ctrack->hostname);
		}
	}
}
