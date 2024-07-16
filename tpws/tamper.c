#define _GNU_SOURCE

#include "tamper.h"
#include "params.h"
#include "hostlist.h"
#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <stdio.h>

// segment buffer has at least 5 extra bytes to extend data block
void tamper_out(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *split_pos, uint8_t *split_flags)
{
	uint8_t *p, *pp, *pHost = NULL;
	size_t method_len = 0, pos;
	const char *method;
	bool bBypass = false, bHaveHost = false, bHostExcluded = false;
	char bRemovedHostSpace = 0;
	char *pc, Host[256];
	
	DBGPRINT("tamper_out")

	*split_pos=0;
	*split_flags=0;

	if ((method = HttpMethod(segment,*size)))
	{
		method_len = strlen(method)-2;
		VPRINT("Data block looks like http request start : %s", method)
		if (!ctrack->l7proto) ctrack->l7proto=HTTP;
		// cpu saving : we search host only if and when required. we do not research host every time we need its position
		if ((params.hostlist || params.hostlist_exclude) && HttpFindHost(&pHost,segment,*size))
		{
			p = pHost + 5;
			while (p < (segment + *size) && (*p == ' ' || *p == '\t')) p++;
			pp = p;
			while (pp < (segment + *size) && (pp - p) < (sizeof(Host) - 1) && *pp != '\r' && *pp != '\n') pp++;
			memcpy(Host, p, pp - p);
			Host[pp - p] = '\0';
			bHaveHost = true;
			VPRINT("Requested Host is : %s", Host)
			for(pc = Host; *pc; pc++) *pc=tolower(*pc);
			bBypass = !HostlistCheck(Host, &bHostExcluded);
		}
		if (!bBypass)
		{
			if (params.unixeol)
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
						VPRINT("Found double EOL at pos %td. Stop replacing.", pp - segment)
						break;
					}
					pp = p;
				}
				pHost = NULL; // invalidate
			}
			if (params.methodeol && (*size+1+!params.unixeol)<=segment_buffer_size)
			{
				VPRINT("Adding EOL before method")
				if (params.unixeol)
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
			if (params.methodspace && *size<segment_buffer_size)
			{
				// we only work with data blocks looking as HTTP query, so method is at the beginning
				VPRINT("Adding extra space after method")
				p = segment + method_len + 1;
				pos = method_len + 1;
				memmove(p + 1, p, *size - pos);
				*p = ' '; // insert extra space
				(*size)++; // block will grow by 1 byte
				if (pHost) pHost++; // Host: position will move by 1 byte
			}
			if ((params.hostdot || params.hosttab) && *size<segment_buffer_size && HttpFindHost(&pHost,segment,*size))
			{
				p = pHost + 5;
				while (p < (segment + *size) && *p != '\r' && *p != '\n') p++;
				if (p < (segment + *size))
				{
					pos = p - segment;
					VPRINT("Adding %s to host name at pos %zu", params.hostdot ? "dot" : "tab", pos)
					memmove(p + 1, p, *size - pos);
					*p = params.hostdot ? '.' : '\t'; // insert dot or tab
					(*size)++; // block will grow by 1 byte
				}
			}
			if (params.domcase && HttpFindHost(&pHost,segment,*size))
			{
				p = pHost + 5;
				pos = p - segment;
				VPRINT("Mixing domain case at pos %zu",pos)
				for (; p < (segment + *size) && *p != '\r' && *p != '\n'; p++)
					*p = (((size_t)p) & 1) ? tolower(*p) : toupper(*p);
			}
			if (params.hostnospace && HttpFindHost(&pHost,segment,*size) && (pHost+5)<(segment+*size) && pHost[5] == ' ')
			{
				p = pHost + 6;
				pos = p - segment;
				VPRINT("Removing space before host name at pos %zu", pos)
				memmove(p - 1, p, *size - pos);
				(*size)--; // block will shrink by 1 byte
				bRemovedHostSpace = 1;
			}
			if (params.hostcase && HttpFindHost(&pHost,segment,*size))
			{
				VPRINT("Changing 'Host:' => '%c%c%c%c:' at pos %td", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3], pHost - segment)
				memcpy(pHost, params.hostspell, 4);
			}
			if (params.hostpad && HttpFindHost(&pHost,segment,*size))
			{
				//  add :  XXXXX: <padding?[\r\n|\n]
				char s[8];
				size_t hsize = params.unixeol ? 8 : 9;
				size_t hostpad = params.hostpad<hsize ? hsize : params.hostpad;

				if ((hsize+*size)>segment_buffer_size)
					VPRINT("could not add host padding : buffer too small")
				else
				{
					if ((hostpad+*size)>segment_buffer_size)
					{
						hostpad=segment_buffer_size-*size;
						VPRINT("host padding reduced to %zu bytes : buffer too small", hostpad)
					}
					else
						VPRINT("host padding with %zu bytes", hostpad)
					
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
						if (params.unixeol)
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
			*split_pos = HttpPos(params.split_http_req, params.split_pos, segment, *size);
			if (params.disorder_http) *split_flags |= SPLIT_FLAG_DISORDER;
			if (params.oob_http) *split_flags |= SPLIT_FLAG_OOB;
		}
		else
		{
			VPRINT("Not acting on this request")
		}
	}
	else if (IsTLSClientHello(segment,*size,false))
	{
		size_t tpos=0,spos=0;
		const uint8_t *ext;
		
		if (!ctrack->l7proto) ctrack->l7proto=TLS;

		VPRINT("packet contains TLS ClientHello")
		// we need host only if hostlist is present
		if ((params.hostlist || params.hostlist_exclude) && TLSHelloExtractHost((uint8_t*)segment,*size,Host,sizeof(Host),false))
		{
			VPRINT("hostname: %s",Host)
			bHaveHost = true;
			bBypass = !HostlistCheck(Host, &bHostExcluded);
		}
		if (bBypass)
		{
			VPRINT("Not acting on this request")
		}
		else
		{
			spos = TLSPos(params.split_tls, params.split_pos, segment, *size, 0);

			if ((5+*size)<=segment_buffer_size)
			{
				tpos = TLSPos(params.tlsrec, params.tlsrec_pos+5, segment, *size, 0);
				if (tpos>5)
				{
					// construct 2 TLS records from one
					uint16_t l = pntoh16(segment+3); // length
					if (l>=2)
					{
						// length is checked in IsTLSClientHello and cannot exceed buffer size
						if ((tpos-5)>=l) tpos=5+1;
						VPRINT("making 2 TLS records at pos %zu",tpos)
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
			{
				VPRINT("split pos %zu",spos);
				*split_pos = spos;
			}

			if (params.disorder_tls) *split_flags |= SPLIT_FLAG_DISORDER;
			if (params.oob_tls) *split_flags |= SPLIT_FLAG_OOB;
		}
	}
	else if (params.split_any_protocol && params.split_pos < *size)
		*split_pos = params.split_pos;
		
	if (bHaveHost && bBypass && !bHostExcluded && *params.hostlist_auto_filename)
	{
		DBGPRINT("tamper_out put hostname : %s", Host)
		if (ctrack->hostname) free(ctrack->hostname);
		ctrack->hostname=strdup(Host);
	}
	if (params.disorder) *split_flags |= SPLIT_FLAG_DISORDER;
	if (params.oob) *split_flags |= SPLIT_FLAG_OOB;
}

static void auto_hostlist_reset_fail_counter(const char *hostname)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;
	
		fail_counter = HostFailPoolFind(params.hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&params.hostlist_auto_fail_counters, fail_counter);
			VPRINT("auto hostlist : %s : fail counter reset. website is working.", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : fail counter reset. website is working.", hostname);
		}
	}
}

static void auto_hostlist_failed(const char *hostname)
{
	hostfail_pool *fail_counter;

	fail_counter = HostFailPoolFind(params.hostlist_auto_fail_counters, hostname);
	if (!fail_counter)
	{
		fail_counter = HostFailPoolAdd(&params.hostlist_auto_fail_counters, hostname, params.hostlist_auto_fail_time);
		if (!fail_counter)
		{
			fprintf(stderr, "HostFailPoolAdd: out of memory\n");
			return;
		}
	}
	fail_counter->counter++;
	VPRINT("auto hostlist : %s : fail counter %d/%d", hostname, fail_counter->counter, params.hostlist_auto_fail_threshold);
	HOSTLIST_DEBUGLOG_APPEND("%s : fail counter %d/%d", hostname, fail_counter->counter, params.hostlist_auto_fail_threshold);
	if (fail_counter->counter >= params.hostlist_auto_fail_threshold)
	{
		VPRINT("auto hostlist : fail threshold reached. adding %s to auto hostlist", hostname);
		HostFailPoolDel(&params.hostlist_auto_fail_counters, fail_counter);
		
		VPRINT("auto hostlist : rechecking %s to avoid duplicates", hostname);
		bool bExcluded=false;
		if (!HostlistCheck(hostname, &bExcluded) && !bExcluded)
		{
			VPRINT("auto hostlist : adding %s", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : adding", hostname);
			if (!StrPoolAddStr(&params.hostlist, hostname))
			{
				fprintf(stderr, "StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(params.hostlist_auto_filename, hostname))
			{
				perror("write to auto hostlist:");
				return;
			}
			params.hostlist_auto_mod_time = file_mod_time(params.hostlist_auto_filename);
		}
		else
		{
			VPRINT("auto hostlist : NOT adding %s", hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : NOT adding, duplicate detected", hostname);
		}
	}
}

void tamper_in(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size)
{
	bool bFail=false;

	DBGPRINT("tamper_in hostname=%s", ctrack->hostname)

	if (*params.hostlist_auto_filename)
	{
		HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

		if (ctrack->l7proto==HTTP && ctrack->hostname)
		{
			if (IsHttpReply(segment,*size))
			{
				VPRINT("incoming HTTP reply detected for hostname %s", ctrack->hostname);
				bFail = HttpReplyLooksLikeDPIRedirect(segment, *size, ctrack->hostname);
				if (bFail)
				{
					VPRINT("redirect to another domain detected. possibly DPI redirect.")
					HOSTLIST_DEBUGLOG_APPEND("%s : redirect to another domain", ctrack->hostname);
				}
				else
					VPRINT("local or in-domain redirect detected. it's not a DPI redirect.")
			}
			else
			{
				// received not http reply. do not monitor this connection anymore
				VPRINT("incoming unknown HTTP data detected for hostname %s", ctrack->hostname);
			}
			if (bFail) auto_hostlist_failed(ctrack->hostname);

		}
		if (!bFail) auto_hostlist_reset_fail_counter(ctrack->hostname);

	}
	ctrack->bTamperInCutoff = true;
}

void rst_in(t_ctrack *ctrack)
{
	DBGPRINT("rst_in hostname=%s", ctrack->hostname)

	if (!*params.hostlist_auto_filename) return;

	HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

	if (!ctrack->bTamperInCutoff && ctrack->hostname)
	{
		VPRINT("incoming RST detected for hostname %s", ctrack->hostname);
		HOSTLIST_DEBUGLOG_APPEND("%s : incoming RST", ctrack->hostname);
		auto_hostlist_failed(ctrack->hostname);
	}
}
void hup_out(t_ctrack *ctrack)
{
	DBGPRINT("hup_out hostname=%s", ctrack->hostname)

	if (!*params.hostlist_auto_filename) return;

	HostFailPoolPurgeRateLimited(&params.hostlist_auto_fail_counters);

	if (!ctrack->bTamperInCutoff && ctrack->hostname)
	{
		// local leg dropped connection after first request. probably due to timeout.
		VPRINT("local leg closed connection after first request (timeout ?). hostname: %s", ctrack->hostname);
		HOSTLIST_DEBUGLOG_APPEND("%s : client closed connection without server reply", ctrack->hostname);
		auto_hostlist_failed(ctrack->hostname);
	}
}
