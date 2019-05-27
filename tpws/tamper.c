#include "tamper.h"
#include "params.h"
#include <string.h>
#include <stdio.h>

char *find_bin(void *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data = (char*)data + 1;
		len--;
	}
	return NULL;
}

// pHost points to "Host: ..."
bool find_host(char **pHost,char *buf,size_t bs)
{
	if (!*pHost)
	{
		*pHost = find_bin(buf, bs, "\nHost: ", 7);
		if (*pHost) (*pHost)++;
		printf("Found Host: at pos %zu\n",*pHost - buf);
	}
	return !!*pHost;
}

static const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
void modify_tcp_segment(char *segment,size_t *size,size_t *split_pos)
{
	char *p, *pp, *pHost = NULL;
	size_t method_len = 0, pos;
	const char **method;
	bool bIsHttp = false, bBypass = false;
	char bRemovedHostSpace = 0;
	char Host[128];
	
	*split_pos=0;

	for (method = http_methods; *method; method++)
	{
		method_len = strlen(*method);
		if (method_len <= *size && !memcmp(segment, *method, method_len))
		{
			bIsHttp = true;
			method_len -= 2; // "GET /" => "GET"
			break;
		}
	}
	if (bIsHttp)
	{
		printf("Data block looks like http request start : %s\n", *method);
		// cpu saving : we search host only if and when required. we do not research host every time we need its position
		if (params.hostlist && find_host(&pHost,segment,*size))
		{
			bool bInHostList = false;
			p = pHost + 6;
			while (p < (segment + *size) && (*p == ' ' || *p == '\t')) p++;
			pp = p;
			while (pp < (segment + *size) && (pp - p) < (sizeof(Host) - 1) && *pp != '\r' && *pp != '\n') pp++;
			memcpy(Host, p, pp - p);
			Host[pp - p] = '\0';
			printf("Requested Host is : %s\n", Host);
			for(p = Host; *p; p++) *p=tolower(*p);
			p = Host;
			while (p)
			{
				bInHostList = StrPoolCheckStr(params.hostlist, p);
				printf("Hostlist check for %s : %s\n", p, bInHostList ? "positive" : "negative");
				if (bInHostList) break;
				p = strchr(p, '.');
				if (p) p++;
			}
			bBypass = !bInHostList;
		}
		if (!bBypass)
		{
			if (params.unixeol)
			{
				p = pp = segment;
				while (p = find_bin(p, segment + *size - p, "\r\n", 2))
				{
					*p = '\n'; p++;
					memmove(p, p + 1, segment + *size - p - 1);
					(*size)--;
					if (pp == (p - 1))
					{
						// probably end of http headers
						printf("Found double EOL at pos %zu. Stop replacing.\n", pp - segment);
						break;
					}
					pp = p;
				}
				pHost = NULL; // invalidate
			}

			if (params.methodspace)
			{
				// we only work with data blocks looking as HTTP query, so method is at the beginning
				printf("Adding extra space after method\n");
				p = segment + method_len + 1;
				pos = method_len + 1;
				memmove(p + 1, p, *size - pos);
				*p = ' '; // insert extra space
				(*size)++; // block will grow by 1 byte
				if (pHost) pHost++; // Host: position will move by 1 byte
			}
			if ((params.hostdot || params.hosttab) && find_host(&pHost,segment,*size))
			{
				p = pHost + 6;
				while (p < (segment + *size) && *p != '\r' && *p != '\n') p++;
				if (p < (segment + *size))
				{
					pos = p - segment;
					printf("Adding %s to host name at pos %zu\n", params.hostdot ? "dot" : "tab", pos);
					memmove(p + 1, p, *size - pos);
					*p = params.hostdot ? '.' : '\t'; // insert dot or tab
					(*size)++; // block will grow by 1 byte
				}
			}
			if (params.hostnospace && find_host(&pHost,segment,*size) && pHost[5] == ' ')
			{
				p = pHost + 6;
				pos = p - segment;
				printf("Removing space before host name at pos %zu\n", pos);
				memmove(p - 1, p, *size - pos);
				(*size)--; // block will shrink by 1 byte
				bRemovedHostSpace = 1;
			}
			if (!params.split_pos)
			{
				switch (params.split_http_req)
				{
				case split_method:
					*split_pos = method_len - 1;
					break;
				case split_host:
					if (find_host(&pHost,segment,*size))
						*split_pos = pHost + 6 - bRemovedHostSpace - segment;
					break;
				}
			}
			if (params.hostcase && find_host(&pHost,segment,*size))
			{
				printf("Changing 'Host:' => '%c%c%c%c:' at pos %zu\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3], pHost - segment);
				memcpy(pHost, params.hostspell, 4);
			}
			if (params.methodeol)
			{
				printf("Adding EOL before method\n");
				if (params.unixeol)
				{
					memmove(segment + 1, segment, *size);
					(*size)++;;
					segment[0] = '\n';
					if (*split_pos) (*split_pos)++;
				}
				else
				{
					memmove(segment + 2, segment, *size);
					*size += 2;
					segment[0] = '\r';
					segment[1] = '\n';
					if (*split_pos) *split_pos += 2;
				}
			}
			if (params.split_pos && params.split_pos < *size) *split_pos = params.split_pos;
		}
		else
		{
			printf("Not acting on this request\n");
		}
	}
	else
	{
		printf("Data block does not look like http request start\n");
		// this is the only parameter applicable to non-http block (may be https ?)
		if (params.split_pos && params.split_pos < *size) *split_pos = params.split_pos;
	}
}
