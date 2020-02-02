#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
bool IsHttp(const char *data, size_t len)
{
	const char **method;
	size_t method_len;
	for (method = http_methods; *method; method++)
	{
		method_len = strlen(*method);
		if (method_len <= len && !memcmp(data, *method, method_len))
			return true;
	}
	return false;
}
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	const uint8_t *p, *s, *e=data+len;

	p = (uint8_t*)strncasestr((char*)data, "\nHost:", len);
	if (!p) return false;
	p+=6;
	while(p<e && (*p==' ' || *p=='\t')) p++;
	s=p;
	while(s<e && (*s!='\r' && *s!='\n' && *s!=' ' && *s!='\t')) s++;
	if (s>p)
	{
		size_t slen = s-p;
		if (host && len_host)
		{
			if (slen>=len_host) slen=len_host-1;
			for(size_t i=0;i<slen;i++) host[i]=tolower(p[i]);
			host[slen]=0;
		}
		return true;
	}
	return false;
}
bool IsTLSClientHello(const uint8_t *data, size_t len)
{
	return len>=6 && data[0]==0x16 && data[1]==0x03 && data[2]==0x01 && data[5]==0x01 && (ntohs(*(uint16_t*)(data+3))+5)<=len;
}
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext)
{
	// +0
	// u8	ContentType: Handshake
	// u16	Version: TLS1.0
	// u16	Length
	// +5 
	// u8	HandshakeType: ClientHello
	// u24	Length
	// u16	Version
	// c[32] random
	// u8	SessionIDLength
	//	<SessionID>
	// u16	CipherSuitesLength
	//	<CipherSuites>
	// u8	CompressionMethodsLength
	//	<CompressionMethods>
	// u16	ExtensionsLength

	size_t l,ll;

	l = 1+2+2+1+3+2+32;
	// SessionIDLength
	if (len<(l+1)) return false;
	ll = data[6]<<16 | data[7]<<8 | data[8]; // HandshakeProtocol length
	if (len<(ll+9)) return false;
	l += data[l]+1;
	// CipherSuitesLength
	if (len<(l+2)) return false;
	l += ntohs(*(uint16_t*)(data+l))+2;
	// CompressionMethodsLength
	if (len<(l+1)) return false;
	l += data[l]+1;
	// ExtensionsLength
	if (len<(l+2)) return false;

	data+=l; len-=l;
	l=ntohs(*(uint16_t*)data);
	data+=2; len-=2;
	if (l<len) return false;

	uint16_t ntype=htons(type);
	while(l>=4)
	{
		uint16_t etype=*(uint16_t*)data;
		size_t elen=ntohs(*(uint16_t*)(data+2));
		data+=4; l-=4;
		if (l<elen) break;
		if (etype==ntype)
		{
			if (ext && len_ext)
			{
				*ext = data;
				*len_ext = elen;
			}
			return true;
		}
		data+=elen; l-=elen;
	}

	return false;
}
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data,len,0,&ext,&elen)) return false;
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (elen<5 || ext[2]!=0) return false;
	size_t slen = ntohs(*(uint16_t*)(ext+3));
	ext+=5; elen-=5;
	if (slen<elen) return false;
	if (ext && len_host)
	{
		if (slen>=len_host) slen=len_host-1;
		for(size_t i=0;i<slen;i++) host[i]=tolower(ext[i]);
		host[slen]=0;
	}
	return true;
}
