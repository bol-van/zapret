#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>


const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
const char *HttpMethod(const uint8_t *data, size_t len)
{
	const char **method;
	size_t method_len;
	for (method = http_methods; *method; method++)
	{
		method_len = strlen(*method);
		if (method_len <= len && !memcmp(data, *method, method_len))
			return *method;
	}
	return NULL;
}
bool IsHttp(const uint8_t *data, size_t len)
{
	return !!HttpMethod(data,len);
}

static bool IsHostAt(const uint8_t *p)
{
	return \
		p[0]=='\n' &&
		(p[1]=='H' || p[1]=='h') &&
		(p[2]=='o' || p[2]=='O') &&
		(p[3]=='s' || p[3]=='S') &&
		(p[4]=='t' || p[4]=='T') &&
		p[5]==':';
}
static uint8_t *FindHostIn(uint8_t *buf, size_t bs)
{
	size_t pos;
	if (bs<6) return NULL;
	bs-=6;
	for(pos=0;pos<=bs;pos++)
		if (IsHostAt(buf+pos))
			return buf+pos;

	return NULL;
}
static const uint8_t *FindHostInConst(const uint8_t *buf, size_t bs)
{
	size_t pos;
	if (bs<6) return NULL;
	bs-=6;
	for(pos=0;pos<=bs;pos++)
		if (IsHostAt(buf+pos))
			return buf+pos;

	return NULL;
}
// pHost points to "Host: ..."
bool HttpFindHost(uint8_t **pHost,uint8_t *buf,size_t bs)
{
	if (!*pHost)
	{
		*pHost = FindHostIn(buf, bs);
		if (*pHost) (*pHost)++;
	}
	return !!*pHost;
}
bool HttpFindHostConst(const uint8_t **pHost,const uint8_t *buf,size_t bs)
{
	if (!*pHost)
	{
		*pHost = FindHostInConst(buf, bs);
		if (*pHost) (*pHost)++;
	}
	return !!*pHost;
}
bool IsHttpReply(const uint8_t *data, size_t len)
{
	// HTTP/1.x 200\r\n
	return len>14 && !memcmp(data,"HTTP/1.",7) && (data[7]=='0' || data[7]=='1') && data[8]==' ' &&
		data[9]>='0' && data[9]<='9' &&
		data[10]>='0' && data[10]<='9' &&
		data[11]>='0' && data[11]<='9';
}
int HttpReplyCode(const uint8_t *data, size_t len)
{
	return (data[9]-'0')*100 + (data[10]-'0')*10 + (data[11]-'0');
}
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf)
{
	const uint8_t *p, *s, *e = data + len;

	p = (uint8_t*)strncasestr((char*)data, header, len);
	if (!p) return false;
	p += strlen(header);
	while (p < e && (*p == ' ' || *p == '\t')) p++;
	s = p;
	while (s < e && (*s != '\r' && *s != '\n' && *s != ' ' && *s != '\t')) s++;
	if (s > p)
	{
		size_t slen = s - p;
		if (buf && len_buf)
		{
			if (slen >= len_buf) slen = len_buf - 1;
			for (size_t i = 0; i < slen; i++) buf[i] = tolower(p[i]);
			buf[slen] = 0;
		}
		return true;
	}
	return false;
}
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	return HttpExtractHeader(data, len, "\nHost:", host, len_host);
}
const char *HttpFind2ndLevelDomain(const char *host)
{
	const char *p=NULL;
	if (*host)
	{
		for (p = host + strlen(host)-1; p>host && *p!='.'; p--);
		if (*p=='.') for (p--; p>host && *p!='.'; p--);
		if (*p=='.') p++;
	}
	return p;
}
// DPI redirects are global redirects to another domain
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host)
{
	char loc[256],*redirect_host, *p;
	int code;
	
	if (!host || !*host) return false;
	
	code = HttpReplyCode(data,len);
	
	if ((code!=302 && code!=307) || !HttpExtractHeader(data,len,"\nLocation:",loc,sizeof(loc))) return false;

	// something like : https://censor.net/badpage.php?reason=denied&source=RKN
		
	if (!strncmp(loc,"http://",7))
		redirect_host=loc+7;
	else if (!strncmp(loc,"https://",8))
		redirect_host=loc+8;
	else
		return false;
		
	// somethinkg like : censor.net/badpage.php?reason=denied&source=RKN
	
	for(p=redirect_host; *p && *p!='/' ; p++);
	*p=0;
	if (!*redirect_host) return false;

	// somethinkg like : censor.net
	
	// extract 2nd level domains

	const char *dhost = HttpFind2ndLevelDomain(host);
	const char *drhost = HttpFind2ndLevelDomain(redirect_host);
	
	return strcasecmp(dhost, drhost)!=0;
}
size_t HttpPos(enum httpreqpos tpos_type, size_t hpos_pos, const uint8_t *http, size_t sz)
{
	const uint8_t *method, *host=NULL;
	int i;
	
	switch(tpos_type)
	{
		case httpreqpos_method:
			// recognize some tpws pre-applied hacks
			method=http;
			if (sz<10) break;
			if (*method=='\n' || *method=='\r') method++;
			if (*method=='\n' || *method=='\r') method++;
			for (i=0;i<7;i++) if (*method>='A' && *method<='Z') method++;
			if (i<3 || *method!=' ') break;
			return method-http-1;
		case httpreqpos_host:
			if (HttpFindHostConst(&host,http,sz) && (host-http+7)<sz)
			{
				host+=5;
				if (*host==' ') host++;
				return host-http;
			}
			break;
		case httpreqpos_pos:
			break;
		default:
			return 0;
	}
	return hpos_pos<sz ? hpos_pos : 0;
}



uint16_t TLSRecordDataLen(const uint8_t *data)
{
	return pntoh16(data + 3);
}
size_t TLSRecordLen(const uint8_t *data)
{
	return TLSRecordDataLen(data) + 5;
}
bool IsTLSRecordFull(const uint8_t *data, size_t len)
{
	return TLSRecordLen(data)<=len;
}
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return len >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03 && data[5] == 0x01 && (bPartialIsOK || TLSRecordLen(data) <= len);
}

// bPartialIsOK=true - accept partial packets not containing the whole TLS message
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK)
{
	// +0
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

	size_t l, ll;

	l = 1 + 3 + 2 + 32;
	// SessionIDLength
	if (len < (l + 1)) return false;
	if (!bPartialIsOK)
	{
	    ll = data[1] << 16 | data[2] << 8 | data[3]; // HandshakeProtocol length
	    if (len < (ll + 4)) return false;
	}
	l += data[l] + 1;
	// CipherSuitesLength
	if (len < (l + 2)) return false;
	l += pntoh16(data + l) + 2;
	// CompressionMethodsLength
	if (len < (l + 1)) return false;
	l += data[l] + 1;
	// ExtensionsLength
	if (len < (l + 2)) return false;

	data += l; len -= l;
	l = pntoh16(data);
	data += 2; len -= 2;
	
	if (bPartialIsOK)
	{
		if (len < l) l = len;
	}
	else
	{
		if (len < l) return false;
	}

	while (l >= 4)
	{
		uint16_t etype = pntoh16(data);
		size_t elen = pntoh16(data + 2);
		data += 4; l -= 4;
		if (l < elen) break;
		if (etype == type)
		{
			if (ext && len_ext)
			{
				*ext = data;
				*len_ext = elen;
			}
			return true;
		}
		data += elen; l -= elen;
	}

	return false;
}
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK)
{
	// +0
	// u8	ContentType: Handshake
	// u16	Version: TLS1.0
	// u16	Length
	size_t reclen;
	if (!IsTLSClientHello(data, len, bPartialIsOK)) return false;
	reclen=TLSRecordLen(data);
	if (reclen<len) len=reclen; // correct len if it has more data than the first tls record has
	return TLSFindExtInHandshake(data + 5, len - 5, type, ext, len_ext, bPartialIsOK);
}
static bool TLSExtractHostFromExt(const uint8_t *ext, size_t elen, char *host, size_t len_host)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (elen < 5 || ext[2] != 0) return false;
	size_t slen = pntoh16(ext + 3);
	ext += 5; elen -= 5;
	if (slen < elen) return false;
	if (host && len_host)
	{
		if (slen >= len_host) slen = len_host - 1;
		for (size_t i = 0; i < slen; i++) host[i] = tolower(ext[i]);
		host[slen] = 0;
	}
	return true;
}
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data, len, 0, &ext, &elen, bPartialIsOK)) return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExtInHandshake(data, len, 0, &ext, &elen, bPartialIsOK)) return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}
size_t TLSPos(enum tlspos tpos_type, size_t tpos_pos, const uint8_t *tls, size_t sz, uint8_t type)
{
	size_t elen;
	const uint8_t *ext;
	switch(tpos_type)
	{
		case tlspos_sni:
		case tlspos_sniext:
			if (TLSFindExt(tls,sz,0,&ext,&elen,false))
				return (tpos_type==tlspos_sni) ? ext-tls+6 : ext-tls+1;
			// fall through
		case tlspos_pos:
			return tpos_pos<sz ? tpos_pos : 0;
		default:
			return 0;
	}
}
