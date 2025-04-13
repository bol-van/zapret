#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

// find N level domain
static bool FindNLD(const uint8_t *dom, size_t dlen, int level, const uint8_t **p, size_t *len)
{
	int i;
	const uint8_t *p1,*p2;
	for (i=1,p2=dom+dlen;i<level;i++)
	{
		for (p2--; p2>dom && *p2!='.'; p2--);
		if (p2<=dom) return false;
	}
	for (p1=p2-1 ; p1>dom && *p1!='.'; p1--);
	if (*p1=='.') p1++;
	if (p) *p = p1;
	if (len) *len = p2-p1;
	return true;
}

const char *l7proto_str(t_l7proto l7)
{
	switch(l7)
	{
		case HTTP: return "http";
		case TLS: return "tls";
		case QUIC: return "quic";
		case WIREGUARD: return "wireguard";
		case DHT: return "dht";
		default: return "unknown";
	}
}
bool l7_proto_match(t_l7proto l7proto, uint32_t filter_l7)
{
	return  (l7proto==UNKNOWN && (filter_l7 & L7_PROTO_UNKNOWN)) ||
		(l7proto==HTTP && (filter_l7 & L7_PROTO_HTTP)) ||
		(l7proto==TLS && (filter_l7 & L7_PROTO_TLS)) ||
		(l7proto==QUIC && (filter_l7 & L7_PROTO_QUIC)) ||
		(l7proto==WIREGUARD && (filter_l7 & L7_PROTO_WIREGUARD)) ||
		(l7proto==DHT && (filter_l7 & L7_PROTO_DHT));
}

#define PM_ABS		0
#define PM_HOST		1
#define PM_HOST_END	2
#define PM_HOST_SLD	3
#define PM_HOST_MIDSLD	4
#define PM_HOST_ENDSLD	5
#define PM_HTTP_METHOD	6
#define PM_SNI_EXT	7
bool IsHostMarker(uint8_t posmarker)
{
	switch(posmarker)
	{
		case PM_HOST:
		case PM_HOST_END:
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
			return true;
		default:
			return false;
	}
}
const char *posmarker_name(uint8_t posmarker)
{
	switch(posmarker)
	{
		case PM_ABS: return "abs";
		case PM_HOST: return "host";
		case PM_HOST_END: return "endhost";
		case PM_HOST_SLD: return "sld";
		case PM_HOST_MIDSLD: return "midsld";
		case PM_HOST_ENDSLD: return "endsld";
		case PM_HTTP_METHOD: return "method";
		case PM_SNI_EXT: return "sniext";
		default: return "?";
	}
}

static size_t CheckPos(size_t sz, ssize_t offset)
{
	return (offset>=0 && offset<sz) ? offset : 0;
}
size_t AnyProtoPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	ssize_t offset;
	switch(posmarker)
	{
		case PM_ABS:
			offset = (pos<0) ? sz+pos : pos;
			return CheckPos(sz,offset);
		default:
			return 0;
	}
}
static size_t HostPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz, size_t offset_host, size_t len_host)
{
	ssize_t offset;
	const uint8_t *p;
	size_t slen;

	switch(posmarker)
	{
		case PM_HOST:
			offset = offset_host+pos;
			break;
		case PM_HOST_END:
			offset = offset_host+len_host+pos;
			break;
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
			if (((offset_host+len_host)<=sz) && FindNLD(data+offset_host,len_host,2,&p,&slen))
				offset = (posmarker==PM_HOST_SLD ? p-data : posmarker==PM_HOST_ENDSLD ? p-data+slen : slen==1 ? p+1-data : p+slen/2-data) + pos;
			else
				offset = 0;
			break;
	}
	return CheckPos(sz,offset);
}
size_t ResolvePos(const uint8_t *data, size_t sz, t_l7proto l7proto, const struct proto_pos *sp)
{
	switch(l7proto)
	{
		case HTTP:
			return HttpPos(sp->marker, sp->pos, data, sz);
		case TLS:
			return TLSPos(sp->marker, sp->pos, data, sz);
		default:
			return AnyProtoPos(sp->marker, sp->pos, data, sz);
	}
}
void ResolveMultiPos(const uint8_t *data, size_t sz, t_l7proto l7proto, const struct proto_pos *splits, int split_count, size_t *pos, int *pos_count)
{
	int i,j;
	for(i=j=0;i<split_count;i++)
	{
		pos[j] = ResolvePos(data,sz,l7proto,splits+i);
		if (pos[j]) j++;
	}
	qsort_size_t(pos, j);
	j=unique_size_t(pos, j);
	*pos_count=j;
}


const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS ","PUT /","DELETE /","CONNECT ","TRACE /",NULL };
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
	const char *dhost, *drhost;
	if (!FindNLD((uint8_t*)host,strlen(host),2,(const uint8_t**)&dhost,NULL) || !FindNLD((uint8_t*)redirect_host,strlen(redirect_host),2,(const uint8_t**)&drhost,NULL))
		return false;

	// compare 2nd level domains		
	return strcasecmp(dhost, drhost)!=0;
}
size_t HttpPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	const uint8_t *method, *host=NULL, *p;
	size_t offset_host,len_host;
	ssize_t offset;
	int i;
	
	switch(posmarker)
	{
		case PM_HTTP_METHOD:
			// recognize some tpws pre-applied hacks
			method=data;
			if (sz<10) break;
			if (*method=='\n' || *method=='\r') method++;
			if (*method=='\n' || *method=='\r') method++;
			for (p=method,i=0;i<7;i++) if (*p>='A' && *p<='Z') p++;
			if (i<3 || *p!=' ') break;
			return CheckPos(sz,method-data+pos);
		case PM_HOST:
		case PM_HOST_END:
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
			if (HttpFindHostConst(&host,data,sz) && (host-data+7)<sz)
			{
				host+=5;
				if (*host==' ' || *host=='\t') host++;
				offset_host = host-data;
				if (posmarker!=PM_HOST)
					for (len_host=0; (offset_host+len_host)<sz && data[offset_host+len_host]!='\r' && data[offset_host+len_host]!='\n'; len_host++);
				else
					len_host = 0;
				return HostPos(posmarker,pos,data,sz,offset_host,len_host);
			}
			break;
		default:
			return AnyProtoPos(posmarker,pos,data,sz);
	}
	return 0;
}



const char *TLSVersionStr(uint16_t tlsver)
{
	switch(tlsver)
	{
		case 0x0301: return "TLS 1.0";
		case 0x0302: return "TLS 1.1";
		case 0x0303: return "TLS 1.2";
		case 0x0304: return "TLS 1.3";
		default:
			// 0x0a0a, 0x1a1a, ..., 0xfafa
			return (((tlsver & 0x0F0F) == 0x0A0A) && ((tlsver>>12)==((tlsver>>4)&0xF))) ? "GREASE" : "UNKNOWN";
	}
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
static bool TLSAdvanceToHostInSNI(const uint8_t **ext, size_t *elen, size_t *slen)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (*elen < 5 || (*ext)[2] != 0) return false;
	*slen = pntoh16(*ext + 3);
	*ext += 5; *elen -= 5;
	return *slen <= *elen;
}
static bool TLSExtractHostFromExt(const uint8_t *ext, size_t elen, char *host, size_t len_host)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	size_t slen;
	if (!TLSAdvanceToHostInSNI(&ext,&elen,&slen))
		return false;
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

// find N level domain in SNI
static bool TLSHelloFindNLDInSNI(const uint8_t *ext, size_t elen, int level, const uint8_t **p, size_t *len)
{
	size_t slen;
	return TLSAdvanceToHostInSNI(&ext,&elen,&slen) && FindNLD(ext,slen,level,p,len);
}
// find the middle of second level domain (SLD) in SNI ext : www.sobaka.ru => aka.ru
// return false if SNI ext is bad or SLD is not found
static bool TLSHelloFindMiddleOfSLDInSNI(const uint8_t *ext, size_t elen, const uint8_t **p)
{
	size_t len;
	if (!TLSHelloFindNLDInSNI(ext,elen,2,p,&len))
		return false;
	// in case of one letter SLD (x.com) we split at '.' to prevent appearance of the whole SLD
	*p = (len==1) ? *p+1 : *p+len/2;
	return true;
}
size_t TLSPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz)
{
	size_t elen;
	const uint8_t *ext, *p;
	size_t offset_host,len_host;
	ssize_t offset;

	switch(posmarker)
	{
		case PM_HOST:
		case PM_HOST_END:
		case PM_HOST_SLD:
		case PM_HOST_MIDSLD:
		case PM_HOST_ENDSLD:
		case PM_SNI_EXT:
			if (TLSFindExt(data,sz,0,&ext,&elen,false))
			{
				if (posmarker==PM_SNI_EXT)
				{
					return CheckPos(sz,ext-data+pos);
				}
				else
				{
					if (!TLSAdvanceToHostInSNI(&ext,&elen,&len_host))
						return 0;
					offset_host = ext-data;
					return HostPos(posmarker,pos,data,sz,offset_host,len_host);
				}
			}
			return 0;
		default:
			return AnyProtoPos(posmarker,pos,data,sz);
	}
}
