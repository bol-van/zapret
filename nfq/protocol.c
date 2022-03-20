#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
bool IsHttp(const uint8_t *data, size_t len)
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
	const uint8_t *p, *s, *e = data + len;

	p = (uint8_t*)strncasestr((char*)data, "\nHost:", len);
	if (!p) return false;
	p += 6;
	while (p < e && (*p == ' ' || *p == '\t')) p++;
	s = p;
	while (s < e && (*s != '\r' && *s != '\n' && *s != ' ' && *s != '\t')) s++;
	if (s > p)
	{
		size_t slen = s - p;
		if (host && len_host)
		{
			if (slen >= len_host) slen = len_host - 1;
			for (size_t i = 0; i < slen; i++) host[i] = tolower(p[i]);
			host[slen] = 0;
		}
		return true;
	}
	return false;
}
bool IsTLSClientHello(const uint8_t *data, size_t len)
{
	return len >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x01 && data[2] <= 0x03 && data[5] == 0x01 && (ntohs(*(uint16_t*)(data + 3)) + 5) <= len;
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

	size_t l, ll;

	l = 1 + 2 + 2 + 1 + 3 + 2 + 32;
	// SessionIDLength
	if (len < (l + 1)) return false;
	ll = data[6] << 16 | data[7] << 8 | data[8]; // HandshakeProtocol length
	if (len < (ll + 9)) return false;
	l += data[l] + 1;
	// CipherSuitesLength
	if (len < (l + 2)) return false;
	l += ntohs(*(uint16_t*)(data + l)) + 2;
	// CompressionMethodsLength
	if (len < (l + 1)) return false;
	l += data[l] + 1;
	// ExtensionsLength
	if (len < (l + 2)) return false;

	data += l; len -= l;
	l = ntohs(*(uint16_t*)data);
	data += 2; len -= 2;
	if (l < len) return false;

	uint16_t ntype = htons(type);
	while (l >= 4)
	{
		uint16_t etype = *(uint16_t*)data;
		size_t elen = ntohs(*(uint16_t*)(data + 2));
		data += 4; l -= 4;
		if (l < elen) break;
		if (etype == ntype)
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
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data, len, 0, &ext, &elen)) return false;
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (elen < 5 || ext[2] != 0) return false;
	size_t slen = ntohs(*(uint16_t*)(ext + 3));
	ext += 5; elen -= 5;
	if (slen < elen) return false;
	if (ext && len_host)
	{
		if (slen >= len_host) slen = len_host - 1;
		for (size_t i = 0; i < slen; i++) host[i] = tolower(ext[i]);
		host[slen] = 0;
	}
	return true;
}


#define QUIC_MAX_CID_LENGTH  20
/* Returns the QUIC draft version or 0 if not applicable. */
static inline uint8_t quic_draft_version(uint32_t version) {
	/* IETF Draft versions */
	if ((version >> 8) == 0xff0000) {
		return (uint8_t)version;
	}
	/* Facebook mvfst, based on draft -22. */
	if (version == 0xfaceb001) {
		return 22;
	}
	/* Facebook mvfst, based on draft -27. */
	if (version == 0xfaceb002 || version == 0xfaceb00e) {
		return 27;
	}
	/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
	 * but we must return a sensible value */
	if (version == 0x51303530 ||
		version == 0x54303530 ||
		version == 0x54303531) {
		return 27;
	}
	/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	   "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	   forcing version negotiation to be exercised"
	   It is tricky to return a correct draft version: such number is primarily
	   used to select a proper salt (which depends on the version itself), but
	   we don't have a real version here! Let's hope that we need to handle
	   only latest drafts... */
	if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
		return 29;
	}
	/* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
	   final draft version */
	if (version == 0x00000001) {
		return 34;
	}
	/* QUIC Version 2 */
	/* TODO: for the time being use 100 as a number for V2 and let see how v2 drafts evolve */
	if (version == 0x709A50C4) {
		return 100;
	}
	return 0;
}
bool IsQUICInitial(uint8_t *data, size_t len)
{
	// long header, fixed bit, type=initial
	if (len < 512 || (data[0] & 0xF0) != 0xC0) return false;
	uint8_t *p = data + 1;
	uint32_t ver = ntohl(*(uint32_t*)p);
	if (quic_draft_version(ver) < 11) return false;
	p += 4;
	if (!*p || *p > QUIC_MAX_CID_LENGTH) return false;
	return true;
}
