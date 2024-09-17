#define _GNU_SOURCE

#include "protocol.h"
#include "helpers.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>

const char *http_methods[] = {"GET /", "POST /", "HEAD /", "OPTIONS /", "PUT /", "DELETE /", "CONNECT /", "TRACE /", NULL};
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
	return !!HttpMethod(data, len);
}
// pHost points to "Host: ..."
bool HttpFindHost(uint8_t **pHost, uint8_t *buf, size_t bs)
{
	if (!*pHost)
	{
		*pHost = memmem(buf, bs, "\nHost:", 6);
		if (*pHost)
			(*pHost)++;
	}
	return !!*pHost;
}
bool HttpFindHostConst(const uint8_t **pHost, const uint8_t *buf, size_t bs)
{
	if (!*pHost)
	{
		*pHost = memmem(buf, bs, "\nHost:", 6);
		if (*pHost)
			(*pHost)++;
	}
	return !!*pHost;
}

bool IsHttpReply(const uint8_t *data, size_t len)
{
	// HTTP/1.x 200\r\n
	return len > 14 && !memcmp(data, "HTTP/1.", 7) && (data[7] == '0' || data[7] == '1') && data[8] == ' ' &&
		   data[9] >= '0' && data[9] <= '9' &&
		   data[10] >= '0' && data[10] <= '9' &&
		   data[11] >= '0' && data[11] <= '9';
}
int HttpReplyCode(const uint8_t *data, size_t len)
{
	return (data[9] - '0') * 100 + (data[10] - '0') * 10 + (data[11] - '0');
}
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf)
{
	const uint8_t *p, *s, *e = data + len;

	p = (uint8_t *)strncasestr((char *)data, header, len);
	if (!p)
		return false;
	p += strlen(header);
	while (p < e && (*p == ' ' || *p == '\t'))
		p++;
	s = p;
	while (s < e && (*s != '\r' && *s != '\n' && *s != ' ' && *s != '\t'))
		s++;
	if (s > p)
	{
		size_t slen = s - p;
		if (buf && len_buf)
		{
			if (slen >= len_buf)
				slen = len_buf - 1;
			for (size_t i = 0; i < slen; i++)
				buf[i] = tolower(p[i]);
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
	const char *p = NULL;
	if (*host)
	{
		for (p = host + strlen(host) - 1; p > host && *p != '.'; p--)
			;
		if (*p == '.')
			for (p--; p > host && *p != '.'; p--)
				;
		if (*p == '.')
			p++;
	}
	return p;
}
// DPI redirects are global redirects to another domain
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host)
{
	char loc[256], *redirect_host, *p;
	int code;

	if (!host || !*host)
		return false;

	code = HttpReplyCode(data, len);

	if ((code != 302 && code != 307) || !HttpExtractHeader(data, len, "\nLocation:", loc, sizeof(loc)))
		return false;

	// something like : https://censor.net/badpage.php?reason=denied&source=RKN

	if (!strncmp(loc, "http://", 7))
		redirect_host = loc + 7;
	else if (!strncmp(loc, "https://", 8))
		redirect_host = loc + 8;
	else
		return false;

	// somethinkg like : censor.net/badpage.php?reason=denied&source=RKN

	for (p = redirect_host; *p && *p != '/'; p++)
		;
	*p = 0;
	if (!*redirect_host)
		return false;

	// somethinkg like : censor.net

	// extract 2nd level domains

	const char *dhost = HttpFind2ndLevelDomain(host);
	const char *drhost = HttpFind2ndLevelDomain(redirect_host);

	return strcasecmp(dhost, drhost) != 0;
}
size_t HttpPos(enum httpreqpos tpos_type, size_t hpos_pos, const uint8_t *http, size_t sz)
{
	const uint8_t *method, *host;
	int i;

	switch (tpos_type)
	{
	case httpreqpos_method:
		// recognize some tpws pre-applied hacks
		method = http;
		if (sz < 10)
			break;
		if (*method == '\n' || *method == '\r')
			method++;
		if (*method == '\n' || *method == '\r')
			method++;
		for (i = 0; i < 7; i++)
			if (*method >= 'A' && *method <= 'Z')
				method++;
		if (i < 3 || *method != ' ')
			break;
		return method - http - 1;
	case httpreqpos_host:
		if (HttpFindHostConst(&host, http, sz) && (host - http + 7) < sz)
		{
			host += 5;
			if (*host == ' ')
				host++;
			return host - http;
		}
		break;
	case httpreqpos_pos:
		break;
	default:
		return 0;
	}
	return hpos_pos < sz ? hpos_pos : 0;
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
	return TLSRecordLen(data) <= len;
}
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK)
{
	return len >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03 && data[5] == 0x01 && (bPartialIsOK || TLSRecordLen(data) <= len);
}

size_t TLSHandshakeLen(const uint8_t *data)
{
	return data[1] << 16 | data[2] << 8 | data[3]; // HandshakeProtocol length
}
bool IsTLSHandshakeClientHello(const uint8_t *data, size_t len)
{
	return len >= 4 && data[0] == 0x01 && TLSHandshakeLen(data) > 0;
}
bool IsTLSHandshakeFull(const uint8_t *data, size_t len)
{
	return (4 + TLSHandshakeLen(data)) <= len;
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

	size_t l;

	if (!bPartialIsOK && !IsTLSHandshakeFull(data, len))
		return false;

	l = 1 + 3 + 2 + 32;
	// SessionIDLength
	if (len < (l + 1))
		return false;
	l += data[l] + 1;
	// CipherSuitesLength
	if (len < (l + 2))
		return false;
	l += pntoh16(data + l) + 2;
	// CompressionMethodsLength
	if (len < (l + 1))
		return false;
	l += data[l] + 1;
	// ExtensionsLength
	if (len < (l + 2))
		return false;

	data += l;
	len -= l;
	l = pntoh16(data);
	data += 2;
	len -= 2;

	if (bPartialIsOK)
	{
		if (len < l)
			l = len;
	}
	else
	{
		if (len < l)
			return false;
	}

	while (l >= 4)
	{
		uint16_t etype = pntoh16(data);
		size_t elen = pntoh16(data + 2);
		data += 4;
		l -= 4;
		if (l < elen)
			break;
		if (etype == type)
		{
			if (ext && len_ext)
			{
				*ext = data;
				*len_ext = elen;
			}
			return true;
		}
		data += elen;
		l -= elen;
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
	if (!IsTLSClientHello(data, len, bPartialIsOK))
		return false;
	reclen = TLSRecordLen(data);
	if (reclen < len)
		len = reclen; // correct len if it has more data than the first tls record has
	return TLSFindExtInHandshake(data + 5, len - 5, type, ext, len_ext, bPartialIsOK);
}
static bool TLSExtractHostFromExt(const uint8_t *ext, size_t elen, char *host, size_t len_host)
{
	// u16	data+0 - name list length
	// u8	data+2 - server name type. 0=host_name
	// u16	data+3 - server name length
	if (elen < 5 || ext[2] != 0)
		return false;
	size_t slen = pntoh16(ext + 3);
	ext += 5;
	elen -= 5;
	if (slen < elen)
		return false;
	if (host && len_host)
	{
		if (slen >= len_host)
			slen = len_host - 1;
		for (size_t i = 0; i < slen; i++)
			host[i] = tolower(ext[i]);
		host[slen] = 0;
	}
	return true;
}
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExt(data, len, 0, &ext, &elen, bPartialIsOK))
		return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK)
{
	const uint8_t *ext;
	size_t elen;

	if (!TLSFindExtInHandshake(data, len, 0, &ext, &elen, bPartialIsOK))
		return false;
	return TLSExtractHostFromExt(ext, elen, host, len_host);
}
size_t TLSPos(enum tlspos tpos_type, size_t tpos_pos, const uint8_t *tls, size_t sz, uint8_t type)
{
	size_t elen;
	const uint8_t *ext;
	switch (tpos_type)
	{
	case tlspos_sni:
	case tlspos_sniext:
		if (TLSFindExt(tls, sz, 0, &ext, &elen, false))
			return (tpos_type == tlspos_sni) ? ext - tls + 6 : ext - tls + 1;
		// fall through
	case tlspos_pos:
		return tpos_pos < sz ? tpos_pos : 0;
	default:
		return 0;
	}
}

static uint8_t tvb_get_varint(const uint8_t *tvb, uint64_t *value)
{
	switch (*tvb >> 6)
	{
	case 0: /* 0b00 => 1 byte length (6 bits Usable) */
		if (value)
			*value = *tvb & 0x3F;
		return 1;
	case 1: /* 0b01 => 2 bytes length (14 bits Usable) */
		if (value)
			*value = pntoh16(tvb) & 0x3FFF;
		return 2;
	case 2: /* 0b10 => 4 bytes length (30 bits Usable) */
		if (value)
			*value = pntoh32(tvb) & 0x3FFFFFFF;
		return 4;
	case 3: /* 0b11 => 8 bytes length (62 bits Usable) */
		if (value)
			*value = pntoh64(tvb) & 0x3FFFFFFFFFFFFFFF;
		return 8;
	}
	// impossible case
	if (*value)
		*value = 0;
	return 0;
}
static uint8_t tvb_get_size(uint8_t tvb)
{
	return 1 << (tvb >> 6);
}

bool IsQUICCryptoHello(const uint8_t *data, size_t len, size_t *hello_offset, size_t *hello_len)
{
	size_t offset = 1;
	uint64_t coff, clen;
	if (len < 3 || *data != 6)
		return false;
	if ((offset + tvb_get_size(data[offset])) >= len)
		return false;
	offset += tvb_get_varint(data + offset, &coff);
	// offset must be 0 if it's a full segment, not just a chunk
	if (coff || (offset + tvb_get_size(data[offset])) >= len)
		return false;
	offset += tvb_get_varint(data + offset, &clen);
	if ((offset + clen) > len || !IsTLSHandshakeClientHello(data + offset, clen))
		return false;
	if (hello_offset)
		*hello_offset = offset;
	if (hello_len)
		*hello_len = (size_t)clen;
	return true;
}

/* Returns the QUIC draft version or 0 if not applicable. */
uint8_t QUICDraftVersion(uint32_t version)
{
	/* IETF Draft versions */
	if ((version >> 8) == 0xff0000)
	{
		return (uint8_t)version;
	}
	/* Facebook mvfst, based on draft -22. */
	if (version == 0xfaceb001)
	{
		return 22;
	}
	/* Facebook mvfst, based on draft -27. */
	if (version == 0xfaceb002 || version == 0xfaceb00e)
	{
		return 27;
	}
	/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
	 * but we must return a sensible value */
	if (version == 0x51303530 ||
		version == 0x54303530 ||
		version == 0x54303531)
	{
		return 27;
	}
	/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	   "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	   forcing version negotiation to be exercised"
	   It is tricky to return a correct draft version: such number is primarily
	   used to select a proper salt (which depends on the version itself), but
	   we don't have a real version here! Let's hope that we need to handle
	   only latest drafts... */
	if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
	{
		return 29;
	}
	/* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
	   final draft version */
	if (version == 0x00000001)
	{
		return 34;
	}
	/* QUIC Version 2 */
	/* TODO: for the time being use 100 as a number for V2 and let see how v2 drafts evolve */
	if (version == 0x709A50C4)
	{
		return 100;
	}
	return 0;
}

static bool is_quic_draft_max(uint32_t draft_version, uint8_t max_version)
{
	return draft_version && draft_version <= max_version;
}
static bool is_quic_v2(uint32_t version)
{
	return version == 0x6b3343cf;
}

static bool quic_hkdf_expand_label(const uint8_t *secret, uint8_t secret_len, const char *label, uint8_t *out, size_t out_len)
{
	uint8_t hkdflabel[64];

	size_t label_size = strlen(label);
	if (label_size > 255)
		return false;
	size_t hkdflabel_size = 2 + 1 + label_size + 1;
	if (hkdflabel_size > sizeof(hkdflabel))
		return false;

	phton16(hkdflabel, out_len);
	hkdflabel[2] = (uint8_t)label_size;
	memcpy(hkdflabel + 3, label, label_size);
	hkdflabel[3 + label_size] = 0;
	return !hkdfExpand(SHA256, secret, secret_len, hkdflabel, hkdflabel_size, out, out_len);
}

static bool quic_derive_initial_secret(const quic_cid_t *cid, uint8_t *client_initial_secret, uint32_t version)
{
	/*
	 * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
	 *
	 * initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899
	 * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
	 *
	 * client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "client in", "", Hash.length)
	 * server_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "server in", "", Hash.length)
	 *
	 * Hash for handshake packets is SHA-256 (output size 32).
	 */
	static const uint8_t handshake_salt_draft_22[20] = {
		0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a};
	static const uint8_t handshake_salt_draft_23[20] = {
		0xc3,
		0xee,
		0xf7,
		0x12,
		0xc7,
		0x2e,
		0xbb,
		0x5a,
		0x11,
		0xa7,
		0xd2,
		0x43,
		0x2b,
		0xb4,
		0x63,
		0x65,
		0xbe,
		0xf9,
		0xf5,
		0x02,
	};
	static const uint8_t handshake_salt_draft_29[20] = {
		0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
	static const uint8_t handshake_salt_v1[20] = {
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
	static const uint8_t hanshake_salt_draft_q50[20] = {
		0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
		0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45};
	static const uint8_t hanshake_salt_draft_t50[20] = {
		0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
		0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10};
	static const uint8_t hanshake_salt_draft_t51[20] = {
		0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
		0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d};
	static const uint8_t handshake_salt_v2[20] = {
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

	int err;
	const uint8_t *salt;
	uint8_t secret[USHAMaxHashSize];
	uint8_t draft_version = QUICDraftVersion(version);

	if (version == 0x51303530)
	{
		salt = hanshake_salt_draft_q50;
	}
	else if (version == 0x54303530)
	{
		salt = hanshake_salt_draft_t50;
	}
	else if (version == 0x54303531)
	{
		salt = hanshake_salt_draft_t51;
	}
	else if (is_quic_draft_max(draft_version, 22))
	{
		salt = handshake_salt_draft_22;
	}
	else if (is_quic_draft_max(draft_version, 28))
	{
		salt = handshake_salt_draft_23;
	}
	else if (is_quic_draft_max(draft_version, 32))
	{
		salt = handshake_salt_draft_29;
	}
	else if (is_quic_draft_max(draft_version, 34))
	{
		salt = handshake_salt_v1;
	}
	else
	{
		salt = handshake_salt_v2;
	}

	err = hkdfExtract(SHA256, salt, 20, cid->cid, cid->len, secret);
	if (err)
		return false;

	if (client_initial_secret && !quic_hkdf_expand_label(secret, SHA256HashSize, "tls13 client in", client_initial_secret, SHA256HashSize))
		return false;

	return true;
}
bool QUICIsLongHeader(const uint8_t *data, size_t len)
{
	return len >= 9 && !!(*data & 0x80);
}
uint32_t QUICExtractVersion(const uint8_t *data, size_t len)
{
	// long header, fixed bit, type=initial
	return QUICIsLongHeader(data, len) ? ntohl(*(uint32_t *)(data + 1)) : 0;
}
bool QUICExtractDCID(const uint8_t *data, size_t len, quic_cid_t *cid)
{
	if (!QUICIsLongHeader(data, len) || !data[5] || data[5] > QUIC_MAX_CID_LENGTH || (6 + data[5]) > len)
		return false;
	cid->len = data[5];
	memcpy(&cid->cid, data + 6, data[5]);
	return true;
}
bool QUICDecryptInitial(const uint8_t *data, size_t data_len, uint8_t *clean, size_t *clean_len)
{
	uint32_t ver = QUICExtractVersion(data, data_len);
	if (!ver)
		return false;

	quic_cid_t dcid;
	if (!QUICExtractDCID(data, data_len, &dcid))
		return false;

	uint8_t client_initial_secret[SHA256HashSize];
	if (!quic_derive_initial_secret(&dcid, client_initial_secret, ver))
		return false;

	uint8_t aeskey[16], aesiv[12], aeshp[16];
	bool v1_label = !is_quic_v2(ver);
	if (!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic key" : "tls13 quicv2 key", aeskey, sizeof(aeskey)) ||
		!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic iv" : "tls13 quicv2 iv", aesiv, sizeof(aesiv)) ||
		!quic_hkdf_expand_label(client_initial_secret, SHA256HashSize, v1_label ? "tls13 quic hp" : "tls13 quicv2 hp", aeshp, sizeof(aeshp)))
	{
		return false;
	}

	uint64_t payload_len, token_len;
	size_t pn_offset;
	pn_offset = 1 + 4 + 1 + data[5];
	if (pn_offset >= data_len)
		return false;
	pn_offset += 1 + data[pn_offset];
	if ((pn_offset + tvb_get_size(data[pn_offset])) >= data_len)
		return false;
	pn_offset += tvb_get_varint(data + pn_offset, &token_len);
	pn_offset += token_len;
	if ((pn_offset + tvb_get_size(data[pn_offset])) >= data_len)
		return false;
	pn_offset += tvb_get_varint(data + pn_offset, &payload_len);
	if (payload_len < 20 || (pn_offset + payload_len) > data_len)
		return false;

	aes_init_keygen_tables();

	uint8_t sample_enc[16];
	aes_context ctx;
	if (aes_setkey(&ctx, 1, aeshp, sizeof(aeshp)) || aes_cipher(&ctx, data + pn_offset + 4, sample_enc))
		return false;

	uint8_t mask[5];
	memcpy(mask, sample_enc, sizeof(mask));

	uint8_t packet0 = data[0] ^ (mask[0] & 0x0f);
	uint8_t pkn_len = (packet0 & 0x03) + 1;

	uint8_t pkn_bytes[4];
	memcpy(pkn_bytes, data + pn_offset, pkn_len);
	uint32_t pkn = 0;
	for (uint8_t i = 0; i < pkn_len; i++)
		pkn |= (uint32_t)(pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));

	phton64(aesiv + sizeof(aesiv) - 8, pntoh64(aesiv + sizeof(aesiv) - 8) ^ pkn);

	size_t cryptlen = payload_len - pkn_len - 16;
	if (cryptlen > *clean_len)
		return false;
	*clean_len = cryptlen;
	const uint8_t *decrypt_begin = data + pn_offset + pkn_len;

	uint8_t atag[16], header[256];
	size_t header_len = pn_offset + pkn_len;
	if (header_len > sizeof(header))
		return false; // not likely header will be so large
	memcpy(header, data, header_len);
	header[0] = packet0;
	for (uint8_t i = 0; i < pkn_len; i++)
		header[header_len - 1 - i] = (uint8_t)(pkn >> (8 * i));

	if (aes_gcm_crypt(AES_DECRYPT, clean, decrypt_begin, cryptlen, aeskey, sizeof(aeskey), aesiv, sizeof(aesiv), header, header_len, atag, sizeof(atag)))
		return false;

	// check if message was decrypted correctly : good keys , no data corruption
	return !memcmp(data + pn_offset + pkn_len + cryptlen, atag, 16);
}

bool QUICDefragCrypto(const uint8_t *clean, size_t clean_len, uint8_t *defrag, size_t *defrag_len)
{
	// Crypto frame can be split into multiple chunks
	// chromium randomly splits it and pads with zero/one bytes to force support the standard
	// mozilla does not split

	if (*defrag_len < 10)
		return false;
	uint8_t *defrag_data = defrag + 10;
	size_t defrag_data_len = *defrag_len - 10;

	uint8_t ft;
	uint64_t offset, sz, szmax = 0, zeropos = 0, pos = 0;
	bool found = false;

	while (pos < clean_len)
	{
		ft = clean[pos];
		pos++;
		if (ft > 1) // 00 - padding, 01 - ping
		{
			if (ft != 6)
				return false; // don't want to know all possible frame type formats

			if (pos >= clean_len)
				return false;

			if ((pos + tvb_get_size(clean[pos]) >= clean_len))
				return false;
			pos += tvb_get_varint(clean + pos, &offset);

			if ((pos + tvb_get_size(clean[pos]) > clean_len))
				return false;
			pos += tvb_get_varint(clean + pos, &sz);
			if ((pos + sz) > clean_len)
				return false;

			if ((offset + sz) > defrag_data_len)
				return false;
			if (zeropos < offset)
				// make sure no uninitialized gaps exist in case of not full fragment coverage
				memset(defrag_data + zeropos, 0, offset - zeropos);
			if ((offset + sz) > zeropos)
				zeropos = offset + sz;
			memcpy(defrag_data + offset, clean + pos, sz);
			if ((offset + sz) > szmax)
				szmax = offset + sz;

			found = true;
			pos += sz;
		}
	}
	if (found)
	{
		defrag[0] = 6;
		defrag[1] = 0; // offset
		// 2..9 - length 64 bit
		// +10 - data start
		phton64(defrag + 2, szmax);
		defrag[2] |= 0xC0; // 64 bit value
		*defrag_len = (size_t)(szmax + 10);
	}
	return found;
}

bool QUICExtractHostFromInitial(const uint8_t *data, size_t data_len, char *host, size_t len_host, bool *bDecryptOK, bool *bIsCryptoHello)
{
	if (bIsCryptoHello)
		*bIsCryptoHello = false;
	if (bDecryptOK)
		*bDecryptOK = false;

	uint8_t clean[1500];
	size_t clean_len = sizeof(clean);
	if (!QUICDecryptInitial(data, data_len, clean, &clean_len))
		return false;

	if (bDecryptOK)
		*bDecryptOK = true;

	uint8_t defrag[1500];
	size_t defrag_len = sizeof(defrag);
	if (!QUICDefragCrypto(clean, clean_len, defrag, &defrag_len))
		return false;

	size_t hello_offset, hello_len;
	if (!IsQUICCryptoHello(defrag, defrag_len, &hello_offset, &hello_len))
		return false;
	if (bIsCryptoHello)
		*bIsCryptoHello = true;

	return TLSHelloExtractHostFromHandshake(defrag + hello_offset, hello_len, host, len_host, true);
}

bool IsQUICInitial(const uint8_t *data, size_t len)
{
	// too small packets are not likely to be initials with ClientHello
	// long header, fixed bit
	if (len < 256 || (data[0] & 0xC0) != 0xC0)
		return false;

	uint32_t ver = QUICExtractVersion(data, len);
	if (QUICDraftVersion(ver) < 11)
		return false;

	// QUIC v1 : initial packets are 00b
	// QUIC v2 : initial packets are 01b
	if ((data[0] & 0x30) != (is_quic_v2(ver) ? 0x10 : 0x00))
		return false;

	uint64_t offset = 5, sz;

	// DCID. must be present
	if (!data[offset] || data[offset] > QUIC_MAX_CID_LENGTH)
		return false;
	offset += 1 + data[offset];

	// SCID
	if (data[offset] > QUIC_MAX_CID_LENGTH)
		return false;
	offset += 1 + data[offset];

	// token length
	offset += tvb_get_varint(data + offset, &sz);
	offset += sz;
	if (offset >= len)
		return false;

	// payload length
	if ((offset + tvb_get_size(data[offset])) > len)
		return false;
	tvb_get_varint(data + offset, &sz);
	offset += sz;
	if (offset > len)
		return false;

	// ClientHello cannot be too small. likely ACK
	return sz >= 96;
}

bool IsWireguardHandshakeInitiation(const uint8_t *data, size_t len)
{
	return len == 148 && data[0] == 1 && data[1] == 0 && data[2] == 0 && data[3] == 0;
}
bool IsDhtD1(const uint8_t *data, size_t len)
{
	return len >= 7 && data[0] == 'd' && data[1] == '1' && data[len - 1] == 'e';
}
