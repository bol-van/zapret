#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {UNKNOWN=0, HTTP, TLS, QUIC, WIREGUARD, DHT} t_l7proto;
#define L7_PROTO_HTTP		0x00000001
#define L7_PROTO_TLS		0x00000002
#define L7_PROTO_QUIC		0x00000004
#define L7_PROTO_WIREGUARD	0x00000008
#define L7_PROTO_DHT		0x00000010
#define L7_PROTO_UNKNOWN	0x80000000
const char *l7proto_str(t_l7proto l7);
bool l7_proto_match(t_l7proto l7proto, uint32_t filter_l7);

// pos markers
#define PM_ABS		0
#define PM_HOST		1
#define PM_HOST_END	2
#define PM_HOST_SLD	3
#define PM_HOST_MIDSLD	4
#define PM_HOST_ENDSLD	5
#define PM_HTTP_METHOD	6
#define PM_SNI_EXT	7
struct proto_pos
{
	int16_t pos;
	uint8_t marker;
};
#define PROTO_POS_EMPTY(sp) ((sp)->marker==PM_ABS && (sp)->pos==0)
bool IsHostMarker(uint8_t posmarker);
const char *posmarker_name(uint8_t posmarker);
size_t AnyProtoPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz);
size_t HttpPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz);
size_t TLSPos(uint8_t posmarker, int16_t pos, const uint8_t *data, size_t sz);
size_t ResolvePos(const uint8_t *data, size_t sz, t_l7proto l7proto, const struct proto_pos *sp);
void ResolveMultiPos(const uint8_t *data, size_t sz, t_l7proto l7proto, const struct proto_pos *splits, int split_count, size_t *pos, int *pos_count);


extern const char *http_methods[9];
const char *HttpMethod(const uint8_t *data, size_t len);
bool IsHttp(const uint8_t *data, size_t len);
bool HttpFindHost(uint8_t **pHost,uint8_t *buf,size_t bs);
bool HttpFindHostConst(const uint8_t **pHost,const uint8_t *buf,size_t bs);
// header must be passed like this : "\nHost:"
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf);
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
bool IsHttpReply(const uint8_t *data, size_t len);
const char *HttpFind2ndLevelDomain(const char *host);
// must be pre-checked by IsHttpReply
int HttpReplyCode(const uint8_t *data, size_t len);
// must be pre-checked by IsHttpReply
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host);

const char *TLSVersionStr(uint16_t tlsver);
uint16_t TLSRecordDataLen(const uint8_t *data);
size_t TLSRecordLen(const uint8_t *data);
bool IsTLSRecordFull(const uint8_t *data, size_t len);
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
