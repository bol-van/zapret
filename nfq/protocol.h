#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto/sha.h"
#include "crypto/aes-gcm.h"
#include "helpers.h"

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
enum httpreqpos { httpreqpos_none = 0, httpreqpos_method, httpreqpos_host, httpreqpos_pos };
size_t HttpPos(enum httpreqpos tpos_type, size_t hpos_pos, const uint8_t *http, size_t sz);

uint16_t TLSRecordDataLen(const uint8_t *data);
size_t TLSRecordLen(const uint8_t *data);
bool IsTLSRecordFull(const uint8_t *data, size_t len);
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK);
size_t TLSHandshakeLen(const uint8_t *data);
bool IsTLSHandshakeClientHello(const uint8_t *data, size_t len);
bool IsTLSHandshakeFull(const uint8_t *data, size_t len);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
enum tlspos { tlspos_none = 0, tlspos_sni, tlspos_sniext, tlspos_pos };
size_t TLSPos(enum tlspos tpos_type, size_t tpos_pos, const uint8_t *tls, size_t sz, uint8_t type);

bool IsWireguardHandshakeInitiation(const uint8_t *data, size_t len);
bool IsDhtD1(const uint8_t *data, size_t len);

#define QUIC_MAX_CID_LENGTH  20
typedef struct quic_cid {
	uint8_t      len;
	uint8_t      cid[QUIC_MAX_CID_LENGTH];
} quic_cid_t;

bool IsQUICInitial(const uint8_t *data, size_t len);
bool IsQUICCryptoHello(const uint8_t *data, size_t len, size_t *hello_offset, size_t *hello_len);
bool QUICIsLongHeader(const uint8_t *data, size_t len);
uint32_t QUICExtractVersion(const uint8_t *data, size_t len);
uint8_t QUICDraftVersion(uint32_t version);
bool QUICExtractDCID(const uint8_t *data, size_t len, quic_cid_t *cid);

bool QUICDecryptInitial(const uint8_t *data, size_t data_len, uint8_t *clean, size_t *clean_len);
bool QUICDefragCrypto(const uint8_t *clean,size_t clean_len, uint8_t *defrag,size_t *defrag_len);
bool QUICExtractHostFromInitial(const uint8_t *data, size_t data_len, char *host, size_t len_host, bool *bDecryptOK, bool *bIsCryptoHello);
