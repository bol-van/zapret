#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

bool IsHttp(const uint8_t *data, size_t len);
// header must be passed like this : "\nHost:"
bool HttpExtractHeader(const uint8_t *data, size_t len, const char *header, char *buf, size_t len_buf);
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
bool IsHttpReply(const uint8_t *data, size_t len);
const char *HttpFind2ndLevelDomain(const char *host);
// must be pre-checked by IsHttpReply
int HttpReplyCode(const uint8_t *data, size_t len);
// must be pre-checked by IsHttpReply
bool HttpReplyLooksLikeDPIRedirect(const uint8_t *data, size_t len, const char *host);

uint16_t TLSRecordDataLen(const uint8_t *data);
size_t TLSRecordLen(const uint8_t *data);
bool IsTLSRecordFull(const uint8_t *data, size_t len);
bool IsTLSClientHello(const uint8_t *data, size_t len, bool bPartialIsOK);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext, bool bPartialIsOK);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host, bool bPartialIsOK);
