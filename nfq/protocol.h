#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto/sha.h"
#include "crypto/aes-gcm.h"

bool IsHttp(const uint8_t *data, size_t len);
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);

bool IsTLSClientHello(const uint8_t *data, size_t len);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext);
bool TLSFindExtInHandshake(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
bool TLSHelloExtractHostFromHandshake(const uint8_t *data, size_t len, char *host, size_t len_host);

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
