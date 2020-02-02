#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

bool IsHttp(const char *data, size_t len);
bool HttpExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
bool IsTLSClientHello(const uint8_t *data, size_t len);
bool TLSFindExt(const uint8_t *data, size_t len, uint16_t type, const uint8_t **ext, size_t *len_ext);
bool TLSHelloExtractHost(const uint8_t *data, size_t len, char *host, size_t len_host);
