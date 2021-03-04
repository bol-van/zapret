#pragma once

#include "darkmagic.h"
#include "nfqws.h"

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#ifdef __linux__
#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000
#else
#define DPI_DESYNC_FWMARK_DEFAULT 512
#endif

#define DPI_DESYNC_MAX_FAKE_LEN 1500

enum dpi_desync_mode {
	DESYNC_NONE=0,
	DESYNC_INVALID,
	DESYNC_FAKE,
	DESYNC_RST,
	DESYNC_RSTACK,
	DESYNC_DISORDER,
	DESYNC_DISORDER2,
	DESYNC_SPLIT,
	DESYNC_SPLIT2
};

extern const char *fake_http_request_default;
extern const uint8_t fake_tls_clienthello_default[517];

enum dpi_desync_mode desync_mode_from_string(const char *s);
bool desync_valid_first_stage(enum dpi_desync_mode mode);
bool desync_valid_second_stage(enum dpi_desync_mode mode);

void desync_init();
packet_process_result dpi_desync_packet(uint8_t *data_pkt, size_t len_pkt, struct ip *ip, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, size_t len_tcp, uint8_t *data_payload, size_t len_payload);
