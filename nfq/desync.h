#pragma once

#include "darkmagic.h"
#include "nfqws.h"

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000
#define DPI_DESYNC_MAX_FAKE_LEN 1500

enum dpi_desync_mode {
	DESYNC_NONE=0,
	DESYNC_FAKE,
	DESYNC_RST,
	DESYNC_RSTACK,
	DESYNC_DISORDER,
	DESYNC_DISORDER2,
	DESYNC_SPLIT,
	DESYNC_SPLIT2
};

void desync_init();
packet_process_result dpi_desync_packet(uint8_t *data_pkt, size_t len_pkt, struct iphdr *iphdr, struct ip6_hdr *ip6hdr, struct tcphdr *tcphdr, size_t len_tcp, uint8_t *data_payload, size_t len_payload);
