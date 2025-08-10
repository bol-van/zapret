/* SPDX-License-Identifier: GPL-2.0 */
/* Zapret eBPF - DPI Evasion and Packet Filtering
 * Copyright (c) 2024 Zapret Project
 */

#ifndef __ZAPRET_EBPF_H__
#define __ZAPRET_EBPF_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#endif

/* Maximum supported packet size */
#define MAX_PACKET_SIZE 1500
#define MAX_HOSTNAME_LEN 256
#define MAX_JA3_LEN 512
#define MAX_FRAGMENTS 16

/* Protocol definitions */
#define IPPROTO_QUIC 17  /* QUIC over UDP */
#define TLS_HANDSHAKE_TYPE 22
#define TLS_CLIENT_HELLO 1
#define QUIC_INITIAL_PACKET 0x00

/* TLS versions */
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

/* QUIC versions */
#define QUIC_VERSION_1 0x00000001
#define QUIC_VERSION_2 0x6b3343cf

/* Action flags */
#define ACTION_PASS 0
#define ACTION_DROP 1
#define ACTION_FRAGMENT 2
#define ACTION_RANDOMIZE_TLS 4
#define ACTION_ENCRYPT_SNI 8
#define ACTION_MODIFY_JA3 16

/* Action flags for filter rules */
#define ACTION_ALLOW           0x01
#define ACTION_BLOCK           0x02
#define ACTION_RANDOMIZE_TLS   0x04
#define ACTION_FRAGMENT_PACKET 0x08
#define ACTION_ENCRYPT_SNI     0x10

/* Maximum cipher suites */
#define MAX_CIPHER_SUITES 32

/* Fragment strategies */
#define FRAG_STRATEGY_TCP_SEG 1
#define FRAG_STRATEGY_IP_FRAG 2
#define FRAG_STRATEGY_TLS_REC 3

/* Performance monitoring */
struct perf_stats {
    uint64_t packets_processed;
    uint64_t packets_filtered;
    uint64_t packets_fragmented;
    uint64_t packets_dropped;
    uint64_t tls_fingerprints_randomized;
    uint64_t sni_encrypted;
    uint64_t bytes_processed;
    uint64_t processing_time_ns;
    uint64_t total_processing_time;
    uint64_t max_processing_time;
    uint64_t min_processing_time;
    uint64_t last_update;
};

/* TLS fingerprint structure */
struct tls_fingerprint {
    uint16_t version;
    uint16_t cipher_suites[32];
    uint8_t cipher_suites_len;
    uint16_t extensions[16];
    uint8_t extensions_len;
    uint16_t elliptic_curves[8];
    uint8_t elliptic_curves_len;
    uint8_t signature_algorithms[16];
    uint8_t signature_algorithms_len;
    char ja3_hash[33];  /* MD5 hash as hex string */
};

/* Alternative TLS fingerprint structure for compatibility */
struct tls_fingerprint_compat {
    uint16_t version;
    uint16_t cipher_suites[MAX_CIPHER_SUITES];
    uint8_t cipher_count;
    uint8_t extensions[32];
    uint32_t ja3_hash;
};

/* QUIC connection info */
struct quic_conn_info {
    uint32_t version;
    uint8_t dcid[20];
    uint8_t dcid_len;
    uint8_t scid[20];
    uint8_t scid_len;
    uint16_t initial_packet_len;
    uint8_t has_sni;
    char sni[MAX_HOSTNAME_LEN];
};

/* Alternative QUIC connection information for compatibility */
struct quic_conn_info_compat {
    uint32_t version;
    uint8_t connection_id[20];
    uint8_t packet_type;
    uint32_t packet_number;
    uint8_t is_initial;
};

/* Packet fragmentation context */
struct fragment_ctx {
    uint32_t strategy;
    uint16_t fragment_size;
    uint16_t fragments_count;
    uint32_t sequence_base;
    uint8_t randomize_order;
};

/* Alternative packet fragmentation context for compatibility */
struct fragment_ctx_compat {
    uint32_t fragment_size;
    uint32_t max_fragments;
    uint8_t fragmentation_method;
    uint8_t enabled;
    uint8_t needs_fragmentation;
    uint32_t original_size;
    uint8_t fragment_count;
    uint32_t fragment_offsets[MAX_FRAGMENTS];
    uint32_t fragment_sizes[MAX_FRAGMENTS];
};

/* SNI encryption context */
struct sni_encrypt_ctx {
    uint8_t enabled;
    uint8_t ech_supported;
    uint8_t esni_supported;
    uint8_t key[32];  /* Encryption key */
    uint8_t key_len;
    uint8_t iv[12];
    uint8_t encrypted;
    uint8_t padding[2];
};

/* Connection tracking entry */
struct conn_track {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t state;
    uint64_t first_seen;
    uint64_t last_seen;
    uint32_t packets_count;
    uint32_t bytes_count;
    struct tls_fingerprint tls_fp;
    struct quic_conn_info quic_info;
    struct fragment_ctx frag_ctx;
    struct sni_encrypt_ctx sni_ctx;
    struct conn_track *next;  /* For hash table chaining */
};

/* Filter rule structure */
struct filter_rule {
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port_min;
    uint16_t src_port_max;
    uint16_t dst_port_min;
    uint16_t dst_port_max;
    uint8_t protocol;
    uint32_t action_flags;
    uint32_t priority;
    char hostname_pattern[MAX_HOSTNAME_LEN];
    uint8_t enabled;
};

/* Configuration structure */
struct zapret_config {
    uint8_t enable_tls_randomization;
    uint8_t enable_quic_filtering;
    uint8_t enable_packet_fragmentation;
    uint8_t enable_sni_encryption;
    uint8_t enable_performance_monitoring;
    uint8_t use_netfilter;
    uint8_t use_tc;
    uint8_t use_raw_socket;
    uint32_t max_connections;
    uint32_t connection_timeout;
    uint32_t fragment_threshold;
    struct filter_rule default_rule;
};

/* Map definitions */
#ifdef __KERNEL__
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, uint64_t);  /* 5-tuple hash */
    __type(value, struct conn_track);
} connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct zapret_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct perf_stats);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_HOSTNAME_LEN]);
    __type(value, uint32_t);  /* action flags */
} hostname_rules SEC(".maps");

/* TLS fingerprint randomization patterns */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, struct tls_fingerprint);
} tls_fingerprint_pool SEC(".maps");
#endif

/* Helper function declarations */
#ifdef __KERNEL__
static inline uint64_t compute_5tuple_hash(struct iphdr *ip, void *l4_hdr);
static inline int parse_tls_client_hello(void *data, void *data_end, struct tls_fingerprint *fp);
static inline int parse_quic_initial(void *data, void *data_end, struct quic_conn_info *quic);
static inline int extract_sni_from_tls(void *data, void *data_end, char *sni, int max_len);
static inline int randomize_tls_fingerprint(struct tls_fingerprint *fp);
static inline int fragment_packet(struct __sk_buff *skb, struct fragment_ctx *ctx);
static inline int encrypt_sni(char *sni, struct sni_encrypt_ctx *ctx);
static inline void update_performance_stats(struct perf_stats *stats, uint64_t start_time);
#endif

/* Utility macros */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define PACKET_HOST(skb) ((skb)->pkt_type == PACKET_HOST)
#define PACKET_OUTGOING(skb) ((skb)->pkt_type == PACKET_OUTGOING)

/* Bounds checking macro */
#define BOUNDS_CHECK(ptr, end, size) \
    ({ \
        void *_ptr = (void *)(ptr); \
        void *_end = (void *)(end); \
        (_ptr + (size) <= _end) ? 1 : 0; \
    })

/* Network byte order conversion helpers */
#define NET16(x) bpf_htons(x)
#define NET32(x) bpf_htonl(x)
#define HOST16(x) bpf_ntohs(x)
#define HOST32(x) bpf_ntohl(x)

#endif /* __ZAPRET_EBPF_H__ */