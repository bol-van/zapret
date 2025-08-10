/*
 * Zapret eBPF Main Filter Program
 * Packet filtering with DPI evasion techniques
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/zapret_ebpf.h"

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "GPL";

/* BPF Maps */
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, struct tls_fingerprint);
} tls_fingerprint_pool SEC(".maps");

/* Helper Functions */
static __always_inline uint64_t compute_5tuple_hash(struct iphdr *ip, void *l4_hdr) {
    uint64_t hash = 0;
    
    if (!ip || !l4_hdr)
        return 0;
    
    hash = (uint64_t)ip->saddr;
    hash = hash * 31 + (uint64_t)ip->daddr;
    hash = hash * 31 + (uint64_t)ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
        hash = hash * 31 + (uint64_t)tcp->source;
        hash = hash * 31 + (uint64_t)tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4_hdr;
        hash = hash * 31 + (uint64_t)udp->source;
        hash = hash * 31 + (uint64_t)udp->dest;
    }
    
    return hash;
}

static __always_inline int parse_tls_client_hello(void *data, void *data_end, struct tls_fingerprint *fp) {
    if (!data || !data_end || !fp)
        return -1;
    
    /* Basic TLS record parsing */
    if (data + 5 > data_end)
        return -1;
    
    uint8_t *tls_data = (uint8_t *)data;
    
    /* Check for TLS handshake record (0x16) */
    if (tls_data[0] != 0x16)
        return -1;
    
    /* Extract TLS version */
    fp->version = (tls_data[1] << 8) | tls_data[2];
    
    /* Parse Client Hello message */
    if (data + 9 > data_end)
        return -1;
    
    /* Skip to cipher suites */
    uint8_t *pos = tls_data + 43;  /* Skip fixed part of Client Hello */
    
    if (pos + 1 > data_end)
        return -1;
    
    /* Skip session ID */
    uint8_t session_id_len = *pos++;
    pos += session_id_len;
    
    if (pos + 2 > data_end)
        return -1;
    
    /* Parse cipher suites */
    uint16_t cipher_suites_len = (pos[0] << 8) | pos[1];
    pos += 2;
    
    if (pos + cipher_suites_len > data_end)
        return -1;
    
    /* Store first few cipher suites for fingerprinting */
    int cipher_count = cipher_suites_len / 2;
    if (cipher_count > MAX_CIPHER_SUITES)
        cipher_count = MAX_CIPHER_SUITES;
    
    fp->cipher_count = cipher_count;
    for (int i = 0; i < cipher_count && i < MAX_CIPHER_SUITES; i++) {
        if (pos + 2 <= data_end) {
            fp->cipher_suites[i] = (pos[0] << 8) | pos[1];
            pos += 2;
        }
    }
    
    return 0;
}

static __always_inline int parse_quic_initial(void *data, void *data_end, struct quic_conn_info *quic) {
    if (!data || !data_end || !quic)
        return -1;
    
    /* Basic QUIC initial packet parsing */
    if (data + 1 > data_end)
        return -1;
    
    uint8_t *quic_data = (uint8_t *)data;
    
    /* Check for QUIC initial packet (long header with type 0) */
    if ((quic_data[0] & 0x80) == 0)  /* Not a long header */
        return -1;
    
    if ((quic_data[0] & 0x30) != 0x00)  /* Not initial packet */
        return -1;
    
    /* Extract version */
    if (data + 5 > data_end)
        return -1;
    
    quic->version = (quic_data[1] << 24) | (quic_data[2] << 16) | 
                   (quic_data[3] << 8) | quic_data[4];
    
    /* Mark as initial packet */
    quic->is_initial = 1;
    
    return 0;
}

static __always_inline int randomize_tls_fingerprint(void *data, void *data_end, struct tls_fingerprint *fp) {
    if (!data || !data_end || !fp)
        return -1;
    
    /* Get random fingerprint from pool */
    uint32_t key = bpf_get_prandom_u32() % 100;
    struct tls_fingerprint *random_fp = bpf_map_lookup_elem(&tls_fingerprint_pool, &key);
    
    if (!random_fp)
        return -1;
    
    /* Apply randomization to current fingerprint */
    fp->version = random_fp->version;
    fp->cipher_count = random_fp->cipher_count;
    
    for (int i = 0; i < MAX_CIPHER_SUITES && i < fp->cipher_count; i++) {
        fp->cipher_suites[i] = random_fp->cipher_suites[i];
    }
    
    return 0;
}

static __always_inline int fragment_packet(struct __sk_buff *skb, struct fragment_ctx *ctx) {
    if (!skb || !ctx || !ctx->enabled)
        return 0;
    
    /* Simple fragmentation logic - split packet at configured position */
    if (skb->len > ctx->fragment_size) {
        /* Mark for fragmentation in user space */
        ctx->needs_fragmentation = 1;
        ctx->original_size = skb->len;
    }
    
    return 0;
}

static __always_inline void update_performance_stats(struct perf_stats *stats, uint64_t start_time) {
    if (!stats)
        return;
    
    uint64_t end_time = bpf_ktime_get_ns();
    uint64_t processing_time = end_time - start_time;
    
    __sync_fetch_and_add(&stats->packets_processed, 1);
    __sync_fetch_and_add(&stats->total_processing_time, processing_time);
    
    if (processing_time > stats->max_processing_time)
        stats->max_processing_time = processing_time;
}

/* Main packet filter function */
SEC("tc")
int zapret_packet_filter(struct __sk_buff *skb) {
    uint64_t start_time = bpf_ktime_get_ns();
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    
    /* Only process IP packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    /* Parse IP header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    
    /* Get configuration */
    uint32_t config_key = 0;
    struct zapret_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config)
        return TC_ACT_OK;
    
    /* Compute connection hash */
    void *l4_hdr = data + sizeof(*eth) + (ip->ihl * 4);
    if (l4_hdr + sizeof(struct tcphdr) > data_end && 
        l4_hdr + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    
    uint64_t conn_hash = compute_5tuple_hash(ip, l4_hdr);
    
    /* Look up or create connection tracking entry */
    struct conn_track *conn = bpf_map_lookup_elem(&connection_map, &conn_hash);
    if (!conn) {
        struct conn_track new_conn = {0};
        new_conn.src_ip = ip->saddr;
        new_conn.dst_ip = ip->daddr;
        new_conn.protocol = ip->protocol;
        new_conn.first_seen = start_time;
        new_conn.last_seen = start_time;
        new_conn.packets_count = 1;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
            new_conn.src_port = tcp->source;
            new_conn.dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4_hdr;
            new_conn.src_port = udp->source;
            new_conn.dst_port = udp->dest;
        }
        
        bpf_map_update_elem(&connection_map, &conn_hash, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&connection_map, &conn_hash);
    }
    
    if (conn) {
        conn->last_seen = start_time;
        __sync_fetch_and_add(&conn->packets_count, 1);
        __sync_fetch_and_add(&conn->bytes_count, skb->len);
    }
    
    /* Process TLS packets */
    if (ip->protocol == IPPROTO_TCP && config->enable_tls_randomization) {
        struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
        void *payload = l4_hdr + (tcp->doff * 4);
        
        if (payload < data_end) {
            struct tls_fingerprint fp = {0};
            if (parse_tls_client_hello(payload, data_end, &fp) == 0) {
                if (conn) {
                    conn->tls_fp = fp;
                    randomize_tls_fingerprint(payload, data_end, &conn->tls_fp);
                }
            }
        }
    }
    
    /* Process QUIC packets */
    if (ip->protocol == IPPROTO_UDP && config->enable_quic_filtering) {
        struct udphdr *udp = (struct udphdr *)l4_hdr;
        void *payload = l4_hdr + sizeof(*udp);
        
        if (payload < data_end) {
            struct quic_conn_info quic = {0};
            if (parse_quic_initial(payload, data_end, &quic) == 0) {
                if (conn) {
                    conn->quic_info = quic;
                }
            }
        }
    }
    
    /* Apply packet fragmentation if enabled */
    if (config->enable_packet_fragmentation && conn) {
        fragment_packet(skb, &conn->frag_ctx);
    }
    
    /* Update performance statistics */
    if (config->enable_performance_monitoring) {
        uint32_t stats_key = 0;
        struct perf_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
        if (stats) {
            update_performance_stats(stats, start_time);
        }
    }
    
    return TC_ACT_OK;
}

/* XDP version for packet processing */
SEC("xdp")
int zapret_xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    /* Only process IP packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    /* Parse IP header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    /* Fast path filtering - basic DPI evasion */
    if (ip->protocol == IPPROTO_TCP) {
        /* TCP-based filtering logic */
        return XDP_PASS;
    } else if (ip->protocol == IPPROTO_UDP) {
        /* UDP/QUIC-based filtering logic */
        return XDP_PASS;
    }
    
    return XDP_PASS;
}