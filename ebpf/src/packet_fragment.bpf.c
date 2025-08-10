/*
 * Packet Fragmentation eBPF Program
 * Strategic TCP segmentation and IP fragmentation for DPI evasion
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/zapret_ebpf.h"

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "GPL";

/* Fragmentation configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct fragment_config);
} frag_config SEC(".maps");

/* Fragmentation statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct fragment_stats);
} frag_stats SEC(".maps");

/* Connection fragmentation state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, uint64_t);  /* connection hash */
    __type(value, struct fragment_ctx);
} frag_state SEC(".maps");

/* Helper function to compute connection hash */
static __always_inline uint64_t compute_conn_hash(struct iphdr *ip, void *l4_hdr) {
    if (!ip || !l4_hdr)
        return 0;
    
    uint64_t hash = 0;
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

/* Helper function to determine if packet should be fragmented */
static __always_inline int should_fragment_packet(struct __sk_buff *skb, 
                                                 struct fragment_config *config,
                                                 struct iphdr *ip,
                                                 void *l4_hdr) {
    if (!config || !config->enabled)
        return 0;
    
    /* Check packet size threshold */
    if (skb->len < config->min_packet_size)
        return 0;
    
    /* Check protocol-specific rules */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
        uint16_t dst_port = bpf_ntohs(tcp->dest);
        
        /* Fragment HTTPS traffic */
        if (config->fragment_https && dst_port == 443)
            return 1;
        
        /* Fragment HTTP traffic */
        if (config->fragment_http && dst_port == 80)
            return 1;
        
        /* Fragment based on TCP flags */
        if (config->fragment_syn && tcp->syn)
            return 1;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)l4_hdr;
        uint16_t dst_port = bpf_ntohs(udp->dest);
        
        /* Fragment DNS traffic */
        if (config->fragment_dns && dst_port == 53)
            return 1;
        
        /* Fragment QUIC traffic */
        if (config->fragment_quic && (dst_port == 443 || dst_port == 80))
            return 1;
    }
    
    return 0;
}

/* Helper function to calculate optimal fragment position */
static __always_inline uint32_t calculate_fragment_position(struct __sk_buff *skb,
                                                           struct fragment_config *config,
                                                           struct iphdr *ip) {
    uint32_t ip_header_len = ip->ihl * 4;
    uint32_t l4_header_len = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_header_len;
        l4_header_len = tcp->doff * 4;
    } else if (ip->protocol == IPPROTO_UDP) {
        l4_header_len = sizeof(struct udphdr);
    }
    
    uint32_t headers_len = sizeof(struct ethhdr) + ip_header_len + l4_header_len;
    uint32_t payload_start = headers_len;
    
    /* Calculate fragment position based on strategy */
    switch (config->fragment_strategy) {
        case FRAG_STRATEGY_FIXED:
            return payload_start + config->fragment_offset;
        
        case FRAG_STRATEGY_RANDOM:
            {
                uint32_t max_offset = skb->len - payload_start - config->min_fragment_size;
                if (max_offset < config->min_fragment_size)
                    return payload_start + config->min_fragment_size;
                
                uint32_t random_offset = bpf_get_prandom_u32() % max_offset;
                return payload_start + config->min_fragment_size + random_offset;
            }
        
        case FRAG_STRATEGY_DPI_AWARE:
            /* Fragment at strategic positions to break DPI signatures */
            if (ip->protocol == IPPROTO_TCP) {
                /* Fragment TLS Client Hello at cipher suites */
                return payload_start + 64;  /* Typical position */
            } else {
                /* Fragment QUIC at connection ID */
                return payload_start + 16;
            }
        
        default:
            return payload_start + config->fragment_offset;
    }
}

/* Main packet fragmentation function */
SEC("tc")
int packet_fragmenter(struct __sk_buff *skb) {
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
    
    /* Get fragmentation configuration */
    uint32_t config_key = 0;
    struct fragment_config *config = bpf_map_lookup_elem(&frag_config, &config_key);
    if (!config)
        return TC_ACT_OK;
    
    /* Parse L4 header */
    void *l4_hdr = data + sizeof(*eth) + (ip->ihl * 4);
    if (l4_hdr + sizeof(struct tcphdr) > data_end && 
        l4_hdr + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    
    /* Check if packet should be fragmented */
    if (!should_fragment_packet(skb, config, ip, l4_hdr))
        return TC_ACT_OK;
    
    /* Compute connection hash */
    uint64_t conn_hash = compute_conn_hash(ip, l4_hdr);
    
    /* Look up or create fragmentation context */
    struct fragment_ctx *ctx = bpf_map_lookup_elem(&frag_state, &conn_hash);
    if (!ctx) {
        struct fragment_ctx new_ctx = {0};
        new_ctx.enabled = 1;
        new_ctx.fragment_size = config->default_fragment_size;
        new_ctx.fragments_sent = 0;
        
        bpf_map_update_elem(&frag_state, &conn_hash, &new_ctx, BPF_ANY);
        ctx = bpf_map_lookup_elem(&frag_state, &conn_hash);
    }
    
    if (!ctx)
        return TC_ACT_OK;
    
    /* Calculate fragment position */
    uint32_t frag_pos = calculate_fragment_position(skb, config, ip);
    
    /* Mark packet for fragmentation */
    ctx->needs_fragmentation = 1;
    ctx->original_size = skb->len;
    ctx->fragment_position = frag_pos;
    
    /* Update statistics */
    uint32_t stats_key = 0;
    struct fragment_stats *stats = bpf_map_lookup_elem(&frag_stats, &stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets_fragmented, 1);
        __sync_fetch_and_add(&stats->total_fragments, 2);  /* Assume 2 fragments */
        
        if (ip->protocol == IPPROTO_TCP)
            __sync_fetch_and_add(&stats->tcp_fragments, 1);
        else if (ip->protocol == IPPROTO_UDP)
            __sync_fetch_and_add(&stats->udp_fragments, 1);
    }
    
    /* Increment fragment counter */
    __sync_fetch_and_add(&ctx->fragments_sent, 1);
    
    /* For actual fragmentation, this would need to be handled in user space
     * or with more eBPF capabilities. Here we just mark the packet. */
    
    return TC_ACT_OK;
}

/* XDP version for fragmentation marking */
SEC("xdp")
int packet_fragment_xdp(struct xdp_md *ctx) {
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
    
    /* Fast path fragmentation detection */
    uint32_t packet_len = data_end - data;
    
    /* Check for large packets that might need fragmentation */
    if (packet_len > 1200) {  /* Typical fragmentation threshold */
        /* Mark for detailed processing in TC layer */
        return XDP_PASS;
    }
    
    return XDP_PASS;
}