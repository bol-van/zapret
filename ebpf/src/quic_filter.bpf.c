/*
 * QUIC Protocol Filter eBPF Program
 * QUIC/HTTP3 and DNS over QUIC processing
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/zapret_ebpf.h"

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "GPL";

/* QUIC connection tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct quic_conn_id);
    __type(value, struct quic_conn_info);
} quic_connections SEC(".maps");

/* QUIC version support matrix */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, uint32_t);
    __type(value, uint32_t);  /* supported version */
} supported_versions SEC(".maps");

/* DNS over QUIC tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, uint32_t);  /* connection hash */
    __type(value, struct doq_session);
} doq_sessions SEC(".maps");

/* Helper function to parse QUIC header */
static __always_inline int parse_quic_header(void *data, void *data_end, struct quic_header *hdr) {
    if (!data || !data_end || !hdr)
        return -1;
    
    if (data + 1 > data_end)
        return -1;
    
    uint8_t *quic_data = (uint8_t *)data;
    hdr->flags = quic_data[0];
    
    /* Check if it's a long header */
    if (hdr->flags & 0x80) {
        /* Long header packet */
        if (data + 5 > data_end)
            return -1;
        
        hdr->version = (quic_data[1] << 24) | (quic_data[2] << 16) | 
                      (quic_data[3] << 8) | quic_data[4];
        hdr->is_long_header = 1;
        
        /* Extract packet type */
        hdr->packet_type = (hdr->flags & 0x30) >> 4;
    } else {
        /* Short header packet */
        hdr->is_long_header = 0;
        hdr->version = 0;
        hdr->packet_type = 0;
    }
    
    return 0;
}

/* Helper function to extract connection ID */
static __always_inline int extract_connection_id(void *data, void *data_end, 
                                                struct quic_header *hdr,
                                                struct quic_conn_id *conn_id) {
    if (!data || !data_end || !hdr || !conn_id)
        return -1;
    
    uint8_t *pos = (uint8_t *)data;
    
    if (hdr->is_long_header) {
        /* Skip fixed header (1 + 4 bytes) */
        pos += 5;
        
        if (pos + 1 > data_end)
            return -1;
        
        /* Read destination connection ID length */
        uint8_t dcid_len = *pos++;
        if (dcid_len > MAX_CONN_ID_LEN)
            dcid_len = MAX_CONN_ID_LEN;
        
        if (pos + dcid_len > data_end)
            return -1;
        
        conn_id->len = dcid_len;
        for (int i = 0; i < dcid_len && i < MAX_CONN_ID_LEN; i++) {
            conn_id->id[i] = pos[i];
        }
    } else {
        /* Short header - connection ID follows immediately */
        pos += 1;
        
        /* Assume 8-byte connection ID for short headers */
        if (pos + 8 > data_end)
            return -1;
        
        conn_id->len = 8;
        for (int i = 0; i < 8; i++) {
            conn_id->id[i] = pos[i];
        }
    }
    
    return 0;
}

/* Helper function to detect DNS over QUIC */
static __always_inline int is_dns_over_quic(struct quic_conn_info *conn, uint16_t dst_port) {
    if (!conn)
        return 0;
    
    /* Standard DoQ port */
    if (dst_port == 853)
        return 1;
    
    /* Check for DoQ indicators in ALPN */
    if (conn->alpn_len > 0) {
        /* Look for "doq" in ALPN */
        for (int i = 0; i < conn->alpn_len - 2; i++) {
            if (conn->alpn[i] == 'd' && conn->alpn[i+1] == 'o' && conn->alpn[i+2] == 'q')
                return 1;
        }
    }
    
    return 0;
}

/* Main QUIC filter function */
SEC("tc")
int quic_packet_filter(struct __sk_buff *skb) {
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
    
    /* Only process UDP packets */
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    /* Parse UDP header */
    struct udphdr *udp = data + sizeof(*eth) + (ip->ihl * 4);
    if ((void *)udp + sizeof(*udp) > data_end)
        return TC_ACT_OK;
    
    /* Check for QUIC ports */
    uint16_t dst_port = bpf_ntohs(udp->dest);
    uint16_t src_port = bpf_ntohs(udp->source);
    
    /* Common QUIC ports: 443, 80, 853 (DoQ) */
    if (dst_port != 443 && dst_port != 80 && dst_port != 853 &&
        src_port != 443 && src_port != 80 && src_port != 853)
        return TC_ACT_OK;
    
    /* Parse QUIC payload */
    void *quic_payload = (void *)udp + sizeof(*udp);
    if (quic_payload + 1 > data_end)
        return TC_ACT_OK;
    
    struct quic_header hdr = {0};
    if (parse_quic_header(quic_payload, data_end, &hdr) != 0)
        return TC_ACT_OK;
    
    /* Extract connection ID */
    struct quic_conn_id conn_id = {0};
    if (extract_connection_id(quic_payload, data_end, &hdr, &conn_id) != 0)
        return TC_ACT_OK;
    
    /* Look up or create connection info */
    struct quic_conn_info *conn = bpf_map_lookup_elem(&quic_connections, &conn_id);
    if (!conn) {
        struct quic_conn_info new_conn = {0};
        new_conn.version = hdr.version;
        new_conn.is_initial = (hdr.packet_type == 0);  /* Initial packet */
        new_conn.first_seen = bpf_ktime_get_ns();
        new_conn.last_seen = new_conn.first_seen;
        new_conn.packets_count = 1;
        
        bpf_map_update_elem(&quic_connections, &conn_id, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&quic_connections, &conn_id);
    }
    
    if (conn) {
        conn->last_seen = bpf_ktime_get_ns();
        __sync_fetch_and_add(&conn->packets_count, 1);
        __sync_fetch_and_add(&conn->bytes_count, skb->len);
        
        /* Check for DNS over QUIC */
        if (is_dns_over_quic(conn, dst_port)) {
            uint32_t session_hash = ip->saddr ^ ip->daddr ^ dst_port;
            struct doq_session doq = {0};
            doq.conn_id = conn_id;
            doq.queries_count = 1;
            doq.first_seen = conn->first_seen;
            
            bpf_map_update_elem(&doq_sessions, &session_hash, &doq, BPF_ANY);
        }
    }
    
    return TC_ACT_OK;
}

/* XDP version for QUIC processing */
SEC("xdp")
int quic_filter_xdp(struct xdp_md *ctx) {
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
    
    /* Only process UDP packets */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    /* Fast path QUIC detection */
    struct udphdr *udp = data + sizeof(*eth) + (ip->ihl * 4);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;
    
    uint16_t dst_port = bpf_ntohs(udp->dest);
    
    /* Quick QUIC port check */
    if (dst_port == 443 || dst_port == 80 || dst_port == 853) {
        /* Potential QUIC traffic - pass to TC layer for detailed processing */
        return XDP_PASS;
    }
    
    return XDP_PASS;
}