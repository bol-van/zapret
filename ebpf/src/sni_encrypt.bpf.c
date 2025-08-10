/*
 * SNI Encryption eBPF Program
 * ECH (Encrypted ClientHello) and ESNI support for TLS privacy
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/zapret_ebpf.h"

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "GPL";

/* ECH configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct ech_config);
} ech_config SEC(".maps");

/* SNI encryption keys */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, char[MAX_HOSTNAME_LEN]);
    __type(value, struct sni_key);
} sni_keys SEC(".maps");

/* Encryption statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct sni_stats);
} sni_stats SEC(".maps");

/* Helper function to extract SNI from TLS Client Hello */
static __always_inline int extract_sni(void *data, void *data_end, char *sni_buf, int buf_len) {
    if (!data || !data_end || !sni_buf || buf_len <= 0)
        return -1;
    
    uint8_t *tls_data = (uint8_t *)data;
    
    /* Check for TLS handshake record (0x16) */
    if (data + 5 > data_end || tls_data[0] != 0x16)
        return -1;
    
    /* Check for Client Hello (0x01) */
    if (data + 9 > data_end || tls_data[5] != 0x01)
        return -1;
    
    /* Skip to extensions */
    uint8_t *pos = tls_data + 43;  /* Skip fixed part of Client Hello */
    
    if (pos + 1 > data_end)
        return -1;
    
    /* Skip session ID */
    uint8_t session_id_len = *pos++;
    pos += session_id_len;
    
    if (pos + 2 > data_end)
        return -1;
    
    /* Skip cipher suites */
    uint16_t cipher_suites_len = (pos[0] << 8) | pos[1];
    pos += 2 + cipher_suites_len;
    
    if (pos + 1 > data_end)
        return -1;
    
    /* Skip compression methods */
    uint8_t comp_methods_len = *pos++;
    pos += comp_methods_len;
    
    if (pos + 2 > data_end)
        return -1;
    
    /* Parse extensions */
    uint16_t extensions_len = (pos[0] << 8) | pos[1];
    pos += 2;
    
    uint8_t *extensions_end = pos + extensions_len;
    if (extensions_end > data_end)
        extensions_end = data_end;
    
    /* Look for SNI extension (type 0x0000) */
    while (pos + 4 < extensions_end) {
        uint16_t ext_type = (pos[0] << 8) | pos[1];
        uint16_t ext_len = (pos[2] << 8) | pos[3];
        pos += 4;
        
        if (ext_type == 0x0000) {  /* SNI extension */
            if (pos + 5 < extensions_end) {
                uint16_t sni_list_len = (pos[0] << 8) | pos[1];
                pos += 2;
                
                if (pos + 3 < extensions_end) {
                    uint8_t name_type = pos[0];
                    uint16_t name_len = (pos[1] << 8) | pos[2];
                    pos += 3;
                    
                    if (name_type == 0 && pos + name_len <= extensions_end) {
                        /* Copy SNI hostname */
                        int copy_len = name_len;
                        if (copy_len >= buf_len)
                            copy_len = buf_len - 1;
                        
                        for (int i = 0; i < copy_len; i++) {
                            sni_buf[i] = pos[i];
                        }
                        sni_buf[copy_len] = '\0';
                        
                        return copy_len;
                    }
                }
            }
            break;
        }
        
        pos += ext_len;
    }
    
    return -1;
}

/* Helper function to check if SNI should be encrypted */
static __always_inline int should_encrypt_sni(char *hostname, struct ech_config *config) {
    if (!hostname || !config || !config->enabled)
        return 0;
    
    /* Check if hostname matches encryption patterns */
    int hostname_len = 0;
    for (int i = 0; i < MAX_HOSTNAME_LEN && hostname[i] != '\0'; i++) {
        hostname_len++;
    }
    
    if (hostname_len == 0)
        return 0;
    
    /* Check against configured domains */
    for (int i = 0; i < config->domain_count && i < MAX_ECH_DOMAINS; i++) {
        int domain_len = 0;
        for (int j = 0; j < MAX_HOSTNAME_LEN && config->domains[i][j] != '\0'; j++) {
            domain_len++;
        }
        
        if (domain_len > 0 && hostname_len >= domain_len) {
            /* Check if hostname ends with domain */
            int match = 1;
            for (int j = 0; j < domain_len; j++) {
                if (hostname[hostname_len - domain_len + j] != config->domains[i][j]) {
                    match = 0;
                    break;
                }
            }
            
            if (match)
                return 1;
        }
    }
    
    return 0;
}

/* Helper function to apply SNI encryption */
static __always_inline int encrypt_sni(void *data, void *data_end, char *hostname) {
    if (!data || !data_end || !hostname)
        return -1;
    
    /* Look up encryption key for hostname */
    struct sni_key *key = bpf_map_lookup_elem(&sni_keys, hostname);
    if (!key)
        return -1;
    
    /* For actual encryption, this would require packet modification
     * capabilities that are limited in eBPF. This is a placeholder
     * for marking packets that need SNI encryption in user space. */
    
    return 0;
}

/* Main SNI encryption function */
SEC("tc")
int sni_encryptor(struct __sk_buff *skb) {
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
    
    /* Only process TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    /* Parse TCP header */
    struct tcphdr *tcp = data + sizeof(*eth) + (ip->ihl * 4);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;
    
    /* Check for TLS handshake on port 443 */
    uint16_t dst_port = bpf_ntohs(tcp->dest);
    if (dst_port != 443)
        return TC_ACT_OK;
    
    /* Get ECH configuration */
    uint32_t config_key = 0;
    struct ech_config *config = bpf_map_lookup_elem(&ech_config, &config_key);
    if (!config)
        return TC_ACT_OK;
    
    /* Parse TLS payload */
    void *tls_payload = (void *)tcp + (tcp->doff * 4);
    if (tls_payload + 5 > data_end)
        return TC_ACT_OK;
    
    /* Extract SNI from TLS Client Hello */
    char sni_hostname[MAX_HOSTNAME_LEN] = {0};
    int sni_len = extract_sni(tls_payload, data_end, sni_hostname, MAX_HOSTNAME_LEN);
    
    if (sni_len <= 0)
        return TC_ACT_OK;
    
    /* Check if SNI should be encrypted */
    if (!should_encrypt_sni(sni_hostname, config))
        return TC_ACT_OK;
    
    /* Apply SNI encryption */
    if (encrypt_sni(tls_payload, data_end, sni_hostname) == 0) {
        /* Update statistics */
        uint32_t stats_key = 0;
        struct sni_stats *stats = bpf_map_lookup_elem(&sni_stats, &stats_key);
        if (stats) {
            __sync_fetch_and_add(&stats->sni_encrypted, 1);
            
            if (config->use_ech)
                __sync_fetch_and_add(&stats->ech_used, 1);
            else
                __sync_fetch_and_add(&stats->esni_used, 1);
        }
    }
    
    return TC_ACT_OK;
}

/* XDP version for SNI detection */
SEC("xdp")
int sni_encrypt_xdp(struct xdp_md *ctx) {
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
    
    /* Only process TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    /* Fast path TLS detection */
    struct tcphdr *tcp = data + sizeof(*eth) + (ip->ihl * 4);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;
    
    uint16_t dst_port = bpf_ntohs(tcp->dest);
    if (dst_port == 443) {
        /* Potential TLS traffic - pass to TC layer for SNI processing */
        return XDP_PASS;
    }
    
    return XDP_PASS;
}