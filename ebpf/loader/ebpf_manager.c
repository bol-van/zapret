/*
 * Zapret eBPF Manager
 * High-level interface for eBPF program management and integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include "../include/zapret_ebpf.h"

/* Connection tracking hash table */
#define CONN_HASH_SIZE 65536
static struct conn_track *connection_table[CONN_HASH_SIZE];
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Filter rules array */
#define MAX_RULES 1024
static struct filter_rule filter_rules[MAX_RULES];
static int rule_count = 0;
static pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;

/* TLS fingerprint pool */
#define FINGERPRINT_POOL_SIZE 100
static struct tls_fingerprint_compat fingerprint_pool[FINGERPRINT_POOL_SIZE];
static int fingerprint_count = 0;

/* Global configuration and statistics */
extern struct zapret_config global_config;
extern struct perf_stats global_stats;
extern pthread_mutex_t stats_mutex;

/* Hash function for connection tracking */
static uint32_t hash_connection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    uint32_t hash = src_ip;
    hash = hash * 31 + dst_ip;
    hash = hash * 31 + src_port;
    hash = hash * 31 + dst_port;
    hash = hash * 31 + protocol;
    return hash % CONN_HASH_SIZE;
}

/* Connection tracking functions */
struct conn_track* find_connection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    uint32_t hash = hash_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    
    pthread_mutex_lock(&conn_mutex);
    struct conn_track *conn = connection_table[hash];
    
    while (conn) {
        if (conn->src_ip == src_ip && conn->dst_ip == dst_ip &&
            conn->src_port == src_port && conn->dst_port == dst_port &&
            conn->protocol == protocol) {
            pthread_mutex_unlock(&conn_mutex);
            return conn;
        }
        conn = conn->next;  /* Proper linked list traversal */
    }
    
    pthread_mutex_unlock(&conn_mutex);
    return NULL;
}

struct conn_track* create_connection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    struct conn_track *conn = malloc(sizeof(struct conn_track));
    if (!conn) return NULL;
    
    memset(conn, 0, sizeof(*conn));
    conn->src_ip = src_ip;
    conn->dst_ip = dst_ip;
    conn->src_port = src_port;
    conn->dst_port = dst_port;
    conn->protocol = protocol;
    conn->first_seen = time(NULL);
    conn->last_seen = conn->first_seen;
    conn->state = 1;  /* Active */
    
    /* Initialize fragmentation context */
    struct fragment_ctx_compat *frag_ctx = (struct fragment_ctx_compat*)&conn->frag_ctx;
    frag_ctx->fragment_size = global_config.fragment_threshold;
    frag_ctx->max_fragments = MAX_FRAGMENTS;
    frag_ctx->enabled = global_config.enable_packet_fragmentation;
    
    uint32_t hash = hash_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    
    pthread_mutex_lock(&conn_mutex);
    /* Insert at head of hash bucket */
    conn->next = connection_table[hash];
    connection_table[hash] = conn;
    pthread_mutex_unlock(&conn_mutex);
    
    return conn;
}

void cleanup_old_connections(void) {
    time_t current_time = time(NULL);
    
    pthread_mutex_lock(&conn_mutex);
    
    for (int i = 0; i < CONN_HASH_SIZE; i++) {
        struct conn_track **curr = &connection_table[i];
        
        while (*curr) {
            struct conn_track *conn = *curr;
            
            if (current_time - conn->last_seen > global_config.connection_timeout) {
                /* Remove expired connection */
                *curr = (struct conn_track*)(uintptr_t)conn->bytes_count;
                free(conn);
            } else {
                curr = (struct conn_track**)(uintptr_t)&conn->bytes_count;
            }
        }
    }
    
    pthread_mutex_unlock(&conn_mutex);
}

/* Filter rule management */
int add_filter_rule(struct filter_rule *rule) {
    if (!rule) return -1;
    
    pthread_mutex_lock(&rules_mutex);
    
    if (rule_count >= MAX_RULES) {
        pthread_mutex_unlock(&rules_mutex);
        return -1;
    }
    
    memcpy(&filter_rules[rule_count], rule, sizeof(*rule));
    rule_count++;
    
    pthread_mutex_unlock(&rules_mutex);
    return 0;
}

struct filter_rule* match_filter_rule(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    pthread_mutex_lock(&rules_mutex);
    
    for (int i = 0; i < rule_count; i++) {
        struct filter_rule *rule = &filter_rules[i];
        
        if (!rule->enabled) continue;
        
        /* Check protocol */
        if (rule->protocol != 0 && rule->protocol != protocol) continue;
        
        /* Check source IP */
        if (rule->src_mask != 0) {
            if ((src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask)) continue;
        }
        
        /* Check destination IP */
        if (rule->dst_mask != 0) {
            if ((dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask)) continue;
        }
        
        /* Check source port range */
        if (rule->src_port_min != 0 || rule->src_port_max != 0) {
            if (src_port < rule->src_port_min || src_port > rule->src_port_max) continue;
        }
        
        /* Check destination port range */
        if (rule->dst_port_min != 0 || rule->dst_port_max != 0) {
            if (dst_port < rule->dst_port_min || dst_port > rule->dst_port_max) continue;
        }
        
        pthread_mutex_unlock(&rules_mutex);
        return rule;
    }
    
    pthread_mutex_unlock(&rules_mutex);
    return NULL;
}

/* TLS fingerprint management */
void init_fingerprint_pool(void) {
    /* Initialize with common browser fingerprints */
    struct {
        uint16_t version;
        uint16_t ciphers[8];
        int cipher_count;
    } common_fingerprints[] = {
        /* Chrome-like */
        {0x0303, {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0x009e, 0x009f}, 8},
        /* Firefox-like */
        {0x0303, {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xc030, 0x009e, 0x006b}, 8},
        /* Safari-like */
        {0x0304, {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0x009e, 0x009f}, 8},
        /* Edge-like */
        {0x0303, {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030, 0x009e, 0x006b}, 8}
    };
    
    fingerprint_count = sizeof(common_fingerprints) / sizeof(common_fingerprints[0]);
    
    for (int i = 0; i < fingerprint_count; i++) {
        fingerprint_pool[i].version = common_fingerprints[i].version;
        fingerprint_pool[i].cipher_count = common_fingerprints[i].cipher_count;
        
        for (int j = 0; j < common_fingerprints[i].cipher_count; j++) {
            fingerprint_pool[i].cipher_suites[j] = common_fingerprints[i].ciphers[j];
        }
        
        /* Generate JA3 hash (simplified) */
        fingerprint_pool[i].ja3_hash = fingerprint_pool[i].version * 31 + fingerprint_pool[i].cipher_count;
    }
}

struct tls_fingerprint_compat* get_random_fingerprint(void) {
    if (fingerprint_count == 0) return NULL;
    
    int index = rand() % fingerprint_count;
    return &fingerprint_pool[index];
}

/* Packet processing interface */
int process_packet_ebpf(uint8_t *data, size_t len, const char *interface) {
    if (!data || len == 0) return -1;
    
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    /* Parse basic packet headers */
    if (len < 34) return -1;  /* Minimum Ethernet + IP header */
    
    /* Skip Ethernet header */
    uint8_t *ip_hdr = data + 14;
    uint8_t ip_version = (ip_hdr[0] >> 4) & 0x0F;
    
    if (ip_version != 4) return 0;  /* Only IPv4 for now */
    
    uint8_t ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    uint8_t protocol = ip_hdr[9];
    uint32_t src_ip = *(uint32_t*)(ip_hdr + 12);
    uint32_t dst_ip = *(uint32_t*)(ip_hdr + 16);
    
    uint16_t src_port = 0, dst_port = 0;
    
    /* Extract port numbers */
    if (protocol == 6 || protocol == 17) {  /* TCP or UDP */
        if (len >= 14 + ip_hdr_len + 4) {
            uint8_t *l4_hdr = ip_hdr + ip_hdr_len;
            src_port = (l4_hdr[0] << 8) | l4_hdr[1];
            dst_port = (l4_hdr[2] << 8) | l4_hdr[3];
        }
    }
    
    /* Find or create connection */
    struct conn_track *conn = find_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    if (!conn) {
        conn = create_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    }
    
    if (conn) {
        conn->last_seen = time(NULL);
        conn->packets_count++;
        
        /* Apply filter rules */
        struct filter_rule *rule = match_filter_rule(src_ip, dst_ip, src_port, dst_port, protocol);
        if (rule) {
            /* Apply TLS randomization */
            if ((rule->action_flags & ACTION_RANDOMIZE_TLS) && protocol == 6) {
                /* Look for TLS handshake */
                if (len > 14 + ip_hdr_len + 20) {  /* TCP header minimum */
                    uint8_t *tcp_hdr = ip_hdr + ip_hdr_len;
                    uint8_t tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
                    uint8_t *payload = tcp_hdr + tcp_hdr_len;
                    
                    if (payload < data + len && payload[0] == 0x16) {  /* TLS handshake */
                        struct tls_fingerprint_compat *random_fp = get_random_fingerprint();
                        if (random_fp) {
                            memcpy(&conn->tls_fp, random_fp, sizeof(struct tls_fingerprint));
                            
                            pthread_mutex_lock(&stats_mutex);
                            global_stats.tls_fingerprints_randomized++;
                            pthread_mutex_unlock(&stats_mutex);
                        }
                    }
                }
            }
            
            /* Apply packet fragmentation */
            if ((rule->action_flags & ACTION_FRAGMENT_PACKET) && global_config.enable_packet_fragmentation) {
                struct fragment_ctx_compat *frag_ctx = (struct fragment_ctx_compat*)&conn->frag_ctx;
                if (len > frag_ctx->fragment_size) {
                    frag_ctx->needs_fragmentation = 1;
                    frag_ctx->original_size = len;
                    
                    pthread_mutex_lock(&stats_mutex);
                    global_stats.packets_fragmented++;
                    pthread_mutex_unlock(&stats_mutex);
                }
            }
        }
    }
    
    /* Update performance statistics */
    if (global_config.enable_performance_monitoring) {
        struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        
        uint64_t processing_time = (end_time.tv_sec - start_time.tv_sec) * 1000000000UL +
                                  (end_time.tv_nsec - start_time.tv_nsec);
        
        pthread_mutex_lock(&stats_mutex);
        global_stats.packets_processed++;
        global_stats.bytes_processed += len;
        global_stats.total_processing_time += processing_time;
        
        if (processing_time > global_stats.max_processing_time)
            global_stats.max_processing_time = processing_time;
        
        if (processing_time < global_stats.min_processing_time || global_stats.min_processing_time == 0)
            global_stats.min_processing_time = processing_time;
        
        pthread_mutex_unlock(&stats_mutex);
    }
    
    return 0;
}

/* Configuration management */
int load_filter_rules_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Warning: Could not open rules file %s\n", filename);
        return -1;
    }
    
    char line[512];
    int loaded_rules = 0;
    
    while (fgets(line, sizeof(line), fp) && loaded_rules < MAX_RULES) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;
        
        struct filter_rule rule = {0};
        
        /* Parse rule format: src_ip/mask:port-port dst_ip/mask:port-port protocol action */
        char src_spec[64], dst_spec[64], proto_str[16], action_str[64];
        
        if (sscanf(line, "%63s %63s %15s %63s", src_spec, dst_spec, proto_str, action_str) == 4) {
            /* Parse source specification */
            char *slash = strchr(src_spec, '/');
            char *colon = strchr(src_spec, ':');
            
            if (slash) {
                *slash = '\0';
                rule.src_ip = inet_addr(src_spec);
                rule.src_mask = inet_addr(slash + 1);
            }
            
            if (colon) {
                char *dash = strchr(colon + 1, '-');
                rule.src_port_min = atoi(colon + 1);
                rule.src_port_max = dash ? atoi(dash + 1) : rule.src_port_min;
            }
            
            /* Parse destination specification */
            slash = strchr(dst_spec, '/');
            colon = strchr(dst_spec, ':');
            
            if (slash) {
                *slash = '\0';
                rule.dst_ip = inet_addr(dst_spec);
                rule.dst_mask = inet_addr(slash + 1);
            }
            
            if (colon) {
                char *dash = strchr(colon + 1, '-');
                rule.dst_port_min = atoi(colon + 1);
                rule.dst_port_max = dash ? atoi(dash + 1) : rule.dst_port_min;
            }
            
            /* Parse protocol */
            if (strcmp(proto_str, "tcp") == 0) rule.protocol = 6;
            else if (strcmp(proto_str, "udp") == 0) rule.protocol = 17;
            else rule.protocol = atoi(proto_str);
            
            /* Parse actions */
            if (strstr(action_str, "randomize_tls")) rule.action_flags |= ACTION_RANDOMIZE_TLS;
            if (strstr(action_str, "fragment")) rule.action_flags |= ACTION_FRAGMENT_PACKET;
            if (strstr(action_str, "encrypt_sni")) rule.action_flags |= ACTION_ENCRYPT_SNI;
            if (strstr(action_str, "allow")) rule.action_flags |= ACTION_ALLOW;
            if (strstr(action_str, "block")) rule.action_flags |= ACTION_BLOCK;
            
            rule.enabled = 1;
            rule.priority = 100;
            
            if (add_filter_rule(&rule) == 0) {
                loaded_rules++;
            }
        }
    }
    
    fclose(fp);
    printf("Loaded %d filter rules from %s\n", loaded_rules, filename);
    return loaded_rules;
}

/* Cleanup thread */
void* cleanup_thread(void *arg) {
    while (1) {
        sleep(60);  /* Cleanup every minute */
        cleanup_old_connections();
    }
    return NULL;
}

/* Initialize eBPF manager */
int init_ebpf_manager(void) {
    /* Initialize fingerprint pool */
    init_fingerprint_pool();
    
    /* Load default filter rules */
    struct filter_rule default_rule = {0};
    default_rule.action_flags = ACTION_RANDOMIZE_TLS | ACTION_FRAGMENT_PACKET;
    default_rule.priority = 100;
    default_rule.enabled = 1;
    add_filter_rule(&default_rule);
    
    /* Start cleanup thread */
    pthread_t cleanup_tid;
    pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL);
    pthread_detach(cleanup_tid);
    
    printf("eBPF manager initialized\n");
    printf("  Fingerprint pool: %d entries\n", fingerprint_count);
    printf("  Filter rules: %d loaded\n", rule_count);
    
    return 0;
}

/* Get connection statistics */
int get_connection_stats(int *active_connections, int *total_connections) {
    int active = 0, total = 0;
    time_t current_time = time(NULL);
    
    pthread_mutex_lock(&conn_mutex);
    
    for (int i = 0; i < CONN_HASH_SIZE; i++) {
        struct conn_track *conn = connection_table[i];
        
        while (conn) {
            total++;
            if (current_time - conn->last_seen <= 60) {  /* Active in last minute */
                active++;
            }
            conn = (struct conn_track*)(uintptr_t)conn->bytes_count;
        }
    }
    
    pthread_mutex_unlock(&conn_mutex);
    
    if (active_connections) *active_connections = active;
    if (total_connections) *total_connections = total;
    
    return 0;
}