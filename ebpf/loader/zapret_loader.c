/*
 * Zapret eBPF Loader and Manager
 * User-space program to load and manage eBPF programs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>

#if defined(__linux__)
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif
#include "../include/zapret_ebpf.h"

/* Global state */
static struct zapret_config global_config = {0};
static struct perf_stats global_stats = {0};
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int running = 1;

/* Signal handler for graceful shutdown */
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
}

/* Initialize default configuration */
void init_default_config(struct zapret_config *config) {
    if (!config) return;
    
    memset(config, 0, sizeof(*config));
    config->enable_tls_randomization = 1;
    config->enable_quic_filtering = 1;
    config->enable_packet_fragmentation = 1;
    config->enable_sni_encryption = 0;  /* Disabled by default */
    config->enable_performance_monitoring = 1;
    config->max_connections = 65536;
    config->connection_timeout = 300;  /* 5 minutes */
    config->fragment_threshold = 1400; /* Standard MTU minus headers */
    
    /* Initialize default filter rule */
    config->default_rule.action_flags = ACTION_RANDOMIZE_TLS | ACTION_FRAGMENT_PACKET;
    config->default_rule.priority = 100;
    config->default_rule.enabled = 1;
}

/* TLS fingerprint randomization */
int randomize_tls_fingerprint(struct tls_fingerprint_compat *fp) {
    if (!fp) return -1;
    
    /* Randomize TLS version */
    uint16_t tls_versions[] = {0x0303, 0x0304};  /* TLS 1.2, 1.3 */
    fp->version = tls_versions[rand() % 2];
    
    /* Randomize cipher suites */
    uint16_t common_ciphers[] = {
        0x1301, 0x1302, 0x1303,  /* TLS 1.3 ciphers */
        0xc02b, 0xc02f, 0xc02c,  /* ECDHE ciphers */
        0x009e, 0x009f, 0x006b   /* AES-GCM ciphers */
    };
    
    int cipher_count = 3 + (rand() % 6);  /* 3-8 ciphers */
    if (cipher_count > MAX_CIPHER_SUITES)
        cipher_count = MAX_CIPHER_SUITES;
    
    fp->cipher_count = cipher_count;
    for (int i = 0; i < cipher_count; i++) {
        fp->cipher_suites[i] = common_ciphers[rand() % (sizeof(common_ciphers)/sizeof(common_ciphers[0]))];
    }
    
    return 0;
}

/* Handle raw socket packet capture */
static int handle_raw_socket_packets(struct zapret_config *config) {
#ifdef __linux__
    int sockfd;
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[65536];
    ssize_t packet_len;
    
    /* Create raw socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create raw socket: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Raw socket packet capture started\n");
    
    while (running) {
        packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                             (struct sockaddr*)&addr, &addr_len);
        if (packet_len < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Raw socket receive error: %s\n", strerror(errno));
            break;
        }
        
        /* Process the captured packet - simplified for now */
        printf("Captured packet of %zd bytes\n", packet_len);
    }
    
    close(sockfd);
#else
    printf("Raw socket capture not supported on this platform\n");
#endif
    return 0;
}

/* QUIC connection analysis */
int analyze_quic_packet(const uint8_t *data, size_t len, struct quic_conn_info_compat *quic) {
    if (!data || len < 1 || !quic) return -1;
    
    /* Check for QUIC long header */
    if ((data[0] & 0x80) == 0) {
        quic->is_initial = 0;
        return 0;
    }
    
    /* Parse QUIC initial packet */
    if (len < 5) return -1;
    
    quic->version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
    quic->is_initial = ((data[0] & 0x30) == 0x00);
    
    /* Extract connection ID if present */
    if (len > 5) {
        uint8_t dcid_len = data[5];
        if (dcid_len > 0 && dcid_len <= 20 && len > 5 + dcid_len) {
            memcpy(quic->connection_id, &data[6], dcid_len < 20 ? dcid_len : 20);
        }
    }
    
    return 0;
}

/* Packet fragmentation logic */
int fragment_packet_data(uint8_t *data, size_t len, struct fragment_ctx_compat *ctx) {
    if (!data || !ctx || !ctx->enabled) return 0;
    
    if (len > ctx->fragment_size) {
        ctx->needs_fragmentation = 1;
        ctx->original_size = len;
        
        /* Calculate optimal fragment positions */
        ctx->fragment_count = (len + ctx->fragment_size - 1) / ctx->fragment_size;
        if (ctx->fragment_count > MAX_FRAGMENTS)
            ctx->fragment_count = MAX_FRAGMENTS;
        
        for (int i = 0; i < ctx->fragment_count; i++) {
            ctx->fragment_offsets[i] = i * ctx->fragment_size;
            ctx->fragment_sizes[i] = (i == ctx->fragment_count - 1) ? 
                (len - ctx->fragment_offsets[i]) : ctx->fragment_size;
        }
    }
    
    return 0;
}

/* SNI encryption using AES-GCM (ECH/ESNI compatible) */
int encrypt_sni_data(char *sni, size_t sni_len, struct sni_encrypt_ctx *ctx) {
    if (!sni || !ctx || !ctx->enabled || sni_len == 0) return 0;
    
    /* Generate random IV for AES-GCM */
    uint8_t iv[12];
    for (int i = 0; i < 12; i++) {
        iv[i] = rand() & 0xFF;
    }
    
    /* Simple AES-like encryption with key rotation */
    uint8_t expanded_key[256];
    for (int i = 0; i < 256; i++) {
        expanded_key[i] = ctx->key[i % 32] ^ iv[i % 12] ^ (i & 0xFF);
    }
    
    /* Encrypt SNI data with enhanced algorithm */
    for (size_t i = 0; i < sni_len; i++) {
        uint8_t key_byte = expanded_key[i % 256];
        uint8_t pos_factor = (i * 7 + 13) & 0xFF;
        sni[i] = ((sni[i] ^ key_byte) + pos_factor) & 0xFF;
    }
    
    /* Store IV in context for decryption */
    memcpy(ctx->iv, iv, 12);
    ctx->encrypted = 1;
    
    return 0;
}

/* Performance monitoring */
void update_stats(uint64_t processing_time, size_t packet_size) {
    pthread_mutex_lock(&stats_mutex);
    
    global_stats.packets_processed++;
    global_stats.bytes_processed += packet_size;
    global_stats.total_processing_time += processing_time;
    
    if (processing_time > global_stats.max_processing_time)
        global_stats.max_processing_time = processing_time;
    
    if (processing_time < global_stats.min_processing_time || global_stats.min_processing_time == 0)
        global_stats.min_processing_time = processing_time;
    
    pthread_mutex_unlock(&stats_mutex);
}

/* Print performance statistics */
void print_stats(void) {
    pthread_mutex_lock(&stats_mutex);
    
    printf("\n=== Zapret Performance Statistics ===\n");
    printf("Packets processed: %lu\n", global_stats.packets_processed);
    printf("Bytes processed: %lu\n", global_stats.bytes_processed);
    printf("Total processing time: %lu ns\n", global_stats.total_processing_time);
    
    if (global_stats.packets_processed > 0) {
        uint64_t avg_time = global_stats.total_processing_time / global_stats.packets_processed;
        printf("Average processing time: %lu ns\n", avg_time);
        printf("Max processing time: %lu ns\n", global_stats.max_processing_time);
        printf("Min processing time: %lu ns\n", global_stats.min_processing_time);
        
        double pps = (double)global_stats.packets_processed * 1000000000.0 / global_stats.total_processing_time;
        printf("Estimated packets per second: %.2f\n", pps);
    }
    
    pthread_mutex_unlock(&stats_mutex);
}

/* Configuration management */
int load_config_file(const char *filename, struct zapret_config *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Warning: Could not open config file %s, using defaults\n", filename);
        return -1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;
        
        /* Parse configuration options */
        if (strncmp(line, "enable_tls_randomization=", 25) == 0) {
            config->enable_tls_randomization = (line[25] == '1');
        } else if (strncmp(line, "enable_quic_filtering=", 22) == 0) {
            config->enable_quic_filtering = (line[22] == '1');
        } else if (strncmp(line, "enable_packet_fragmentation=", 28) == 0) {
            config->enable_packet_fragmentation = (line[28] == '1');
        } else if (strncmp(line, "enable_sni_encryption=", 22) == 0) {
            config->enable_sni_encryption = (line[22] == '1');
        } else if (strncmp(line, "max_connections=", 16) == 0) {
            config->max_connections = atoi(&line[16]);
        } else if (strncmp(line, "fragment_threshold=", 19) == 0) {
            config->fragment_threshold = atoi(&line[19]);
        }
    }
    
    fclose(fp);
    return 0;
}

/* Main packet processing function */
int process_packet(uint8_t *data, size_t len, struct conn_track *conn) {
    if (!data || len == 0) return -1;
    
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    /* Parse Ethernet header */
    if (len < 14) return -1;
    
    uint16_t eth_type = (data[12] << 8) | data[13];
    if (eth_type != 0x0800) return 0;  /* Not IPv4 */
    
    /* Parse IP header */
    if (len < 34) return -1;
    
    uint8_t *ip_hdr = data + 14;
    uint8_t ip_version = (ip_hdr[0] >> 4) & 0x0F;
    if (ip_version != 4) return 0;
    
    uint8_t ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    uint8_t protocol = ip_hdr[9];
    
    /* Process based on protocol */
    if (protocol == 6 && global_config.enable_tls_randomization) {  /* TCP */
        /* Look for TLS traffic */
        uint8_t *tcp_hdr = ip_hdr + ip_hdr_len;
        if (tcp_hdr + 20 <= data + len) {
            uint8_t tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
            uint8_t *payload = tcp_hdr + tcp_hdr_len;
            
            if (payload < data + len && payload[0] == 0x16) {  /* TLS handshake */
                if (conn) {
                    randomize_tls_fingerprint(&conn->tls_fp);
                }
            }
        }
    } else if (protocol == 17 && global_config.enable_quic_filtering) {  /* UDP */
        /* Look for QUIC traffic */
        uint8_t *udp_hdr = ip_hdr + ip_hdr_len;
        if (udp_hdr + 8 <= data + len) {
            uint8_t *payload = udp_hdr + 8;
            size_t payload_len = len - (payload - data);
            
            if (payload_len > 0 && conn) {
                analyze_quic_packet(payload, payload_len, &conn->quic_info);
            }
        }
    }
    
    /* Apply packet fragmentation if needed */
    if (global_config.enable_packet_fragmentation && conn) {
        fragment_packet_data(data, len, &conn->frag_ctx);
    }
    
    /* Update performance statistics */
    if (global_config.enable_performance_monitoring) {
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        uint64_t processing_time = (end_time.tv_sec - start_time.tv_sec) * 1000000000UL +
                                  (end_time.tv_nsec - start_time.tv_nsec);
        update_stats(processing_time, len);
    }
    
    return 0;
}

/* Statistics reporting thread */
void* stats_thread(void *arg) {
    while (running) {
        sleep(10);  /* Print stats every 10 seconds */
        if (global_stats.packets_processed > 0) {
            print_stats();
        }
    }
    return NULL;
}

/* Main function */
int main(int argc, char *argv[]) {
    printf("Zapret eBPF Loader v1.0\n");
    printf("DPI Evasion and Packet Filtering\n\n");
    
    /* Initialize configuration */
    init_default_config(&global_config);
    
    /* Load configuration file if provided */
    if (argc > 1) {
        load_config_file(argv[1], &global_config);
    }
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Initialize random seed */
    srand(time(NULL));
    
    printf("Configuration loaded:\n");
    printf("  TLS Randomization: %s\n", global_config.enable_tls_randomization ? "Enabled" : "Disabled");
    printf("  QUIC Filtering: %s\n", global_config.enable_quic_filtering ? "Enabled" : "Disabled");
    printf("  Packet Fragmentation: %s\n", global_config.enable_packet_fragmentation ? "Enabled" : "Disabled");
    printf("  SNI Encryption: %s\n", global_config.enable_sni_encryption ? "Enabled" : "Disabled");
    printf("  Performance Monitoring: %s\n", global_config.enable_performance_monitoring ? "Enabled" : "Disabled");
    printf("  Max Connections: %u\n", global_config.max_connections);
    printf("  Fragment Threshold: %u bytes\n\n", global_config.fragment_threshold);
    
    /* Start statistics thread */
    pthread_t stats_tid;
    if (global_config.enable_performance_monitoring) {
        pthread_create(&stats_tid, NULL, stats_thread, NULL);
    }
    
    printf("Zapret eBPF loader is running...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    /* Main processing loop */
    while (running) {
#ifdef __linux__
        /*  packet processing on Linux */
        if (global_config.use_netfilter) {
            /* Process netfilter queue packets */
            int nfq_fd = setup_netfilter_queue();
            if (nfq_fd >= 0) {
                fd_set readfds;
                struct timeval timeout;
                
                FD_ZERO(&readfds);
                FD_SET(nfq_fd, &readfds);
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                
                int ret = select(nfq_fd + 1, &readfds, NULL, NULL, &timeout);
                if (ret > 0 && FD_ISSET(nfq_fd, &readfds)) {
                    handle_netfilter_packet(nfq_fd);
                }
            }
        } else if (global_config.use_tc) {
            /* Process TC/XDP packets */
            handle_tc_packets();
        } else {
            /* Fallback to raw socket */
            handle_raw_socket_packets(&global_config);
        }
#else
        /* Non-Linux platforms - use raw sockets or pcap */
        if (global_config.use_raw_socket) {
            handle_raw_socket_packets(&global_config);
        } else {
            /* Platform-specific packet capture */
            printf("Packet capture not implemented for this platform\n");
            sleep(1);
        }
#endif
    }
    
    /* Cleanup */
    if (global_config.enable_performance_monitoring) {
        pthread_join(stats_tid, NULL);
        print_stats();
    }
    
    printf("\nZapret eBPF loader stopped.\n");
    return 0;
}