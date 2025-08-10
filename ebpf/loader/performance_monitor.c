/*
 * Zapret Performance Monitor
 * Performance monitoring and optimization for eBPF packet filtering
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <signal.h>
#include <math.h>
#include "../include/zapret_ebpf.h"

/* Performance monitoring configuration */
#define PERF_SAMPLE_INTERVAL 1000  /* 1 second in milliseconds */
#define PERF_HISTORY_SIZE 3600     /* 1 hour of samples */
#define PERF_ALERT_THRESHOLD_CPU 80.0  /* CPU usage alert threshold */
#define PERF_ALERT_THRESHOLD_MEMORY 90.0  /* Memory usage alert threshold */
#define PERF_ALERT_THRESHOLD_LATENCY 10000000  /* 10ms latency threshold */

/* Performance metrics history */
struct perf_sample {
    time_t timestamp;
    double cpu_usage;
    double memory_usage;
    uint64_t packets_per_second;
    uint64_t bytes_per_second;
    uint64_t avg_latency_ns;
    uint64_t max_latency_ns;
    uint64_t connections_active;
    uint64_t tls_randomizations;
    uint64_t packet_fragmentations;
    uint64_t sni_encryptions;
};

static struct perf_sample perf_history[PERF_HISTORY_SIZE];
static int perf_history_index = 0;
static int perf_history_count = 0;
static pthread_mutex_t perf_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Performance alerts */
struct perf_alert {
    time_t timestamp;
    char message[256];
    int severity;  /* 1=info, 2=warning, 3=critical */
};

#define MAX_ALERTS 100
static struct perf_alert alert_history[MAX_ALERTS];
static int alert_count = 0;
static pthread_mutex_t alert_mutex = PTHREAD_MUTEX_INITIALIZER;

/* External references */
extern struct perf_stats global_stats;
extern pthread_mutex_t stats_mutex;
extern int get_connection_stats(int *active_connections, int *total_connections);

/* Forward declarations */
void check_performance_alerts(struct perf_sample *sample);

/* System resource monitoring */
static double get_cpu_usage(void) {
    static struct rusage prev_usage = {0};
    static struct timeval prev_time = {0};
    
    struct rusage current_usage;
    struct timeval current_time;
    
    getrusage(RUSAGE_SELF, &current_usage);
    gettimeofday(&current_time, NULL);
    
    if (prev_time.tv_sec == 0) {
        prev_usage = current_usage;
        prev_time = current_time;
        return 0.0;
    }
    
    /* Calculate time differences */
    double time_diff = (current_time.tv_sec - prev_time.tv_sec) + 
                      (current_time.tv_usec - prev_time.tv_usec) / 1000000.0;
    
    double user_time_diff = (current_usage.ru_utime.tv_sec - prev_usage.ru_utime.tv_sec) +
                           (current_usage.ru_utime.tv_usec - prev_usage.ru_utime.tv_usec) / 1000000.0;
    
    double sys_time_diff = (current_usage.ru_stime.tv_sec - prev_usage.ru_stime.tv_sec) +
                          (current_usage.ru_stime.tv_usec - prev_usage.ru_stime.tv_usec) / 1000000.0;
    
    double cpu_usage = ((user_time_diff + sys_time_diff) / time_diff) * 100.0;
    
    prev_usage = current_usage;
    prev_time = current_time;
    
    return cpu_usage;
}

static double get_memory_usage(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0.0;
    
    char line[256];
    long vm_rss = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld kB", &vm_rss);
            break;
        }
    }
    
    fclose(fp);
    
    /* Get total system memory */
    fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0.0;
    
    long mem_total = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line, "MemTotal: %ld kB", &mem_total);
            break;
        }
    }
    
    fclose(fp);
    
    if (mem_total == 0) return 0.0;
    
    return ((double)vm_rss / mem_total) * 100.0;
}

/* Performance alert system */
void add_performance_alert(const char *message, int severity) {
    pthread_mutex_lock(&alert_mutex);
    
    if (alert_count < MAX_ALERTS) {
        alert_history[alert_count].timestamp = time(NULL);
        strncpy(alert_history[alert_count].message, message, sizeof(alert_history[alert_count].message) - 1);
        alert_history[alert_count].message[sizeof(alert_history[alert_count].message) - 1] = '\0';
        alert_history[alert_count].severity = severity;
        alert_count++;
    }
    
    pthread_mutex_unlock(&alert_mutex);
    
    /* Print alert to console */
    const char *severity_str[] = {"", "INFO", "WARNING", "CRITICAL"};
    printf("[%s] %s\n", severity_str[severity], message);
}

/* Performance sample collection */
void collect_performance_sample(void) {
    struct perf_sample sample = {0};
    
    sample.timestamp = time(NULL);
    sample.cpu_usage = get_cpu_usage();
    sample.memory_usage = get_memory_usage();
    
    /* Get packet processing statistics */
    pthread_mutex_lock(&stats_mutex);
    
    static uint64_t prev_packets = 0;
    static uint64_t prev_bytes = 0;
    static time_t prev_time = 0;
    
    uint64_t current_packets = global_stats.packets_processed;
    uint64_t current_bytes = global_stats.bytes_processed;
    time_t current_time = sample.timestamp;
    
    if (prev_time > 0) {
        time_t time_diff = current_time - prev_time;
        if (time_diff > 0) {
            sample.packets_per_second = (current_packets - prev_packets) / time_diff;
            sample.bytes_per_second = (current_bytes - prev_bytes) / time_diff;
        }
    }
    
    /* Calculate average latency */
    if (global_stats.packets_processed > 0) {
        sample.avg_latency_ns = global_stats.total_processing_time / global_stats.packets_processed;
    }
    
    sample.max_latency_ns = global_stats.max_processing_time;
    sample.tls_randomizations = global_stats.tls_fingerprints_randomized;
    sample.packet_fragmentations = global_stats.packets_fragmented;
    sample.sni_encryptions = global_stats.sni_encrypted;
    
    prev_packets = current_packets;
    prev_bytes = current_bytes;
    prev_time = current_time;
    
    pthread_mutex_unlock(&stats_mutex);
    
    /* Get connection statistics */
    int active_connections = 0;
    get_connection_stats(&active_connections, NULL);
    sample.connections_active = active_connections;
    
    /* Store sample in history */
    pthread_mutex_lock(&perf_mutex);
    
    perf_history[perf_history_index] = sample;
    perf_history_index = (perf_history_index + 1) % PERF_HISTORY_SIZE;
    
    if (perf_history_count < PERF_HISTORY_SIZE) {
        perf_history_count++;
    }
    
    pthread_mutex_unlock(&perf_mutex);
    
    /* Check for performance alerts */
    check_performance_alerts(&sample);
}

/* Performance alert checking */
void check_performance_alerts(struct perf_sample *sample) {
    char alert_msg[256];
    
    /* CPU usage alert */
    if (sample->cpu_usage > PERF_ALERT_THRESHOLD_CPU) {
        snprintf(alert_msg, sizeof(alert_msg), 
                "High CPU usage detected: %.1f%%", sample->cpu_usage);
        add_performance_alert(alert_msg, 2);
    }
    
    /* Memory usage alert */
    if (sample->memory_usage > PERF_ALERT_THRESHOLD_MEMORY) {
        snprintf(alert_msg, sizeof(alert_msg), 
                "High memory usage detected: %.1f%%", sample->memory_usage);
        add_performance_alert(alert_msg, 2);
    }
    
    /* Latency alert */
    if (sample->avg_latency_ns > PERF_ALERT_THRESHOLD_LATENCY) {
        snprintf(alert_msg, sizeof(alert_msg), 
                "High processing latency detected: %.2fms", 
                sample->avg_latency_ns / 1000000.0);
        add_performance_alert(alert_msg, 2);
    }
    
    /* Throughput monitoring */
    if (sample->packets_per_second > 100000) {
        snprintf(alert_msg, sizeof(alert_msg), 
                "High packet rate: %lu pps", sample->packets_per_second);
        add_performance_alert(alert_msg, 1);
    }
}

/* Performance statistics calculation */
void calculate_performance_stats(struct perf_sample *min, struct perf_sample *max, struct perf_sample *avg) {
    if (perf_history_count == 0) return;
    
    pthread_mutex_lock(&perf_mutex);
    
    memset(min, 0, sizeof(*min));
    memset(max, 0, sizeof(*max));
    memset(avg, 0, sizeof(*avg));
    
    /* Initialize min values */
    *min = perf_history[0];
    
    double sum_cpu = 0, sum_memory = 0;
    uint64_t sum_pps = 0, sum_bps = 0, sum_latency = 0, sum_connections = 0;
    
    for (int i = 0; i < perf_history_count; i++) {
        struct perf_sample *sample = &perf_history[i];
        
        /* Update minimums */
        if (sample->cpu_usage < min->cpu_usage) min->cpu_usage = sample->cpu_usage;
        if (sample->memory_usage < min->memory_usage) min->memory_usage = sample->memory_usage;
        if (sample->avg_latency_ns < min->avg_latency_ns) min->avg_latency_ns = sample->avg_latency_ns;
        
        /* Update maximums */
        if (sample->cpu_usage > max->cpu_usage) max->cpu_usage = sample->cpu_usage;
        if (sample->memory_usage > max->memory_usage) max->memory_usage = sample->memory_usage;
        if (sample->packets_per_second > max->packets_per_second) max->packets_per_second = sample->packets_per_second;
        if (sample->bytes_per_second > max->bytes_per_second) max->bytes_per_second = sample->bytes_per_second;
        if (sample->avg_latency_ns > max->avg_latency_ns) max->avg_latency_ns = sample->avg_latency_ns;
        if (sample->max_latency_ns > max->max_latency_ns) max->max_latency_ns = sample->max_latency_ns;
        if (sample->connections_active > max->connections_active) max->connections_active = sample->connections_active;
        
        /* Accumulate for averages */
        sum_cpu += sample->cpu_usage;
        sum_memory += sample->memory_usage;
        sum_pps += sample->packets_per_second;
        sum_bps += sample->bytes_per_second;
        sum_latency += sample->avg_latency_ns;
        sum_connections += sample->connections_active;
    }
    
    /* Calculate averages */
    avg->cpu_usage = sum_cpu / perf_history_count;
    avg->memory_usage = sum_memory / perf_history_count;
    avg->packets_per_second = sum_pps / perf_history_count;
    avg->bytes_per_second = sum_bps / perf_history_count;
    avg->avg_latency_ns = sum_latency / perf_history_count;
    avg->connections_active = sum_connections / perf_history_count;
    
    pthread_mutex_unlock(&perf_mutex);
}

/* Performance report generation */
void print_performance_report(void) {
    struct perf_sample min, max, avg;
    calculate_performance_stats(&min, &max, &avg);
    
    printf("\n=== Zapret Performance Report ===\n");
    printf("Monitoring period: %d samples (%d minutes)\n", 
           perf_history_count, perf_history_count / 60);
    
    printf("\nCPU Usage:\n");
    printf("  Current: %.1f%%\n", perf_history_count > 0 ? perf_history[(perf_history_index - 1 + PERF_HISTORY_SIZE) % PERF_HISTORY_SIZE].cpu_usage : 0.0);
    printf("  Average: %.1f%%\n", avg.cpu_usage);
    printf("  Min/Max: %.1f%% / %.1f%%\n", min.cpu_usage, max.cpu_usage);
    
    printf("\nMemory Usage:\n");
    printf("  Current: %.1f%%\n", perf_history_count > 0 ? perf_history[(perf_history_index - 1 + PERF_HISTORY_SIZE) % PERF_HISTORY_SIZE].memory_usage : 0.0);
    printf("  Average: %.1f%%\n", avg.memory_usage);
    printf("  Min/Max: %.1f%% / %.1f%%\n", min.memory_usage, max.memory_usage);
    
    printf("\nThroughput:\n");
    printf("  Average PPS: %lu packets/sec\n", avg.packets_per_second);
    printf("  Peak PPS: %lu packets/sec\n", max.packets_per_second);
    printf("  Average BPS: %.2f MB/sec\n", avg.bytes_per_second / (1024.0 * 1024.0));
    printf("  Peak BPS: %.2f MB/sec\n", max.bytes_per_second / (1024.0 * 1024.0));
    
    printf("\nLatency:\n");
    printf("  Average: %.2f ms\n", avg.avg_latency_ns / 1000000.0);
    printf("  Peak: %.2f ms\n", max.max_latency_ns / 1000000.0);
    
    printf("\nConnections:\n");
    printf("  Average active: %lu\n", avg.connections_active);
    printf("  Peak active: %lu\n", max.connections_active);
    
    printf("\nDPI Evasion Activity:\n");
    printf("  TLS fingerprints randomized: %lu\n", max.tls_randomizations);
    printf("  Packets fragmented: %lu\n", max.packet_fragmentations);
    printf("  SNI encryptions: %lu\n", max.sni_encryptions);
    
    /* Performance optimization recommendations */
    printf("\n=== Performance Recommendations ===\n");
    
    if (avg.cpu_usage > 70.0) {
        printf("⚠️  High CPU usage detected. Consider:\n");
        printf("   - Reducing TLS randomization frequency\n");
        printf("   - Optimizing filter rules\n");
        printf("   - Using hardware acceleration if available\n");
    }
    
    if (avg.memory_usage > 80.0) {
        printf("⚠️  High memory usage detected. Consider:\n");
        printf("   - Reducing connection timeout\n");
        printf("   - Implementing connection pooling\n");
        printf("   - Cleaning up old connections more frequently\n");
    }
    
    if (avg.avg_latency_ns > 5000000) {  /* 5ms */
        printf("⚠️  High processing latency detected. Consider:\n");
        printf("   - Optimizing packet parsing logic\n");
        printf("   - Using eBPF for kernel-level filtering\n");
        printf("   - Reducing complexity of DPI evasion techniques\n");
    }
    
    if (max.packets_per_second > 50000) {
        printf("✅ High throughput achieved. System performing well.\n");
    }
    
    printf("\n");
}

/* Performance monitoring thread */
void* performance_monitor_thread(void *arg) {
    printf("Performance monitor started\n");
    
    while (1) {
        collect_performance_sample();
        usleep(PERF_SAMPLE_INTERVAL * 1000);  /* Convert to microseconds */
    }
    
    return NULL;
}

/* Export performance data to CSV */
int export_performance_data(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("Error: Could not create performance export file %s\n", filename);
        return -1;
    }
    
    /* Write CSV header */
    fprintf(fp, "timestamp,cpu_usage,memory_usage,packets_per_second,bytes_per_second,"
               "avg_latency_ns,max_latency_ns,connections_active,tls_randomizations,"
               "packet_fragmentations,sni_encryptions\n");
    
    pthread_mutex_lock(&perf_mutex);
    
    for (int i = 0; i < perf_history_count; i++) {
        struct perf_sample *sample = &perf_history[i];
        
        fprintf(fp, "%ld,%.2f,%.2f,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
                sample->timestamp,
                sample->cpu_usage,
                sample->memory_usage,
                sample->packets_per_second,
                sample->bytes_per_second,
                sample->avg_latency_ns,
                sample->max_latency_ns,
                sample->connections_active,
                sample->tls_randomizations,
                sample->packet_fragmentations,
                sample->sni_encryptions);
    }
    
    pthread_mutex_unlock(&perf_mutex);
    
    fclose(fp);
    printf("Performance data exported to %s\n", filename);
    return 0;
}

/* Initialize performance monitoring */
int init_performance_monitor(void) {
    /* Reset performance history */
    memset(perf_history, 0, sizeof(perf_history));
    perf_history_index = 0;
    perf_history_count = 0;
    
    /* Reset alert history */
    memset(alert_history, 0, sizeof(alert_history));
    alert_count = 0;
    
    printf("Performance monitor initialized\n");
    printf("  Sample interval: %d ms\n", PERF_SAMPLE_INTERVAL);
    printf("  History size: %d samples\n", PERF_HISTORY_SIZE);
    printf("  Alert thresholds: CPU %.1f%%, Memory %.1f%%, Latency %.1fms\n",
           PERF_ALERT_THRESHOLD_CPU, PERF_ALERT_THRESHOLD_MEMORY, 
           PERF_ALERT_THRESHOLD_LATENCY / 1000000.0);
    
    return 0;
}

/* Get current performance metrics */
int get_current_performance_metrics(struct perf_sample *current) {
    if (!current || perf_history_count == 0) return -1;
    
    pthread_mutex_lock(&perf_mutex);
    
    int latest_index = (perf_history_index - 1 + PERF_HISTORY_SIZE) % PERF_HISTORY_SIZE;
    *current = perf_history[latest_index];
    
    pthread_mutex_unlock(&perf_mutex);
    
    return 0;
}