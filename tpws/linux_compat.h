#ifdef __linux__

#include <linux/types.h>

#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#ifndef IP6T_SO_ORIGINAL_DST
 #define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef PR_SET_NO_NEW_PRIVS
 #define PR_SET_NO_NEW_PRIVS	38
#endif

// workaround for old headers

struct tcp_info_new {
	__u8    tcpi_state;
	__u8    tcpi_ca_state;
	__u8    tcpi_retransmits;
	__u8    tcpi_probes;
	__u8    tcpi_backoff;
	__u8    tcpi_options;
	__u8    tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	__u8    tcpi_delivery_rate_app_limited : 1, tcpi_fastopen_client_fail : 2;

	__u32   tcpi_rto;
	__u32   tcpi_ato;
	__u32   tcpi_snd_mss;
	__u32   tcpi_rcv_mss;

	__u32   tcpi_unacked;
	__u32   tcpi_sacked;
	__u32   tcpi_lost;
	__u32   tcpi_retrans;
	__u32   tcpi_fackets;

	/* Times. */
	__u32   tcpi_last_data_sent;
	__u32   tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32   tcpi_last_data_recv;
	__u32   tcpi_last_ack_recv;

	/* Metrics. */
	__u32   tcpi_pmtu;
	__u32   tcpi_rcv_ssthresh;
	__u32   tcpi_rtt;
	__u32   tcpi_rttvar;
	__u32   tcpi_snd_ssthresh;
	__u32   tcpi_snd_cwnd;
	__u32   tcpi_advmss;
	__u32   tcpi_reordering;

	__u32   tcpi_rcv_rtt;
	__u32   tcpi_rcv_space;

	__u32   tcpi_total_retrans;

	__u64   tcpi_pacing_rate;
	__u64   tcpi_max_pacing_rate;
	__u64   tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	__u64   tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	__u32   tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
	__u32   tcpi_segs_in;        /* RFC4898 tcpEStatsPerfSegsIn */

	__u32   tcpi_notsent_bytes;
	__u32   tcpi_min_rtt;
	__u32   tcpi_data_segs_in;      /* RFC4898 tcpEStatsDataSegsIn */
	__u32   tcpi_data_segs_out;     /* RFC4898 tcpEStatsDataSegsOut */

	__u64   tcpi_delivery_rate;

	__u64   tcpi_busy_time;      /* Time (usec) busy sending data */
	__u64   tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	__u64   tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	__u32   tcpi_delivered;
	__u32   tcpi_delivered_ce;

	__u64   tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	__u64   tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
	__u32   tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
	__u32   tcpi_reord_seen;     /* reordering events seen */

	__u32   tcpi_rcv_ooopack;    /* Out-of-order packets received */

	__u32   tcpi_snd_wnd;        /* peer's advertised receive window after
								  * scaling (bytes)
								  */
	__u32   tcpi_rcv_wnd;        /* local advertised receive window after
								  * scaling (bytes)
								  */

	__u32   tcpi_rehash;         /* PLB or timeout triggered rehash attempts */

	__u16   tcpi_total_rto; /* Total number of RTO timeouts, including
							 * SYN/SYN-ACK and recurring timeouts.
							 */
	__u16   tcpi_total_rto_recoveries;      /* Total number of RTO
											 * recoveries, including any
											 * unfinished recovery.
											 */
	__u32   tcpi_total_rto_time;    /* Total time spent in RTO recoveries
									 * in milliseconds, including any
									 * unfinished recovery.
									 */
};

#endif
