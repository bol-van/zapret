#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "params.h"

#define SPLIT_FLAG_DISORDER	0x01
#define SPLIT_FLAG_OOB		0x02

typedef struct
{
	// common state
	t_l7proto l7proto;
	bool bTamperInCutoff;
	bool b_host_checked,b_host_matches,b_ah_check;
	bool hostname_discovered;
	char *hostname;
	struct desync_profile *dp;		// desync profile cache
} t_ctrack;

void apply_desync_profile(t_ctrack *ctrack, const struct sockaddr *dest);
bool ipcache_put_hostname(const struct in_addr *a4, const struct in6_addr *a6, const char *hostname);

void tamper_out(t_ctrack *ctrack, const struct sockaddr *dest, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *multisplit_pos, int *multisplit_count, uint8_t *split_flags);
void tamper_in(t_ctrack *ctrack, const struct sockaddr *client, uint8_t *segment,size_t segment_buffer_size,size_t *size);
// connection reset by remote leg
void rst_in(t_ctrack *ctrack, const struct sockaddr *client);
// local leg closed connection (timeout waiting response ?)
void hup_out(t_ctrack *ctrack, const struct sockaddr *client);

void packet_debug(const uint8_t *data, size_t sz);
