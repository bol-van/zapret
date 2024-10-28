#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "params.h"

#define SPLIT_FLAG_DISORDER	0x01
#define SPLIT_FLAG_OOB		0x02

typedef enum {UNKNOWN=0, HTTP, TLS} t_l7proto;
typedef struct
{
	// common state
	t_l7proto l7proto;
	bool bFirstReplyChecked;
	bool bTamperInCutoff;
	bool b_ah_check;
	char *hostname;
	struct desync_profile *dp;		// desync profile cache
} t_ctrack;

void apply_desync_profile(t_ctrack *ctrack, const struct sockaddr *dest);

void tamper_out(t_ctrack *ctrack, const struct sockaddr *dest, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *split_pos, uint8_t *split_flags);
void tamper_in(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size);
// connection reset by remote leg
void rst_in(t_ctrack *ctrack);
// local leg closed connection (timeout waiting response ?)
void hup_out(t_ctrack *ctrack);
