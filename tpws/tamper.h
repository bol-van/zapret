#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {UNKNOWN=0, HTTP, TLS} t_l7proto;
typedef struct
{
	// common state
	t_l7proto l7proto;
	bool bFirstReplyChecked;
	bool bTamperInCutoff;
	char *hostname;
} t_ctrack;

void tamper_out(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size, size_t *split_pos);
void tamper_in(t_ctrack *ctrack, uint8_t *segment,size_t segment_buffer_size,size_t *size);
// connection reset by remote leg
void rst_in(t_ctrack *ctrack);
// local leg closed connection (timeout waiting response ?)
void hup_out(t_ctrack *ctrack);
