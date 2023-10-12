#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

bool find_host(uint8_t **pHost,uint8_t *buf,size_t bs);
void modify_tcp_segment(uint8_t *segment,size_t segment_buffer_size,size_t *size,size_t *split_pos);
