#pragma once

#include <stdbool.h>
#include <sys/types.h>

bool find_host(char **pHost,char *buf,size_t bs);
void modify_tcp_segment(char *segment,size_t segment_buffer_size,size_t *size,size_t *split_pos);
