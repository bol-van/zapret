#pragma once

#include <stdbool.h>
#include <sys/types.h>

char *find_bin(void *data, size_t len, const void *blk, size_t blk_len);
bool find_host(char **pHost,char *buf,size_t bs);
void modify_tcp_segment(char *segment,size_t *size,size_t *split_pos);
