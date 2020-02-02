#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

const uint8_t *find_bin_const(const uint8_t *data, size_t len, const void *blk, size_t blk_len);
uint8_t *find_bin(uint8_t *data, size_t len, const void *blk, size_t blk_len);
void print_sockaddr(const struct sockaddr *sa);
