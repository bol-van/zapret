#pragma once

#include "gcm.h"  

int aes_gcm_encrypt(unsigned char* output, const unsigned char* input, size_t input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len);
int aes_gcm_decrypt(unsigned char* output, const unsigned char* input, size_t input_length, const unsigned char* key, const size_t key_len, const unsigned char * iv, const size_t iv_len);
