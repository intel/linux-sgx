/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SGX_PCL_INTERNAL_H
#define SGX_PCL_INTERNAL_H

#define ALIGN_X2Y_AUX(x,y) \
    (x % y ? x + y - (x % y) : x)
#define ALIGN_X2Y(x,y) ALIGN_X2Y_AUX((x),(y))
#define CASTU8P(x) ((uint8_t*)(x))
#define CAST_VOLATILE_U8P(x) ((volatile uint8_t*)(x))
#define CASTU64(x) ((uint64_t)(x))
#define ROUND_TO(x,y) ALIGN_X2Y(x,y)
#define MAX(x,y) ((x)>(y)?(x):(y))
#define assert(x)



#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

void pcl_memcpy(OUT void* dst, IN void* src, size_t size);
void pcl_memset(OUT void* dst, uint8_t val, size_t size);
void pcl_volatile_memset(OUT volatile void* dst, uint8_t val, size_t size);
// code taken from consttime_memequal
uint32_t pcl_consttime_memequal(IN const void *b1, IN const void *b2, size_t len); 

int pcl_decrypt(
        IN unsigned char *ciphertext, 
        size_t ciphertext_len, 
        IN unsigned char *aad,
        size_t aad_len, 
        IN unsigned char *tag, 
        IN unsigned char *key, 
        IN unsigned char *iv,
        OUT unsigned char *plaintext);

sgx_status_t pcl_sha256(IN uint8_t* buf, size_t buflen, OUT uint8_t* hash);
sgx_status_t pcl_unseal_data(
        IN const sgx_sealed_data_t *p_sealed_data, 
        IN uint8_t *p_additional_MACtext,
        INOUT uint32_t *p_additional_MACtext_length, 
        OUT uint8_t *p_decrypted_text, 
        INOUT uint32_t *p_decrypted_text_length);
sgx_status_t pcl_gcm_decrypt(
        IN uint8_t* plaintext, 
        OUT uint8_t* ciphertext, 
        size_t textlen,
        IN uint8_t* aad, 
        size_t aad_len, 
        IN uint8_t* key, 
        IN uint8_t* iv, 
        IN uint8_t* tag);
        
uint32_t pcl_bswap32(uint32_t val);
uint64_t pcl_bswap64(uint64_t val);

sgx_status_t pcl_increment_iv(INOUT uint8_t* iv);

void abort(void) __attribute__((__noreturn__));

int pcl_is_outside_enclave(const void *addr, size_t size);
int pcl_is_within_enclave(const void *addr, size_t size);
#ifdef __cplusplus
}; // extern "C" 
#endif // #ifdef __cplusplus

#endif // #ifndef SGX_PCL_INTERNAL_H

