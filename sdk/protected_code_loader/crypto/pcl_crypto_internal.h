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

#ifndef SGX_PCL_CRYPTO_INTERNAL_H
#define SGX_PCL_CRYPTO_INTERNAL_H

extern "C" 
{

int pcl_SHA256_Update(SHA256_CTX *c, void *data_, size_t len);
int pcl_SHA256_Final(unsigned char *md, SHA256_CTX *c);
int pcl_SHA256_Init(SHA256_CTX *c);

typedef uint64_t          u64;
typedef uint32_t          u32;
typedef uint8_t           u8;
typedef struct {
    u64 hi, lo;
} u128;

int pcl_vpaes_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
    u128 Htable[16];
    void (*gmult) (u64 Xi[2], const u128 Htable[16]);
    void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
    unsigned int mres, ares;
    block128_f block;
    void *key;
};

void pcl_CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
void pcl_CRYPTO_gcm128_setiv(
        GCM128_CONTEXT *ctx, 
        const unsigned char *iv,
        size_t len);
int pcl_CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len);
int pcl_CRYPTO_gcm128_aad(
        GCM128_CONTEXT *ctx, 
        const unsigned char *aad,
        size_t len);
int pcl_CRYPTO_gcm128_finish(
        GCM128_CONTEXT *ctx, 
        const unsigned char *tag,
        size_t len);
void pcl_vpaes_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

#ifdef SE_SIM

void make_kn(
        unsigned char *k1, 
        const unsigned char *l, 
        int bl);
void pcl_vpaes_cbc_encrypt(
            uint8_t* in, 
            uint8_t* out, 
            size_t len, 
            AES_KEY* wide_key_p, 
            uint8_t* iv, 
            bool encrypt);

#endif // #ifdef SE_SIM 

}; // extern "C" 

#endif // #ifndef SGX_PCL_CRYPTO_INTERNAL_H

