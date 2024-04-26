/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "crypto_wrapper.h"

void *create_rsa_key_pair(int n_byte_size, uint32_t e)
{
    if (n_byte_size <= 0 || e == 0) {
        return NULL;
    }

    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    BIGNUM* bn_e = BN_new();

    do {
        //create new rsa ctx
        //
        pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
        if (pkey_ctx == NULL) {
            break;
        }
        if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
            break;
        }

        //generate rsa key pair, with n_byte_size*8 mod size and e exponent
        //
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, n_byte_size * 8) <= 0) {
            break;
        }
        if (bn_e == NULL || !BN_set_word(bn_e, e)) {
            break;
        }
        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pkey_ctx, bn_e) <= 0) {
            break;
        }
        if (EVP_PKEY_generate(pkey_ctx, &pkey) <= 0) {
            break;
        }

    } while (0);

    //free rsa ctx (RSA_free also free related BNs obtained in RSA_get functions)
    //
    EVP_PKEY_CTX_free(pkey_ctx);
    BN_free(bn_e);

    return pkey;
}

void *create_rsa_pub_key(const unsigned char *p_n, int len_n, const unsigned char *p_e, int len_e)
{
    if (len_n <= 0 || len_e <= 0 || p_n == NULL || p_e == NULL) {
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    BIGNUM* bn_n = NULL;
    BIGNUM* bn_e = NULL;
    OSSL_PARAM_BLD *param_build = NULL;
    OSSL_PARAM *params = NULL;

    do {
        //convert input buffers to BNs
        //
        bn_n = BN_lebin2bn(p_n, len_n, bn_n);
        if(bn_n == NULL) {
            break;
        }
        bn_e = BN_lebin2bn(p_e, len_e, bn_e);
        if(bn_e == NULL) {
            break;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (pkey_ctx == NULL) {
            break;
        }
        param_build = OSSL_PARAM_BLD_new();
        if (param_build == NULL) {
            break;
        }
        if( !OSSL_PARAM_BLD_push_BN(param_build, "n", bn_n) 
         || !OSSL_PARAM_BLD_push_BN(param_build, "e", bn_e) 
         || (params = OSSL_PARAM_BLD_to_param(param_build)) == NULL) { 
            break;
        }
        if( EVP_PKEY_fromdata_init(pkey_ctx) <= 0) {
            break;
        }
        if( EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
            break;
        }
    } while (0);

    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_BLD_free(param_build);
    OSSL_PARAM_free(params);
    BN_clear_free(bn_n);
    BN_clear_free(bn_e);

    return pkey;
}

bool get_rsa_pub_key(void *pkey, uint8_t *p_n, uint8_t *p_e)
{
    if (pkey == NULL || p_n == NULL || p_e == NULL) {
        return false;
    }

    bool ret_code = false;
    BIGNUM* bn_n = NULL;
    BIGNUM* bn_e = NULL;
    
    do {
        if (EVP_PKEY_get_bn_param((EVP_PKEY*)pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) == 0) {
            break;
        }
        if (EVP_PKEY_get_bn_param((EVP_PKEY*)pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) == 0) {
            break;
        }
        if (!BN_bn2lebinpad(bn_n, p_n, BN_num_bytes(bn_n)) ||
            !BN_bn2lebinpad(bn_e, p_e, BN_num_bytes(bn_e)) ) {
            break;
        }
	ret_code = true;
    } while(0);
    BN_clear_free(bn_n);
    BN_clear_free(bn_e);
    return ret_code;
}
void free_rsa_key(void *pkey)
{
    EVP_PKEY_free((EVP_PKEY *)pkey);
}
