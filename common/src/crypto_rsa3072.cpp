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
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include "crypto_wrapper.h"

bool create_rsa3072_signature(void *pkey, const uint8_t *p_data, uint32_t data_size, uint8_t *p_signature, size_t siglen)
{
    if ((pkey == NULL) || (p_data == NULL) || (data_size < 1) || (p_signature == NULL || siglen != SIGNATURE_SIZE))
    {
	return false;
    }

    // generate digest
    uint8_t hash[SGX_HASH_SIZE] = {0};
    unsigned int hash_size = SGX_HASH_SIZE;
    if(SGX_SUCCESS != sgx_EVP_Digest(EVP_sha256(), p_data, data_size, hash, &hash_size))
    {
        return false;
    }

    // sign
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)pkey, NULL);
    if(!ctx)
    {
        return false;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if(EVP_PKEY_sign(ctx, NULL, &siglen, hash, hash_size) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if(SIGNATURE_SIZE != siglen)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    int ret = EVP_PKEY_sign(ctx, p_signature, &siglen, hash, hash_size);

    EVP_PKEY_CTX_free(ctx);

    return ret == 1 ? true : false;
}

bool verify_rsa3072_signature(void *pkey, const uint8_t *p_data, uint32_t data_size, uint8_t *p_signature, size_t siglen)
{
    if ((pkey == NULL) || (p_data == NULL) || (data_size < 1) || (p_signature == NULL || siglen != SIGNATURE_SIZE))
    {
        return false;
    }

    // generate digest
    uint8_t hash[SGX_HASH_SIZE] = {0};
    unsigned int hash_size = SGX_HASH_SIZE;
    if(SGX_SUCCESS != sgx_EVP_Digest(EVP_sha256(), p_data, data_size, hash, &hash_size))
    {
        return false;
    }

    // verify
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)pkey, NULL);
    if(!ctx)
    {
        return false;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    int ret = EVP_PKEY_verify(ctx, p_signature, siglen, hash, hash_size);

    EVP_PKEY_CTX_free(ctx);

    return ret == 1 ? true : false;
}

