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

#include "crypto_wrapper.h"
#include <openssl/cmac.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <stdint.h>
#include <assert.h>
#include <se_memcpy.h>

sgx_status_t sgx_cmac128_msg(const sgx_key_128bit_t key, const uint8_t *p_src, unsigned int src_len, sgx_mac_t *p_mac)
{
    if(!key || !p_src || src_len == 0 || !p_mac)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_LIB_CTX *lib_ctx = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char cipher_name[] = "AES-128-CBC";
    size_t mac_len = 0;
    do
    {
        if ((lib_ctx = OSSL_LIB_CTX_new()) == NULL)
        {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        if ((mac = EVP_MAC_fetch(lib_ctx, "CMAC", NULL)) == NULL)
        {
            break;
        }
        if ((mctx = EVP_MAC_CTX_new(mac)) == NULL)
        {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,  cipher_name, sizeof(cipher_name));

        if ((!EVP_MAC_init(mctx, key, sizeof(sgx_key_128bit_t), params)))
        {
            break;
        }
        if (!EVP_MAC_update(mctx, p_src, src_len))
        {
            break;
        }
        if (!EVP_MAC_final(mctx, (uint8_t *)p_mac, &mac_len, sizeof(sgx_mac_t))) 
        {
            break;
        }
        if(mac_len != sizeof(sgx_mac_t))
        {
            break;
        }
        ret = SGX_SUCCESS;
    } while (0);

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(lib_ctx);

    return ret;
#else
    CMAC_CTX *cmac_ctx = NULL;
    size_t mac_len;
    
    if(!(cmac_ctx = CMAC_CTX_new()))
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    if(!CMAC_Init(cmac_ctx, key, sizeof(sgx_key_128bit_t), EVP_aes_128_cbc(), NULL))
    {
        CMAC_CTX_free(cmac_ctx);
        return SGX_ERROR_UNEXPECTED;
    }
    if(!CMAC_Update(cmac_ctx, p_src, src_len))
    {
        CMAC_CTX_free(cmac_ctx);
        return SGX_ERROR_UNEXPECTED;
    }
    if(!CMAC_Final(cmac_ctx, (uint8_t *)p_mac, &mac_len))
    {
        CMAC_CTX_free(cmac_ctx);
        return SGX_ERROR_UNEXPECTED;
    }
    CMAC_CTX_free(cmac_ctx);
    if(mac_len != sizeof(sgx_mac_t))
    {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
#endif

}
