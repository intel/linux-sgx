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

#include "ipp_wrapper.h"
#include "stdlib.h"
#include "string.h"
#include "sgx_fips_internal.h"

static void fips_self_test_aes_ctr()
{
    static bool fips_selftest_aes_ctr_flag = false;

    if (g_global_data.fips_on != 0 && fips_selftest_aes_ctr_flag == false)
    {
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
        int buf_size = 0;
        uint8_t *p_buf = NULL;
        do
        {
            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptDecrypt_get_size, &buf_size);
            p_buf = (uint8_t *)malloc(buf_size);
            ALLOC_ERROR_BREAK(p_buf, ret);

            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCTR, p_buf);
            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCTR, p_buf);
            ret = SGX_SUCCESS;
            fips_selftest_aes_ctr_flag = true;
        } while (0);
        SAFE_FREE(p_buf);

        ERROR_ABORT(ret);
    }
    return;
}

/* AES-CTR 128-bit
 * Parameters:
 *   Return:
 *     sgx_status_t - SGX_SUCCESS or failure as defined in sgx_error.h
 *   Inputs:
 *     sgx_aes_128bit_key_t *p_key - Pointer to the key used in encryption/decryption operation
 *     uint8_t *p_src - Pointer to the input stream to be encrypted/decrypted
 *     uint32_t src_len - Length of the input stream to be encrypted/decrypted
 *     uint8_t *p_ctr - Pointer to the counter block
 *     uint32_t ctr_inc_bits - Number of bits in counter to be incremented
 *   Output:
 *     uint8_t *p_dst - Pointer to the cipher text. Size of buffer should be >= src_len.
 */
sgx_status_t sgx_aes_ctr_encrypt(const sgx_aes_ctr_128bit_key_t *p_key, const uint8_t *p_src,
                                 const uint32_t src_len, uint8_t *p_ctr, const uint32_t ctr_inc_bits,
                                 uint8_t *p_dst)
{
    IppStatus error_code = ippStsNoErr;
    IppsAESSpec *ptr_ctx = NULL;
    int ctx_size = 0;

    if ((p_key == NULL) || (p_src == NULL) || (p_ctr == NULL) || (p_dst == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_aes_ctr();

    // AES-CTR-128 encryption
    error_code = ippsAESGetSize(&ctx_size);
    if (error_code != ippStsNoErr)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    ptr_ctx = (IppsAESSpec *)malloc(ctx_size);
    if (ptr_ctx == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // Init
    error_code = ippsAESInit((const Ipp8u *)p_key, SGX_AESCTR_KEY_SIZE, ptr_ctx, ctx_size);
    if (error_code != ippStsNoErr)
    {
        // Clear temp State before free.
        memset_s(ptr_ctx, ctx_size, 0, ctx_size);
        free(ptr_ctx);
        switch (error_code)
        {
        case ippStsMemAllocErr:
            return SGX_ERROR_OUT_OF_MEMORY;
        case ippStsNullPtrErr:
        case ippStsLengthErr:
            return SGX_ERROR_INVALID_PARAMETER;
        default:
            return SGX_ERROR_UNEXPECTED;
        }
    }
    error_code = ippsAESEncryptCTR(p_src, p_dst, src_len, ptr_ctx, p_ctr, ctr_inc_bits);
    if (error_code != ippStsNoErr)
    {
        // Clear temp State before free.
        memset_s(ptr_ctx, ctx_size, 0, ctx_size);
        free(ptr_ctx);
        switch (error_code)
        {
        case ippStsCTRSizeErr:
        case ippStsNullPtrErr:
        case ippStsLengthErr:
            return SGX_ERROR_INVALID_PARAMETER;
        default:
            return SGX_ERROR_UNEXPECTED;
        }
    }
    // Clear temp State before free.
    memset_s(ptr_ctx, ctx_size, 0, ctx_size);
    free(ptr_ctx);
    return SGX_SUCCESS;
}

sgx_status_t sgx_aes_ctr_decrypt(const sgx_aes_ctr_128bit_key_t *p_key, const uint8_t *p_src,
                                 const uint32_t src_len, uint8_t *p_ctr, const uint32_t ctr_inc_bits,
                                 uint8_t *p_dst)
{
    IppStatus error_code = ippStsNoErr;
    IppsAESSpec *ptr_ctx = NULL;
    int ctx_size = 0;

    if ((p_key == NULL) || (p_src == NULL) || (p_ctr == NULL) || (p_dst == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_aes_ctr();

    // AES-CTR-128 encryption
    error_code = ippsAESGetSize(&ctx_size);
    if (error_code != ippStsNoErr)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    ptr_ctx = (IppsAESSpec *)malloc(ctx_size);
    if (ptr_ctx == NULL)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    // Init
    error_code = ippsAESInit((const Ipp8u *)p_key, SGX_AESCTR_KEY_SIZE, ptr_ctx, ctx_size);
    if (error_code != ippStsNoErr)
    {
        // Clear temp State before free.
        memset_s(ptr_ctx, ctx_size, 0, ctx_size);
        free(ptr_ctx);
        switch (error_code)
        {
        case ippStsMemAllocErr:
            return SGX_ERROR_OUT_OF_MEMORY;
        case ippStsNullPtrErr:
        case ippStsLengthErr:
            return SGX_ERROR_INVALID_PARAMETER;
        default:
            return SGX_ERROR_UNEXPECTED;
        }
    }
    error_code = ippsAESDecryptCTR(p_src, p_dst, src_len, ptr_ctx, p_ctr, ctr_inc_bits);
    if (error_code != ippStsNoErr)
    {
        // Clear temp State before free.
        memset_s(ptr_ctx, ctx_size, 0, ctx_size);
        free(ptr_ctx);
        switch (error_code)
        {
        case ippStsCTRSizeErr:
        case ippStsNullPtrErr:
        case ippStsLengthErr:
            return SGX_ERROR_INVALID_PARAMETER;
        default:
            return SGX_ERROR_UNEXPECTED;
        }
    }
    // Clear temp State before free.
    memset_s(ptr_ctx, ctx_size, 0, ctx_size);
    free(ptr_ctx);
    return SGX_SUCCESS;
}
