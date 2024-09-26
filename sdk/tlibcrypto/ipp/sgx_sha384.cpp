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

#include "ippcp.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include "sgx_fips_internal.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

void fips_self_test_hash384()
{
    static bool fips_selftest_hash384_flag = false;

    if (g_global_data.fips_on != 0 && fips_selftest_hash384_flag == false)
    {
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
        int buf_size = 0;
        uint8_t *p_buf = NULL;

        do
        {
            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHash_rmf_get_size, &buf_size);
            p_buf = (uint8_t *)malloc(buf_size);
            FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsHashUpdate_rmf, (IppHashAlgId)ippHashAlg_SHA384, p_buf);
            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHashMessage_rmf, (IppHashAlgId)ippHashAlg_SHA384);

            ret = SGX_SUCCESS;
            fips_selftest_hash384_flag = true;

        } while (0);
        SAFE_FREE(p_buf);
        ERROR_ABORT(ret);
    }
    return;
}

/* Allocates and initializes sha384 state
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
 *   Output: sgx_sha_state_handle_t *p_sha_handle - Pointer to the handle of the SHA384 state  */
sgx_status_t sgx_sha384_init(sgx_sha_state_handle_t *p_sha_handle)
{
    IppStatus ipp_ret = ippStsNoErr;
    IppsHashState_rmf *p_temp_state = NULL;

    if (p_sha_handle == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    fips_self_test_hash384();

    int ctx_size = 0;
    ipp_ret = ippsHashGetSize_rmf(&ctx_size);
    if (ipp_ret != ippStsNoErr)
        return SGX_ERROR_UNEXPECTED;
    p_temp_state = (IppsHashState_rmf *)(malloc(ctx_size));
    if (p_temp_state == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    ipp_ret = ippsHashInit_rmf(p_temp_state, ippsHashMethod_SHA384());
    if (ipp_ret != ippStsNoErr)
    {
        SAFE_FREE(p_temp_state);
        *p_sha_handle = NULL;
        switch (ipp_ret)
        {
        case ippStsNullPtrErr:
        case ippStsLengthErr:
            return SGX_ERROR_INVALID_PARAMETER;
        default:
            return SGX_ERROR_UNEXPECTED;
        }
    }

    *p_sha_handle = p_temp_state;
    return SGX_SUCCESS;
}

/* Updates sha384 has calculation based on the input message
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.
 *   Input:  sgx_sha_state_handle_t sha_handle - Handle to the SHA384 state
 *           uint8_t *p_src - Pointer to the input stream to be hashed
 *           uint32_t src_len - Length of the input stream to be hashed  */
sgx_status_t sgx_sha384_update(const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle)
{
    if ((p_src == NULL) || (sha_handle == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_hash384();

    IppStatus ipp_ret = ippStsNoErr;
    ipp_ret = ippsHashUpdate_rmf(p_src, src_len, (IppsHashState_rmf *)sha_handle);
    switch (ipp_ret)
    {
    case ippStsNoErr:
        return SGX_SUCCESS;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
        return SGX_ERROR_INVALID_PARAMETER;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
}

/* Returns Hash calculation
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
 *   Input:  sgx_sha_state_handle_t sha_handle - Handle to the SHA384 state
 *   Output: sgx_sha384_hash_t *p_hash - Resultant hash from operation  */
sgx_status_t sgx_sha384_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha384_hash_t *p_hash)
{
    if ((sha_handle == NULL) || (p_hash == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_hash384();

    IppStatus ipp_ret = ippStsNoErr;
    ipp_ret = ippsHashGetTag_rmf((Ipp8u *)p_hash, SGX_SHA384_HASH_SIZE, (IppsHashState_rmf *)sha_handle);
    switch (ipp_ret)
    {
    case ippStsNoErr:
        return SGX_SUCCESS;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
        return SGX_ERROR_INVALID_PARAMETER;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
}

/* Cleans up sha state
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
 *   Input:  sgx_sha_state_handle_t sha_handle - Handle to the SHA384 state  */
sgx_status_t sgx_sha384_close(sgx_sha_state_handle_t sha_handle)
{
    if (sha_handle == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    SAFE_FREE(sha_handle);
    return SGX_SUCCESS;
}
