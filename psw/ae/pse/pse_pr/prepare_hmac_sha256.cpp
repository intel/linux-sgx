/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#include "prepare_hmac_sha256.h"
#include <stdlib.h>


PrepareHMACSHA256::PrepareHMACSHA256(const unsigned char *key, size_t keyLength)
    : m_sgxstatus(SGX_ERROR_UNEXPECTED), m_pCtx(NULL)
{
        m_sgxstatus = sgx_hmac256_init(key, (int)keyLength, &m_pCtx);
}

PrepareHMACSHA256::~PrepareHMACSHA256(void)
{
    if (m_pCtx) {
        sgx_hmac256_close(m_pCtx);
	}
}

ae_error_t PrepareHMACSHA256::Update(const void* pData, size_t numBytes)
{
    do
    {
        //validate calling object has passed initialization
        //
        if (m_sgxstatus != SGX_SUCCESS) {
            break;
        }

        if (NULL == pData || numBytes < 1 || NULL == m_pCtx || numBytes > INT32_MAX)
        {
            m_sgxstatus = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        m_sgxstatus = sgx_hmac256_update((const uint8_t*)pData, (int)numBytes, m_pCtx);
        if (m_sgxstatus != SGX_SUCCESS)
            break;

    } while (0);

    ae_error_t ae_status = AE_SUCCESS;
    if (m_sgxstatus != SGX_SUCCESS)
    {
        if (m_sgxstatus == SGX_ERROR_OUT_OF_MEMORY)
            ae_status = PSE_PR_INSUFFICIENT_MEMORY_ERROR;
        else
            ae_status = PSE_PR_HMAC_CALC_ERROR;
    }

    return ae_status;
}

// pCMAC will contain the computed CMAC if SDS_SUCCESS
ae_error_t PrepareHMACSHA256::Finalize(SIGMA_HMAC *pHMAC)
{
    do
    {
        if (m_sgxstatus != SGX_SUCCESS)
            break;

        if (NULL == m_pCtx || NULL == pHMAC)
        {
            m_sgxstatus = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        m_sgxstatus = sgx_hmac256_final(*pHMAC, SIGMA_HMAC_LENGTH, m_pCtx);
        if (m_sgxstatus != SGX_SUCCESS)
            break;

    } while (0);

    ae_error_t ae_status = AE_SUCCESS;
    if (m_sgxstatus != SGX_SUCCESS)
    {
        if (m_sgxstatus == SGX_ERROR_OUT_OF_MEMORY)
            ae_status = PSE_PR_INSUFFICIENT_MEMORY_ERROR;
        else
            ae_status = PSE_PR_HMAC_CALC_ERROR;
    }

    return ae_status;
}
