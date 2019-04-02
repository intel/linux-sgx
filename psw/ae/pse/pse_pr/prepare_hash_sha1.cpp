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

#include "prepare_hash_sha1.h"
#include <stdlib.h>

PrepareHashSHA1::PrepareHashSHA1()
    : m_status(false), m_pCtx(0)
{
    if (sgx_sha1_init(&m_pCtx) == SGX_SUCCESS) {
        m_status = true;
    }
}

PrepareHashSHA1::~PrepareHashSHA1(void)
{
	sgx_sha1_close(m_pCtx);
}

bool PrepareHashSHA1::Update(const void* pData, size_t numBytes)
{
    do
    {
        if (!m_status) {
            break;
	}

        m_status = false;

        if (NULL == pData || numBytes < 1 || NULL == m_pCtx) {
            break;
	}

        if (numBytes > INT32_MAX) {
            break;
	}

        if (sgx_sha1_update((const uint8_t *)pData, numBytes, m_pCtx) != SGX_SUCCESS) {
            break;
	}

        m_status = true;

    } while (0);

    return m_status;
}

// pHash will contain the computed hash if SDS_SUCCESS
bool PrepareHashSHA1::Finalize(sgx_sha1_hash_t *pHash)
{
    do
    {
        if (!m_status) {
            break;
	}

        m_status = false;

        if (NULL == m_pCtx || NULL == pHash) {
            break;
	}

        if (sgx_sha1_get_hash(m_pCtx, pHash) != SGX_SUCCESS) {
            break;
	}

        m_status = true;

    } while (0);

    return m_status;
}
