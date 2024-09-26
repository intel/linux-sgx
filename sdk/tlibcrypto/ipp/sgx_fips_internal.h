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

#pragma once

#include "sgx_tcrypto.h"
#include "ippcp.h"
#include "ippcp/fips_cert.h"
#include "global_data.h"

#define ERROR_SELFTEST_BREAK(test_result)     \
    if (test_result != IPPCP_ALGO_SELFTEST_OK) \
    {                                          \
        break;                                 \
    }
#define ALLOC_ERROR_BREAK(pointer, ret)  \
    if (pointer == NULL)                 \
    {                                  \
        ret = SGX_ERROR_OUT_OF_MEMORY; \
        break;                         \
    }

#define FIPS_SELFTEST_FUNC(result, func) \
    result = func();                     \
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_1(result, func, para) \
    result = func(para);                       \
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_2(result, func, para1, para2) \
    result = func(para1, para2);\
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_3(result, func, para1, para2, para3) \
    result = func(para1, para2, para3);\
    ERROR_SELFTEST_BREAK(result)

#define ERROR_ABORT(ret)               \
    {                                  \
        if (ret != SGX_SUCCESS)        \
        {                              \
            g_global_data.fips_on = 0; \
            abort();                   \
        }                              \
    }

void fips_self_test_ecc();
void fips_self_test_hash256();
void fips_self_test_hash384();
