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

#ifndef _SGX_UAE_PLATFORM_H_
#define _SGX_UAE_PLATFORM_H_

#include <stdint.h>

#include "sgx_error.h"
#include "sgx_urts.h"

#define PS_CAP_TRUSTED_TIME         0x1
#define PS_CAP_MONOTONIC_COUNTER    0x2

/**
 * Platform service capabilities
 *      ps_cap0
 *       Bit 0 : Trusted Time
 *       Bit 1 : Monotonic Counter
 *       Bit 2-31 : Reserved
 *      ps_cap1
 *       Bit 0-31 : Reserved
 */
typedef struct _sgx_ps_cap_t
{
    uint32_t ps_cap0;
    uint32_t ps_cap1;
} sgx_ps_cap_t;

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Get the platform service capabilities
 *
 * @param sgx_ps_cap Platform capabilities reported by AESM.
 * @return if OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_get_ps_cap(sgx_ps_cap_t* p_sgx_ps_cap);

#define SGX_IS_TRUSTED_TIME_AVAILABLE(cap)           ((((uint32_t)PS_CAP_TRUSTED_TIME)&((cap).ps_cap0))!=0)
#define SGX_IS_MONOTONIC_COUNTER_AVAILABLE(cap)      ((((uint32_t)PS_CAP_MONOTONIC_COUNTER)&((cap).ps_cap0))!=0)

#ifdef  __cplusplus
}
#endif

#endif
