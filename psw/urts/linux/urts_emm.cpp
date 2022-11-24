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

#include "urts_emm.h"
#include "sgx_enclave_common.h"

#ifdef SE_SIM
#include "util.h"
#include <sys/mman.h>
#endif

typedef struct ms_alloc_ocall_t {
    int32_t  retval;
    size_t addr;
    size_t size;
    uint32_t page_properties;
    uint32_t alloc_flags;
} ms_emm_alloc_ocall_t;

extern "C" sgx_status_t SGX_CDECL ocall_emm_alloc(void* pms)
{
#ifdef SE_SIM
    UNUSED(pms);
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
#else
    ms_emm_alloc_ocall_t* ms = SGX_CAST(ms_emm_alloc_ocall_t*, pms);
    ms->retval = enclave_alloc((void *)ms->addr, ms->size,ms->page_properties,  ms->alloc_flags, NULL);
    return SGX_SUCCESS;
#endif
}

typedef struct ms_modify_ocall_t {
    int32_t  retval;
    size_t addr;
    size_t size;
    uint32_t flags_from;
    uint32_t flags_to;
} ms_emm_modify_ocall_t;


extern "C" sgx_status_t SGX_CDECL ocall_emm_modify(void* pms)
{
#ifdef SE_SIM
    UNUSED(pms);
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
#else
    ms_emm_modify_ocall_t* ms = SGX_CAST(ms_emm_modify_ocall_t*, pms);
    ms->retval = enclave_modify((void *)ms->addr, ms->size, ms->flags_from, ms->flags_to, NULL);
    return SGX_SUCCESS;
#endif
}
