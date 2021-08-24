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

#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include "ema.h"
#include "emm_private.h"
#include "sgx_mm_rt_abstraction.h"

extern ema_root_t g_rts_ema_root;
#define LEGAL_INIT_FLAGS (\
                          SGX_EMA_PAGE_TYPE_REG \
                        | SGX_EMA_PAGE_TYPE_TCS \
                        | SGX_EMA_PAGE_TYPE_SS_FIRST \
                        | SGX_EMA_PAGE_TYPE_SS_REST \
                        | SGX_EMA_SYSTEM \
                        | SGX_EMA_RESERVE \
                        )

int mm_init_ema(void *addr, size_t size, int flags, int prot,
              sgx_enclave_fault_handler_t handler,
              void *handler_private)
{
    if (!sgx_mm_is_within_enclave(addr, size))
        return EACCES;
    if( ((unsigned int)flags) & (~LEGAL_INIT_FLAGS))
        return EINVAL;
    if(prot &(~SGX_EMA_PROT_MASK))
        return EINVAL;
    ema_t* next_ema = NULL;

    if(!find_free_region_at(&g_rts_ema_root, (size_t)addr, size, &next_ema))
        return EINVAL;

    ema_t* ema = ema_new((size_t)addr, size,  flags & SGX_EMA_ALLOC_FLAGS_MASK,
                            (uint64_t)prot | (SGX_EMA_PAGE_TYPE_MASK & flags),
                            handler, handler_private, next_ema);
    if(!ema) return ENOMEM;
    if (flags & SGX_EMA_RESERVE)
        return 0;
    return ema_set_eaccept_full(ema);
}

extern int mm_alloc_internal(void *addr, size_t size, uint32_t flags,
                 sgx_enclave_fault_handler_t handler,
                 void *private, void** out_addr, ema_root_t* root);

int mm_alloc(void *addr, size_t size, uint32_t flags,
                 sgx_enclave_fault_handler_t handler,
                 void *private, void** out_addr)
{
    return mm_alloc_internal(addr, size, flags, handler, private,
                            out_addr, &g_rts_ema_root);
}

extern int mm_commit_internal(void *addr, size_t size, ema_root_t* root);

int mm_commit(void *addr, size_t size)
{
   return mm_commit_internal(addr, size, &g_rts_ema_root);
}

extern int mm_uncommit_internal(void *addr, size_t size, ema_root_t* root);

int mm_uncommit(void *addr, size_t size)
{
    return mm_uncommit_internal(addr, size,  &g_rts_ema_root);
}

extern int mm_dealloc_internal(void *addr, size_t size, ema_root_t* root);

int mm_dealloc(void *addr, size_t size)
{
    return mm_dealloc_internal(addr, size, &g_rts_ema_root);
}

extern int mm_commit_data_internal(void *addr, size_t size,
                            uint8_t *data, int prot, ema_root_t* root);

int mm_commit_data(void *addr, size_t size, uint8_t *data, int prot)
{
    return mm_commit_data_internal(addr, size, data, prot, &g_rts_ema_root);
}

extern int mm_modify_type_internal(void *addr, size_t size, int type, ema_root_t* root);

int mm_modify_type(void *addr, size_t size, int type)
{
    return mm_modify_type_internal(addr,  size, type, &g_rts_ema_root);
}

extern int mm_modify_permissions_internal(void *addr, size_t size,
                                            int prot, ema_root_t* root);

int mm_modify_permissions(void *addr, size_t size, int prot)
{
    return mm_modify_permissions_internal(addr, size, prot, &g_rts_ema_root);
}

