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
#include "sgx_thread.h"
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include "sgx_trts.h" // for sgx_ocalloc, sgx_is_outside_enclave
#include "arch.h"
#include "sgx_edger8r.h" // for sgx_ocall etc.
#include "internal/rts.h"
#include "sgx_mm_rt_abstraction.h"
#define OCALLOC(val, type, len) do {    \
    void* __tmp = sgx_ocalloc(len); \
    if (__tmp == NULL) {    \
        sgx_ocfree();   \
        return SGX_ERROR_UNEXPECTED;\
    }           \
    (val) = (type)__tmp;    \
} while (0)

typedef struct ms_emm_alloc_ocall_t {
	int retval;
    size_t addr;
    size_t size;
    int flags;
} ms_emm_alloc_ocall_t;

int SGXAPI sgx_mm_alloc_ocall(size_t addr, size_t size, int flags)
{
#ifdef SE_SIM
    (void)addr;
    (void)size;
    (void)flags;
    return 0;
#else
    int status = SGX_SUCCESS;
    int ret = EFAULT;
    ms_emm_alloc_ocall_t* ms;
    OCALLOC(ms, ms_emm_alloc_ocall_t*, sizeof(*ms));

    ms->addr = (size_t)addr;
    ms->size = size;
    ms->flags = flags;

    status = sgx_ocall((unsigned int)EDMM_ALLOC, ms);
	if(status == SGX_SUCCESS)
		ret = ms->retval;

    sgx_ocfree();
    return ret;
#endif
}

typedef struct ms_emm_modify_ocall_t {
    int retval;
    size_t addr;
    size_t size;
    int flags_from;
    int flags_to;
} ms_emm_modify_ocall_t;

int SGXAPI sgx_mm_modify_ocall(size_t addr, size_t size, int flags_from, int flags_to)
{
#ifdef SE_SIM
    (void)addr;
    (void)size;
    (void)flags_from;
    (void)flags_to;
    return 0;
#else
    int status = SGX_SUCCESS;
    int ret = EFAULT;
    ms_emm_modify_ocall_t* ms;
    OCALLOC(ms, ms_emm_modify_ocall_t*, sizeof(*ms));

    ms->addr = (size_t)addr;
    ms->size = size;
    ms->flags_from = flags_from;
    ms->flags_to = flags_to;
    status = sgx_ocall((unsigned int)EDMM_MODIFY, ms);
	if(status == SGX_SUCCESS)
		ret = ms->retval;

    sgx_ocfree();
    return ret;
#endif
}

extern sgx_mm_pfhandler_t g_mm_pfhandler;

bool sgx_mm_register_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    if (g_mm_pfhandler != NULL)
        return false;
    else
    {
        g_mm_pfhandler = pfhandler;
        return true;
    }
}

bool sgx_mm_unregister_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    if (g_mm_pfhandler != pfhandler)
        return false;
    g_mm_pfhandler = NULL;
    return true;
}

typedef struct _sgx_mm_mutex {
    sgx_thread_mutex_t m;
}sgx_mm_mutex;

static int sgx_mm_mutex_init(sgx_mm_mutex* mutex)
{
    //Recursive locks needed for cases when exception happens in
    // mm_x_internal functions while lock being held. For example,
    // stack expansion/heap expansion during those calls as we use
    // regular enclave stack and heap for internal processing and
    // book keeping.
    mutex->m = (sgx_thread_mutex_t)SGX_THREAD_RECURSIVE_MUTEX_INITIALIZER;
    return 0;
}

sgx_mm_mutex *sgx_mm_mutex_create()
{
    sgx_mm_mutex *mutex = (sgx_mm_mutex *)malloc(sizeof(sgx_mm_mutex));
    if (!mutex) {
        return NULL;
    }
    sgx_mm_mutex_init(mutex);
    return mutex;
}

int sgx_mm_mutex_lock(sgx_mm_mutex* mutex)
{
    assert(mutex != NULL);
    //!FIXME
    //Intel SDK does not have
    // WAKE/WAIT event ocalls as builtins.  And TCS
    // pages are addred in a  "utility" thread which
    // does not have those in ocall table for the ecall.
    // Therefore we must not make ocalls for synchronization.
    // OE has builtin ocalls for wait/wake so no trylock needed
    while ( sgx_thread_mutex_trylock(&mutex->m));
    return 0;
}

int sgx_mm_mutex_unlock(sgx_mm_mutex* mutex)
{
    assert(mutex != NULL);
    return sgx_thread_mutex_unlock(&mutex->m);
}

int sgx_mm_mutex_destroy(sgx_mm_mutex* mutex)
{
    assert(mutex != NULL);
    int ret = sgx_thread_mutex_destroy(&mutex->m);
    free(mutex);
    return ret;
}

bool sgx_mm_is_within_enclave(const void* addr, size_t size)
{
    return sgx_is_within_enclave(addr, size);
}
