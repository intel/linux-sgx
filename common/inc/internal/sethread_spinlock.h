
/*
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
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

#ifndef _SE_THREAD_SPINLOCK_H_
#define _SE_THREAD_SPINLOCK_H_
#include "sgx_thread.h"
/** a recursive spin lock */
typedef struct _sgx_thread_spinlock_t
{
    size_t              m_refcount; /* number of recursive calls */
    volatile uint32_t   m_lock;   /* use sgx_spinlock_t */
    sgx_thread_t        m_owner;
} sgx_thread_spinlock_t;

#define SGX_THREAD_RECURSIVE_SPINLOCK_INITIALIZER \
            {0, 0, SGX_THREAD_T_NULL}
#ifdef __cplusplus
extern "C" {
#endif

int sgx_thread_spin_init(sgx_thread_spinlock_t *mutex);
int sgx_thread_spin_destroy(sgx_thread_spinlock_t *mutex);

int sgx_thread_spin_trylock(sgx_thread_spinlock_t *mutex);
int sgx_thread_spin_unlock(sgx_thread_spinlock_t *mutex);
#ifdef __cplusplus
}
#endif

#endif
