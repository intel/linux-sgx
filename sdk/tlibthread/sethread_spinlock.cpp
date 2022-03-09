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


#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "sethread_internal.h"
#include "sethread_spinlock.h"
int sgx_thread_spin_init(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    mutex->m_refcount = 0;
    mutex->m_owner = SGX_THREAD_T_NULL;
    mutex->m_lock = SGX_SPINLOCK_INITIALIZER;

    return 0;
}

int sgx_thread_spin_destroy(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    SPIN_LOCK(&mutex->m_lock);
    if (mutex->m_owner != SGX_THREAD_T_NULL) {
        SPIN_UNLOCK(&mutex->m_lock);
        return EBUSY;
    }

    mutex->m_refcount = 0;
    SPIN_UNLOCK(&mutex->m_lock);

    return 0;
}

int sgx_thread_spin_trylock(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    sgx_thread_t self = (sgx_thread_t)get_thread_data();

    SPIN_LOCK(&mutex->m_lock);

    if (mutex->m_owner == self) {
        mutex->m_refcount++;
        SPIN_UNLOCK(&mutex->m_lock);
        return 0;
    }

    if (mutex->m_owner == SGX_THREAD_T_NULL) {
        mutex->m_owner = self;
        mutex->m_refcount++;
        SPIN_UNLOCK(&mutex->m_lock);
        return 0;
    }

    SPIN_UNLOCK(&mutex->m_lock);
    return EBUSY;
}

int sgx_thread_spin_unlock(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    sgx_thread_t self = (sgx_thread_t)get_thread_data();

    SPIN_LOCK(&mutex->m_lock);
    /* if the mutux is not locked by anyone */
    if(mutex->m_owner == SGX_THREAD_T_NULL) {
        SPIN_UNLOCK(&mutex->m_lock);
        return EPERM;
    }

    /* if the mutex is locked by another thread */
    if (mutex->m_owner != self) {
        SPIN_UNLOCK(&mutex->m_lock);
        return EPERM;
    }

    /* the mutex is locked by current thread */
    if (--mutex->m_refcount == 0) {
        mutex->m_owner = SGX_THREAD_T_NULL;
    }

    SPIN_UNLOCK(&mutex->m_lock);
    return 0;
}
