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


#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "sethread_internal.h"
#include "sethread_spinlock.h"

//copied from sgx_spinlock

static inline void _mm_pause(void)  /* definition requires -ffreestanding */
{
    __asm __volatile(
        "pause"
    );
}

static inline int _InterlockedExchange(int volatile * dst, int val)
{
    int res;

    __asm __volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : "=m" (res)
        : "m" (*dst),
        "r" (val)
        : "memory"
    );

    return (res);

}

#define MIN_BACKOFF 2
#define MAX_BACKOFF 1024
static uint32_t spin_lock(sgx_spinlock_t *lock)
{
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
        int b = MIN_BACKOFF;
        do
        {    /* tell cpu we are spinning */
            for (int i=0; i < b; i++)
                _mm_pause();
            b = b << 1;
            if (b > MAX_BACKOFF) b = MAX_BACKOFF;

        } while (*lock);
    }

    return (0);
}


static uint32_t spin_unlock(sgx_spinlock_t *lock)
{
    *lock = 0;

    return (0);
}


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

    spin_lock(&mutex->m_lock);
    if (mutex->m_owner != SGX_THREAD_T_NULL) {
        spin_unlock(&mutex->m_lock);
        return EBUSY;
    }

    mutex->m_refcount = 0;
    spin_unlock(&mutex->m_lock);

    return 0;
}

int sgx_thread_spin_trylock(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    sgx_thread_t self = (sgx_thread_t)get_thread_data();

    spin_lock(&mutex->m_lock);

    if (mutex->m_owner == self) {
        mutex->m_refcount++;
        spin_unlock(&mutex->m_lock);
        return 0;
    }

    if (mutex->m_owner == SGX_THREAD_T_NULL) {
        mutex->m_owner = self;
        mutex->m_refcount++;
        spin_unlock(&mutex->m_lock);
        return 0;
    }

    spin_unlock(&mutex->m_lock);
    return EBUSY;
}

int sgx_thread_spin_unlock(sgx_thread_spinlock_t *mutex)
{
    CHECK_PARAMETER(mutex);

    sgx_thread_t self = (sgx_thread_t)get_thread_data();

    spin_lock(&mutex->m_lock);
    /* if the mutux is not locked by anyone */
    if(mutex->m_owner == SGX_THREAD_T_NULL) {
        spin_unlock(&mutex->m_lock);
        return EPERM;
    }

    /* if the mutex is locked by another thread */
    if (mutex->m_owner != self) {
        spin_unlock(&mutex->m_lock);
        return EPERM;
    }

    /* the mutex is locked by current thread */
    if (--mutex->m_refcount == 0) {
        mutex->m_owner = SGX_THREAD_T_NULL;
    }

    spin_unlock(&mutex->m_lock);
    return 0;
}
