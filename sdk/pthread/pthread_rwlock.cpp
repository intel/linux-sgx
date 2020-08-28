/*	$OpenBSD: rthread_cond.c,v 1.5 2019/01/29 17:40:26 mpi Exp $ */
/*
 * Copyright (c) 2017 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2012 Philip Guenther <guenther@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "sgx_trts.h"
#include "sgx_spinlock.h"
#include "pthread_imp.h"
#include "util.h"

static volatile uint32_t static_init_lock = SGX_SPINLOCK_INITIALIZER;

int pthread_rwlock_init(pthread_rwlock_t *rwlockp, const pthread_rwlockattr_t *attr)
{
    pthread_rwlock_t rwlock;
    UNUSED(attr);
    rwlock = (pthread_rwlock_t)calloc(1, sizeof(*rwlock));
    if (rwlock == NULL)
        return (ENOMEM);
    sgx_thread_rwlock_init(rwlock, NULL);
    *rwlockp = rwlock;
    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);

    sgx_thread_rwlock_t *rwlock = *rwlockp;
    if(rwlock) {
        int ret = sgx_thread_rwlock_destroy(rwlock);
        if(ret != 0)
            return ret;

        free((void *)(rwlock));
        *rwlockp = NULL;
    }
    return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);
    int error = 0;

    /*
      * If the rwlock is statically initialized, perform the dynamic
      * initialization.
    */
    if (*rwlockp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*rwlockp == NULL)
            error = pthread_rwlock_init(rwlockp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_rwlock_rdlock(*rwlockp);
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);
    int error=0;

    /*
      * If the rwlock is statically initialized, perform the dynamic
      * initialization. 
    */
    if (*rwlockp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*rwlockp == NULL)
            error = pthread_rwlock_init(rwlockp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_rwlock_tryrdlock(*rwlockp);
}


int pthread_rwlock_wrlock(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);
    int error = 0;

    /*
      * If the rwlock is statically initialized, perform the dynamic
      * initialization.
    */
    if (*rwlockp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*rwlockp == NULL)
            error = pthread_rwlock_init(rwlockp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_rwlock_wrlock(*rwlockp);
}


int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);
    int error = 0;

    /*
      * If the rwlock is statically initialized, perform the dynamic
      * initialization.
    */
    if (*rwlockp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*rwlockp == NULL)
            error = pthread_rwlock_init(rwlockp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_rwlock_trywrlock(*rwlockp);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlockp)
{
    if (rwlockp == NULL)
        return (EINVAL);

    if (*rwlockp == NULL)
        abort();

    return sgx_thread_rwlock_unlock(*rwlockp);
}

