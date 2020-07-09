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

int pthread_mutex_init(pthread_mutex_t *mutexp, const pthread_mutexattr_t *attr)
{
    pthread_mutex_t mutex;
    UNUSED(attr);
    mutex = (pthread_mutex_t)calloc(1, sizeof(*mutex));
    if (mutex == NULL)
        return (ENOMEM);
    sgx_thread_mutex_init(mutex, NULL);
    *mutexp = mutex;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutexp)
{
    if (mutexp == NULL)
        return (EINVAL);

    sgx_thread_mutex_t *mutex = *mutexp;
    if(mutex) {
        int ret = sgx_thread_mutex_destroy(mutex);
        if(ret != 0)
            return ret;

        free((void *)(mutex));
        *mutexp = NULL;
    }
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutexp)
{
    if (mutexp == NULL)
        return (EINVAL);
    int error=0;

    /*
      * If the mutex is statically initialized, perform the dynamic
      * initialization. Note: _thread_mutex_lock() in libc requires
      * pthread_mutex_lock() to perform the mutex init when *mutexp
      * is NULL.
    */
    if (*mutexp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*mutexp == NULL)
            error = pthread_mutex_init(mutexp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_mutex_lock(*mutexp);
}

int pthread_mutex_trylock(pthread_mutex_t *mutexp)
{
    if (mutexp == NULL)
        return (EINVAL);
    int error=0;

    /*
      * If the mutex is statically initialized, perform the dynamic
      * initialization. Note: _thread_mutex_lock() in libc requires
      * pthread_mutex_lock() to perform the mutex init when *mutexp
      * is NULL.
    */
    if (*mutexp == NULL) {
        sgx_spin_lock(&static_init_lock);
        if (*mutexp == NULL)
            error = pthread_mutex_init(mutexp, NULL);
        sgx_spin_unlock(&static_init_lock);
        if (error != 0)
            return (EINVAL);
    }

    return sgx_thread_mutex_trylock(*mutexp);
}

int pthread_mutex_unlock(pthread_mutex_t *mutexp)
{
    if (mutexp == NULL)
        return (EINVAL);

    if (*mutexp == NULL)
        abort();

    return sgx_thread_mutex_unlock(*mutexp);
}

