
/**
 *
 * Copyright(c) 2011-2019 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code ("Material") are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and treaty
 * provisions. No part of the Material may be used, copied, reproduced, modified,
 * published, uploaded, posted, transmitted, distributed, or disclosed in any
 * way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel(R) in writing.
 *
 */

#ifndef _PTHREAD_H_
#define _PTHREAD_H_

#include <sgx_defs.h>

/*
 * Flags for once initialization.
 */
#define PTHREAD_NEEDS_INIT  0
#define PTHREAD_DONE_INIT   1

/*
 * Static once initialization values. 
 */
#define PTHREAD_ONCE_INIT   { PTHREAD_NEEDS_INIT, PTHREAD_MUTEX_INITIALIZER }

/*
 * Static initialization values. 
 */
#define PTHREAD_MUTEX_INITIALIZER	NULL
#define PTHREAD_COND_INITIALIZER	NULL
#define PTHREAD_RWLOCK_INITIALIZER	NULL

/*
 * Primitive system data type definitions required by P1003.1c.
 *
 * Note that P1003.1c specifies that there are no defined comparison
 * or assignment operators for the types pthread_attr_t, pthread_cond_t,
 * pthread_condattr_t, pthread_mutex_t, pthread_mutexattr_t.
 */
typedef struct	_pthread			*pthread_t;
typedef struct	_pthread_attr		*pthread_attr_t;
typedef struct _sgx_thread_mutex_t	*pthread_mutex_t;
typedef struct	_sgx_thread_mutex_attr_t	*pthread_mutexattr_t;
typedef struct	_sgx_thread_cond_t		*pthread_cond_t;
typedef struct	_sgx_thread_cond_attr_t	*pthread_condattr_t;
typedef int				pthread_key_t;
//typedef struct	pthread_rwlock		*pthread_rwlock_t;
//typedef struct	pthread_rwlockattr	*pthread_rwlockattr_t;
//typedef struct	pthread_barrier		*pthread_barrier_t;
//typedef struct	pthread_barrierattr	*pthread_barrierattr_t;
//typedef struct	pthread_spinlock	*pthread_spinlock_t;

/*
 * Once definitions.
 */
typedef struct _pthread_once_t {
	int		state;
	pthread_mutex_t	mutex;
}pthread_once_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create & exit */
int SGXAPI pthread_create(pthread_t *, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *);
void SGXAPI pthread_exit(void *);
int SGXAPI pthread_join(pthread_t, void **);

/* Mutex */
int SGXAPI pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int SGXAPI pthread_mutex_destroy(pthread_mutex_t *);

int SGXAPI pthread_mutex_lock(pthread_mutex_t *);
int SGXAPI pthread_mutex_trylock(pthread_mutex_t *);
int SGXAPI pthread_mutex_unlock(pthread_mutex_t *);

/* Condition Variable */
int SGXAPI pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int SGXAPI pthread_cond_destroy(pthread_cond_t *);

int SGXAPI pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int SGXAPI pthread_cond_signal(pthread_cond_t *);
int SGXAPI pthread_cond_broadcast(pthread_cond_t *);

/* tls */
int SGXAPI pthread_key_create(pthread_key_t *, void (*destructor)(void*));
int SGXAPI pthread_key_delete(pthread_key_t);
void * SGXAPI pthread_getspecific(pthread_key_t);
int SGXAPI pthread_setspecific(pthread_key_t, const void *);

pthread_t SGXAPI pthread_self(void);
int SGXAPI pthread_equal(pthread_t, pthread_t);
int SGXAPI pthread_once(pthread_once_t*, void (*init_routine)(void));

#ifdef __cplusplus
}
#endif

#endif  //_PTHREAD_H_

