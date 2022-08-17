// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SIGSET_H_
#define _SIGSET_H_

#define __SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))

typedef struct
{
    unsigned long int __val[__SIGSET_NWORDS];
} sigset_t;

#endif /* _SIGSET_H_ */
