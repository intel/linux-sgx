// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_SYSCALL_H_
#define _SYS_SYSCALL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/bits/syscall_x86_64.h>

long syscall(long number, ...);

#include <declarations.h>

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSCALL_H_ */
