// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _DECLARATIONS_H_
#define _DECLARATIONS_H_

#include <sys/bits/syscall_x86_64.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_SYSCALL_NAME(index) sgx##index##_impl

#define SGX_SYSCALL_DISPATCH(index, ...) \
    case index:                    \
        return SGX_SYSCALL_NAME(_##index)(__VA_ARGS__)

#define SGX_SYSCALL_ARGS0 void
#define SGX_SYSCALL_ARGS1 long arg1
#define SGX_SYSCALL_ARGS2 SGX_SYSCALL_ARGS1, long arg2
#define SGX_SYSCALL_ARGS3 SGX_SYSCALL_ARGS2, long arg3
#define SGX_SYSCALL_ARGS4 SGX_SYSCALL_ARGS3, long arg4
#define SGX_SYSCALL_ARGS5 SGX_SYSCALL_ARGS4, long arg5
#define SGX_SYSCALL_ARGS6 SGX_SYSCALL_ARGS5, long arg6
#define SGX_SYSCALL_ARGS7 SGX_SYSCALL_ARGS6, long arg7

#define SGX_DECLARE_SYSCALL0(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS0)
#define SGX_DECLARE_SYSCALL1(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS1)
#define SGX_DECLARE_SYSCALL2(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS2)
#define SGX_DECLARE_SYSCALL3(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS3)
#define SGX_DECLARE_SYSCALL4(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS4)
#define SGX_DECLARE_SYSCALL5(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS5)
#define SGX_DECLARE_SYSCALL6(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS6)
#define SGX_DECLARE_SYSCALL7(index)         \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS7)

#define SGX_DECLARE_SYSCALL1_M(index)       \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS1, ...)
#define SGX_DECLARE_SYSCALL2_M(index)       \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS2, ...)
#define SGX_DECLARE_SYSCALL3_M(index)       \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS3, ...)
#define SGX_DECLARE_SYSCALL4_M(index)       \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS4, ...)
#define SGX_DECLARE_SYSCALL5_M(index)       \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS5, ...)

#define SGX_DEFINE_SYSCALL0(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS0)
#define SGX_DEFINE_SYSCALL1(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS1)
#define SGX_DEFINE_SYSCALL2(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS2)
#define SGX_DEFINE_SYSCALL3(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS3)
#define SGX_DEFINE_SYSCALL4(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS4)
#define SGX_DEFINE_SYSCALL5(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS5)
#define SGX_DEFINE_SYSCALL6(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS6)
#define SGX_DEFINE_SYSCALL7(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS7)

#define SGX_DEFINE_SYSCALL1_M(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS1, ...)
#define SGX_DEFINE_SYSCALL2_M(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS2, ...)
#define SGX_DEFINE_SYSCALL3_M(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS3, ...)
#define SGX_DEFINE_SYSCALL4_M(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS4, ...)
#define SGX_DEFINE_SYSCALL5_M(index) \
    long SGX_SYSCALL_NAME(_##index)(SGX_SYSCALL_ARGS5, ...)

/* The following syscalls are aliased to other syscalls */
#ifndef SYS_getdents
#define SYS_getdents SYS_getdents64
#endif

#ifndef SYS_pread
#define SYS_pread SYS_pread64
#endif

#ifndef SYS_pwrite
#define SYS_pwrite SYS_pwrite64
#endif

#ifndef SYS_fstatat
#if defined(SYS_newfstatat)
#define SYS_fstatat SYS_newfstatat
#elif defined(SYS_fstatat64)
#define SYS_fstatat SYS_fstatat64
#endif
#endif

/** List of syscalls that are supported within enclaves.
 ** In alphabetical order.
 ** Certain syscalls are available only in some platforms.
 **/

SGX_DECLARE_SYSCALL3_M(SYS_accept);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_access);
#endif
SGX_DECLARE_SYSCALL3_M(SYS_bind);
SGX_DECLARE_SYSCALL1(SYS_chdir);
SGX_DECLARE_SYSCALL2(SYS_clock_gettime);
SGX_DECLARE_SYSCALL4_M(SYS_clock_nanosleep);
SGX_DECLARE_SYSCALL1_M(SYS_close);
SGX_DECLARE_SYSCALL3_M(SYS_connect);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_creat);
#endif
SGX_DECLARE_SYSCALL1(SYS_dup);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_dup2);
#endif
SGX_DECLARE_SYSCALL3(SYS_dup3);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL1(SYS_epoll_create);
#endif
SGX_DECLARE_SYSCALL1(SYS_epoll_create1);
SGX_DECLARE_SYSCALL4(SYS_epoll_ctl);
SGX_DECLARE_SYSCALL5_M(SYS_epoll_pwait);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL4_M(SYS_epoll_wait);
#endif
SGX_DECLARE_SYSCALL1(SYS_exit);
SGX_DECLARE_SYSCALL4(SYS_faccessat);
SGX_DECLARE_SYSCALL2_M(SYS_fcntl);
SGX_DECLARE_SYSCALL1_M(SYS_fdatasync);
SGX_DECLARE_SYSCALL2(SYS_flock);
SGX_DECLARE_SYSCALL2(SYS_fstat);
SGX_DECLARE_SYSCALL4(SYS_fstatat);
SGX_DECLARE_SYSCALL2(SYS_fchmod);
SGX_DECLARE_SYSCALL3(SYS_fchown);
SGX_DECLARE_SYSCALL1_M(SYS_fsync);
SGX_DECLARE_SYSCALL2(SYS_ftruncate);
SGX_DECLARE_SYSCALL2(SYS_getcwd);
SGX_DECLARE_SYSCALL3(SYS_getdents);
SGX_DECLARE_SYSCALL3(SYS_getdents64);
SGX_DECLARE_SYSCALL0(SYS_getegid);
SGX_DECLARE_SYSCALL0(SYS_geteuid);
SGX_DECLARE_SYSCALL0(SYS_getgid);
SGX_DECLARE_SYSCALL2(SYS_getgroups);
SGX_DECLARE_SYSCALL3_M(SYS_getpeername);
SGX_DECLARE_SYSCALL1(SYS_getpgid);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL0(SYS_getpgrp);
#endif
SGX_DECLARE_SYSCALL0(SYS_getpid);
SGX_DECLARE_SYSCALL0(SYS_getppid);
SGX_DECLARE_SYSCALL3_M(SYS_getrandom);
SGX_DECLARE_SYSCALL3_M(SYS_getsockname);
SGX_DECLARE_SYSCALL5_M(SYS_getsockopt);
SGX_DECLARE_SYSCALL2(SYS_gettimeofday);
SGX_DECLARE_SYSCALL0(SYS_getuid);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_link);
#endif
SGX_DECLARE_SYSCALL5(SYS_linkat);
SGX_DECLARE_SYSCALL2_M(SYS_listen);
SGX_DECLARE_SYSCALL3(SYS_lseek);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_lstat);
#endif
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_mkdir);
#endif
SGX_DECLARE_SYSCALL3(SYS_mkdirat);
SGX_DECLARE_SYSCALL6(SYS_mmap);
SGX_DECLARE_SYSCALL2(SYS_munmap);
SGX_DECLARE_SYSCALL5(SYS_mount);
SGX_DECLARE_SYSCALL2_M(SYS_nanosleep);
SGX_DECLARE_SYSCALL4(SYS_newfstatat);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2_M(SYS_open);
#endif
SGX_DECLARE_SYSCALL2_M(SYS_openat);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL3_M(SYS_poll);
#endif
SGX_DECLARE_SYSCALL4_M(SYS_ppoll);
SGX_DECLARE_SYSCALL4_M(SYS_pread);
SGX_DECLARE_SYSCALL4(SYS_pread64);
SGX_DECLARE_SYSCALL5_M(SYS_pselect6);
SGX_DECLARE_SYSCALL4_M(SYS_pwrite);
SGX_DECLARE_SYSCALL4(SYS_pwrite64);
SGX_DECLARE_SYSCALL3_M(SYS_read);
SGX_DECLARE_SYSCALL3_M(SYS_readv);
SGX_DECLARE_SYSCALL6(SYS_recvfrom);
SGX_DECLARE_SYSCALL3_M(SYS_recvmsg);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_rename);
#endif
SGX_DECLARE_SYSCALL4_M(SYS_renameat);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL1(SYS_rmdir);
#endif
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL5_M(SYS_select);
#endif
SGX_DECLARE_SYSCALL6(SYS_sendto);
SGX_DECLARE_SYSCALL3_M(SYS_sendmsg);
SGX_DECLARE_SYSCALL5_M(SYS_setsockopt);
SGX_DECLARE_SYSCALL2_M(SYS_shutdown);
SGX_DECLARE_SYSCALL3_M(SYS_socket);
SGX_DECLARE_SYSCALL4_M(SYS_socketpair);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL2(SYS_stat);
#endif
SGX_DECLARE_SYSCALL2(SYS_truncate);
SGX_DECLARE_SYSCALL3_M(SYS_write);
SGX_DECLARE_SYSCALL3_M(SYS_writev);
SGX_DECLARE_SYSCALL1(SYS_uname);
#if __x86_64__ || _M_X64
SGX_DECLARE_SYSCALL1(SYS_unlink);
#endif
SGX_DECLARE_SYSCALL3(SYS_unlinkat);
SGX_DECLARE_SYSCALL2(SYS_umount2);


#ifdef __cplusplus
}
#endif

#endif /* _DECLARATIONS_H_ */
