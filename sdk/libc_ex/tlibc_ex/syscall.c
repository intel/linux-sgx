// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "errno.h"
#include "se_cdefs.h"
#include "stdarg.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include "internal/sgx_read_rand.h"

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_accept)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    socklen_t* addrlen = (socklen_t*)arg3;
    return accept(sockfd, addr, addrlen);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_access)
{
    errno = 0;
    const char* pathname = (const char*)arg1;
    int mode = (int)arg2;

    return access(pathname, mode);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_bind)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    socklen_t addrlen = (socklen_t)arg3;
    return bind(sockfd, addr, addrlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_chdir)
{
    errno = 0;
    char* path = (char*)arg1;

    return chdir(path);
}

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_clock_nanosleep)
{
    errno = 0;
    clockid_t clockid = (clockid_t)arg1;
    int flag = (int)arg2;
    struct timespec* req = (struct timespec*)arg3;
    struct timespec* rem = (struct timespec*)arg4;
    return (long)clock_nanosleep(clockid, flag, req, rem);
}

SGX_WEAK SGX_DEFINE_SYSCALL1_M(SYS_close)
{
    errno = 0;
    int fd = (int)arg1;

    return close(fd);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_connect)
{
    errno = 0;
    int sd = (int)arg1;
    const struct sockaddr* addr = (const struct sockaddr*)arg2;
    socklen_t addrlen = (socklen_t)arg3;
    return connect(sd, addr, addrlen);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_creat)
{
    errno = 0;
    long ret = -1;
    const char* pathname = (const char*)arg1;
    mode_t mode = (mode_t)arg2;
    int flags = (O_CREAT | O_WRONLY | O_TRUNC);

    ret = open(pathname, flags, mode);

    if (errno == ENOENT)
    {
        /* If the file was not found, give the caller (libc) a chance
         * to handle this syscall.
         */
        errno = ENOSYS;
    }

    return ret;
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_dup)
{
    errno = 0;
    int fd = (int)arg1;

    return dup(fd);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_dup2)
{
    errno = 0;
    int oldfd = (int)arg1;
    int newfd = (int)arg2;

    return dup2(oldfd, newfd);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_dup3)
{
    errno = 0;
    long ret = -1;
    int oldfd = (int)arg1;
    int newfd = (int)arg2;
    int flags = (int)arg3;

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = dup2(oldfd, newfd);
done:
    return ret;
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_epoll_create)
{
    errno = 0;
    int size = (int)arg1;
    return epoll_create(size);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_epoll_create1)
{
    errno = 0;
    int flags = (int)arg1;
    return epoll_create1(flags);
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_epoll_ctl)
{
    errno = 0;
    int epfd = (int)arg1;
    int op = (int)arg2;
    int fd = (int)arg3;
    struct epoll_event* event = (struct epoll_event*)arg4;
    return epoll_ctl(epfd, op, fd, event);
}

SGX_WEAK SGX_DEFINE_SYSCALL5_M(SYS_epoll_pwait)
{
    errno = 0;
    int epfd = (int)arg1;
    struct epoll_event* events = (struct epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    const sigset_t* sigmask = (const sigset_t*)arg5;
    return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_epoll_wait)
{
    errno = 0;
    int epfd = (int)arg1;
    struct epoll_event* events = (struct epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    return epoll_wait(epfd, events, maxevents, timeout);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_exit)
{
    errno = 0;
    int status = (int)arg1;
    exit(status);

    // Control does not reach here.
    asm volatile("ud2");
    return -1;
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_faccessat)
{
    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int mode = (int)arg3;
    int flags = (int)arg4;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = access(pathname, mode);
done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_fcntl)
{
    va_list ap;
    va_start(ap, arg2);
    long arg3 = va_arg(ap, long);
    va_end(ap);

    errno = 0;
    int fd = (int)arg1;
    int cmd = (int)arg2;
    uint64_t arg = (uint64_t)arg3;

    return fcntl(fd, cmd, arg);
}

SGX_WEAK SGX_DEFINE_SYSCALL1_M(SYS_fdatasync)
{
    errno = 0;
    const int fd = (int)arg1;

    return fdatasync(fd);
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_flock)
{
    errno = 0;
    int fd = (int)arg1;
    int operation = (int)arg2;

    return flock(fd, operation);
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_fstat)
{
    errno = 0;
    const int fd = (int)arg1;
    struct stat* const buf = (struct stat*)arg2;
    return fstat(fd, buf);
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_fstatat)
{
    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    struct stat* fstat = (struct stat*)arg3;
    int flags = (int)arg4;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = stat(pathname, fstat);
done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL1_M(SYS_fsync)
{
    errno = 0;
    const int fd = (int)arg1;

    return fsync(fd);
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_ftruncate)
{
    errno = 0;
    const int fd = (int)arg1;
    const ssize_t length = (ssize_t)arg2;
    return ftruncate(fd, length);
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_getcwd)
{
    errno = 0;
    long ret = -1;
    char* buf = (char*)arg1;
    size_t size = (size_t)arg2;

    if (!getcwd(buf, size))
    {
        ret = -1;
    }
    else
    {
        ret = (long)strlen(buf) + 1;
    }

    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_getdents)
{
    errno = 0;
    unsigned int fd = (unsigned int)arg1;
    struct dirent* ent = (struct dirent*)arg2;
    unsigned int count = (unsigned int)arg3;
    return getdents64(fd, ent, count);
}

SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_getdents64)
{
    errno = 0;
    unsigned int fd = (unsigned int)arg1;
    struct dirent* ent = (struct dirent*)arg2;
    unsigned int count = (unsigned int)arg3;
    return getdents64(fd, ent, count);
}

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getegid)
{
    errno = 0;
    return (long)getegid();
}

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_geteuid)
{
    errno = 0;
    return (long)geteuid();
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_getgroups)
{
    errno = 0;
    int size = (int)arg1;
    gid_t* list = (gid_t*)arg2;
    return (long)getgroups(size, list);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_getpeername)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    socklen_t* addrlen = (socklen_t*)arg3;
    return getpeername(sockfd, (struct sockaddr*)addr, addrlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_getpgid)
{
    errno = 0;
    int pid = (int)arg1;
    return (long)getpgid(pid);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getpgrp)
{
    errno = 0;
    return (long)getpgrp();
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getpid)
{
    errno = 0;
    return (long)getpid();
}

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getgid)
{
    errno = 0;
    return (long)getgid();
}

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getppid)
{
    errno = 0;
    return (long)getppid();
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_getrandom)
{
    errno = 0;
    long ret = -1;
    void* buf = (void*)arg1;
    size_t buflen = (size_t)arg2;
    unsigned int flags = (unsigned int)arg3;

    /* Flags (e.g., GRND_RANDOM and GRND_NONBLOCK) are not supported. */
    if (!buf || !buflen || flags)
    {
        errno = EINVAL;
        goto done;
    }

    if (sgx_read_rand((uint8_t*)buf, buflen) != SGX_SUCCESS)
    {
        errno = EAGAIN;
        goto done;
    }

    ret = (long)buflen;

done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_getsockname)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    socklen_t* addrlen = (socklen_t*)arg3;
    return getsockname(sockfd, (struct sockaddr*)addr, addrlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL5_M(SYS_getsockopt)
{
    errno = 0;
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    socklen_t* optlen = (socklen_t*)arg5;
    return getsockopt(sockfd, level, optname, optval, optlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL0(SYS_getuid)
{
    errno = 0;
    return (long)getuid();
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_link)
{
    errno = 0;
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;
    return link(oldpath, newpath);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL5(SYS_linkat)
{
    errno = 0;
    long ret = -1;
    int olddirfd = (int)arg1;
    const char* oldpath = (const char*)arg2;
    int newdirfd = (int)arg3;
    const char* newpath = (const char*)arg4;
    int flags = (int)arg5;

    if (olddirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (newdirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = link(oldpath, newpath);
done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_listen)
{
    errno = 0;
    int sockfd = (int)arg1;
    int backlog = (int)arg2;
    return listen(sockfd, backlog);
}

SGX_WEAK SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_lseek)
{
    errno = 0;
    int fd = (int)arg1;
    ssize_t off = (ssize_t)arg2;
    int whence = (int)arg3;
    return lseek(fd, off, whence);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_lstat)
{
    errno = 0;
    const char *pathname = (const char*)arg1;
    struct stat *statbuf = (struct stat*)arg2;
    return lstat(pathname, statbuf);
}
#endif

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_mkdir)
{
    errno = 0;
    const char* pathname = (const char*)arg1;
    uint32_t mode = (uint32_t)arg2;

    return mkdir(pathname, mode);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_mkdirat)
{
    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    uint32_t mode = (uint32_t)arg3;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    ret = mkdir(pathname, mode);
done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL5(SYS_mount)
{
    errno = 0;
    const char* source = (const char*)arg1;
    const char* target = (const char*)arg2;
    const char* fstype = (const char*)arg3;
    unsigned long flags = (unsigned long)arg4;
    void* data = (void*)arg5;

    return mount(source, target, fstype, flags, data);
}

SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_nanosleep)
{
    errno = 0;
    struct timespec* req = (struct timespec*)arg1;
    struct timespec* rem = (struct timespec*)arg2;
    return (long)nanosleep(req, rem);
}
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_fchmod)
{
    errno = 0;
    int fd = (int)arg1;
    mode_t mode = (mode_t)arg2;
    return (int)fchmod(fd, mode);
}
SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_fchown)
{
    errno = 0;
    int fd = (int)arg1;
    uid_t uid = (uid_t)arg2;
    gid_t gid = (gid_t)arg3;
    return (int)fchown(fd, uid, gid);
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_newfstatat)
{
    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    struct stat* buf = (struct stat*)arg3;
    int flags = (int)arg4;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = stat(pathname, buf);
done:
    return ret;
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_open)
{
    va_list ap;
    va_start(ap, arg2);
    long arg3 = va_arg(ap, long);
    va_end(ap);

    errno = 0;
    long ret = -1;

    const char* pathname = (const char*)arg1;
    int flags = (int)arg2;
    uint32_t mode = (uint32_t)arg3;

    ret = open(pathname, flags, mode);

    if (ret < 0 && errno == ENOENT)
        goto done;

    goto done;
done:
    return ret;
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_openat)
{
    va_list ap;
    va_start(ap, arg2);
    long arg3 = va_arg(ap, long);
    long arg4 = va_arg(ap, long);
    va_end(ap);

    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int flags = (int)arg3;
    uint32_t mode = (uint32_t)arg4;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    ret = open(pathname, flags, mode);

    if (ret < 0 && errno == ENOENT)
        goto done;

    goto done;
done:
    return ret;
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_poll)
{
    errno = 0;
    struct pollfd* fds = (struct pollfd*)arg1;
    nfds_t nfds = (nfds_t)arg2;
    int millis = (int)arg3;
    return poll(fds, nfds, millis);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_ppoll)
{
    errno = 0;
    struct pollfd* fds = (struct pollfd*)arg1;
    nfds_t nfds = (nfds_t)arg2;
    struct timespec* ts = (struct timespec*)arg3;
    sigset_t* sigmask = (sigset_t *)arg4;

    return ppoll(fds, nfds, ts, sigmask);
}

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_pread)
{
    errno = 0;
    const int fd = (int)arg1;
    void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const off_t offset = (off_t)arg4;

    return pread(fd, buf, count, offset);
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_pread64)
{
    errno = 0;
    const int fd = (int)arg1;
    void* const buffer = (void*)arg2;
    const size_t count = (size_t)arg3;
    const off_t offset = (off_t)arg4;

    return pread(fd, buffer, count, offset);
}

SGX_WEAK SGX_DEFINE_SYSCALL5_M(SYS_pselect6)
{
    errno = 0;
    int nfds = (int)arg1;
    fd_set* readfds = (fd_set*)arg2;
    fd_set* writefds = (fd_set*)arg3;
    fd_set* exceptfds = (fd_set*)arg4;
    struct timespec* ts = (struct timespec*)arg5;
    struct timeval buf;
    struct timeval* tv = NULL;

    if (ts)
    {
        tv = &buf;
        tv->tv_sec = ts->tv_sec;
        tv->tv_usec = ts->tv_nsec / 1000;
    }

    return select(nfds, readfds, writefds, exceptfds, tv);
}

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_pwrite)
{
    errno = 0;
    const int fd = (int)arg1;
    const void* const buffer = (void*)arg2;
    const size_t count = (size_t)arg3;
    const off_t offset = (off_t)arg4;

    return pwrite(fd, buffer, count, offset);
}

SGX_WEAK SGX_DEFINE_SYSCALL4(SYS_pwrite64)
{
    errno = 0;
    const int fd = (int)arg1;
    const void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const off_t offset = (off_t)arg4;

    return pwrite(fd, buf, count, offset);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_read)
{
    errno = 0;
    int fd = (int)arg1;
    void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return read(fd, buf, count);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_readv)
{
    errno = 0;
    int fd = (int)arg1;
    const struct iovec* iov = (const struct iovec*)arg2;
    int iovcnt = (int)arg3;

    return readv(fd, iov, iovcnt);
}

SGX_WEAK SGX_DEFINE_SYSCALL6(SYS_recvfrom)
{
    errno = 0;
    int sockfd = (int)arg1;
    void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    struct sockaddr* dest_add = (struct sockaddr*)arg5;
    socklen_t* addrlen = (socklen_t*)arg6;

    return recvfrom(sockfd, buf, len, flags, dest_add, addrlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_recvmsg)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return recvmsg(sockfd, (struct msghdr*)buf, flags);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_rename)
{
    errno = 0;
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;

    return rename(oldpath, newpath);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_renameat)
{
    va_list ap;
    va_start(ap, arg4);
    long arg5 = va_arg(ap, long);
    va_end(ap);

    errno = 0;
    long ret = -1;
    int olddirfd = (int)arg1;
    const char* oldpath = (const char*)arg2;
    int newdirfd = (int)arg3;
    const char* newpath = (const char*)arg4;
    int flags = (int)arg5;

    if (olddirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (newdirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = rename(oldpath, newpath);
done:
    return ret;
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_rmdir)
{
    errno = 0;
    const char* pathname = (const char*)arg1;
    return rmdir(pathname);
}
#endif

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL5_M(SYS_select)
{
    errno = 0;
    int nfds = (int)arg1;
    fd_set* readfds = (fd_set*)arg2;
    fd_set* writefds = (fd_set*)arg3;
    fd_set* efds = (fd_set*)arg4;
    struct timeval* timeout = (struct timeval*)arg5;
    return select(nfds, readfds, writefds, efds, timeout);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL6(SYS_sendto)
{
    errno = 0;
    int sockfd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    const struct sockaddr* dest_add = (const struct sockaddr*)arg5;
    socklen_t addrlen = (socklen_t)arg6;

    return sendto(sockfd, buf, len, flags, dest_add, addrlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_sendmsg)
{
    errno = 0;
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return sendmsg(sockfd, (struct msghdr*)buf, flags);
}

SGX_WEAK SGX_DEFINE_SYSCALL5_M(SYS_setsockopt)
{
    errno = 0;
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    socklen_t optlen = (socklen_t)arg5;
    return setsockopt(sockfd, level, optname, optval, optlen);
}

SGX_WEAK SGX_DEFINE_SYSCALL2_M(SYS_shutdown)
{
    errno = 0;
    int sockfd = (int)arg1;
    int how = (int)arg2;
    return shutdown(sockfd, how);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_socket)
{
    errno = 0;
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    return socket(domain, type, protocol);
}

SGX_WEAK SGX_DEFINE_SYSCALL4_M(SYS_socketpair)
{
    errno = 0;
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    int* sv = (int*)arg4;

    return socketpair(domain, type, protocol, sv);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_stat)
{
    errno = 0;
    const char* pathname = (const char*)arg1;
    struct stat* buf = (struct stat*)arg2;
    return stat(pathname, buf);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_truncate)
{
    errno = 0;
    const char* path = (const char*)arg1;
    ssize_t length = (ssize_t)arg2;

    return truncate(path, length);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_write)
{
    errno = 0;
    int fd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return write(fd, buf, count);
}

SGX_WEAK SGX_DEFINE_SYSCALL3_M(SYS_writev)
{
    errno = 0;
    int fd = (int)arg1;
    const struct iovec* iov = (const struct iovec*)arg2;
    int iovcnt = (int)arg3;

    return writev(fd, iov, iovcnt);
}

SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_uname)
{
    errno = 0;
    struct utsname* buf = (struct utsname*)arg1;
    return uname(buf);
}

#if __x86_64__ || _M_X64
SGX_WEAK SGX_DEFINE_SYSCALL1(SYS_unlink)
{
    errno = 0;
    const char* pathname = (const char*)arg1;

    return unlink(pathname);
}
#endif

SGX_WEAK SGX_DEFINE_SYSCALL3(SYS_unlinkat)
{
    errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int flags = (int)arg3;

    if (dirfd != AT_FDCWD)
    {
        errno = EBADF;
        goto done;
    }

    if (flags != AT_REMOVEDIR && flags != 0)
    {
        errno = EINVAL;
        goto done;
    }

    if (flags == AT_REMOVEDIR)
        ret = rmdir(pathname);
    else
        ret = unlink(pathname);
done:
    return ret;
}

SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_umount2)
{
    errno = 0;
    const char* target = (const char*)arg1;
    int flags = (int)arg2;

    (void)flags;

    return umount(target);
}

SGX_WEAK SGX_DEFINE_SYSCALL6(SYS_mmap)
{
    errno = 0;
    void *addr = (void *)arg1;
    size_t length = (size_t)arg2;
    int prot = (int)arg3;
    int flags = (int)arg4;
    int fd = (int)arg5;
    off_t offset = (off_t)arg6;
    return (long) mmap(addr, length, prot, flags, fd, offset);
}
SGX_WEAK SGX_DEFINE_SYSCALL2(SYS_munmap)
{
    errno = 0;
    void *addr = (void *)arg1;
    size_t length = (size_t)arg2;
    return munmap(addr, length);
}

static long _syscall(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    // Each of the syscall implementation functions must set errno correctly
    // since they can be called directly, bypassing this _sycall dispatching
    // function.

    switch (number)
    {
        SGX_SYSCALL_DISPATCH(SYS_accept, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_access, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_bind, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_chdir, arg1);
        SGX_SYSCALL_DISPATCH(SYS_close, arg1);
        SGX_SYSCALL_DISPATCH(SYS_clock_nanosleep, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_connect, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_creat, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_dup, arg1);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_dup2, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_dup3, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_epoll_create, arg1);
#endif
        SGX_SYSCALL_DISPATCH(SYS_epoll_create1, arg1);
        SGX_SYSCALL_DISPATCH(SYS_epoll_ctl, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_epoll_pwait, arg1, arg2, arg3, arg4, arg5);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_epoll_wait, arg1, arg2, arg3, arg4);
#endif
        SGX_SYSCALL_DISPATCH(SYS_exit, arg1);
        SGX_SYSCALL_DISPATCH(SYS_faccessat, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_fcntl, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_fdatasync, arg1);
        SGX_SYSCALL_DISPATCH(SYS_flock, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_fstat, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_fsync, arg1);
        SGX_SYSCALL_DISPATCH(SYS_ftruncate, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_getcwd, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_getdents64, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_getegid);
        SGX_SYSCALL_DISPATCH(SYS_geteuid);
        SGX_SYSCALL_DISPATCH(SYS_getgid);
        SGX_SYSCALL_DISPATCH(SYS_getgroups, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_getpeername, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_getpgid, arg1);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_getpgrp);
#endif
        SGX_SYSCALL_DISPATCH(SYS_getpid);
        SGX_SYSCALL_DISPATCH(SYS_getppid);
        SGX_SYSCALL_DISPATCH(SYS_getsockname, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_getsockopt, arg1, arg2, arg3, arg4, arg5);
        SGX_SYSCALL_DISPATCH(SYS_getuid);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_link, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_linkat, arg1, arg2, arg3, arg4, arg5);
        SGX_SYSCALL_DISPATCH(SYS_listen, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_lseek, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_lstat, arg1, arg2);
#endif
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_mkdir, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_mkdirat, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_mount, arg1, arg2, arg3, arg4, arg5);
        SGX_SYSCALL_DISPATCH(SYS_nanosleep, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_newfstatat, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_open, arg1, arg2, arg3);
#endif
        SGX_SYSCALL_DISPATCH(SYS_openat, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_poll, arg1, arg2, arg3);
#endif
        SGX_SYSCALL_DISPATCH(SYS_ppoll, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_pread64, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_pselect6, arg1, arg2, arg3, arg4, arg5);
        SGX_SYSCALL_DISPATCH(SYS_pwrite64, arg1, arg2, arg3, arg4);
        SGX_SYSCALL_DISPATCH(SYS_read, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_readv, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_recvfrom, arg1, arg2, arg3, arg4, arg5, arg6);
        SGX_SYSCALL_DISPATCH(SYS_recvmsg, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_rename, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_renameat, arg1, arg2, arg3, arg4, arg5);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_rmdir, arg1);
#endif
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_select, arg1, arg2, arg3, arg4, arg5);
#endif
        SGX_SYSCALL_DISPATCH(SYS_sendto, arg1, arg2, arg3, arg4, arg5, arg6);
        SGX_SYSCALL_DISPATCH(SYS_sendmsg, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_setsockopt, arg1, arg2, arg3, arg4, arg5);
        SGX_SYSCALL_DISPATCH(SYS_shutdown, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_socket, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_socketpair, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_stat, arg1, arg2);
#endif
        SGX_SYSCALL_DISPATCH(SYS_truncate, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_write, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_writev, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_uname, arg1);
#if __x86_64__ || _M_X64
        SGX_SYSCALL_DISPATCH(SYS_unlink, arg1);
#endif
        SGX_SYSCALL_DISPATCH(SYS_unlinkat, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_umount2, arg1, arg2);
        SGX_SYSCALL_DISPATCH(SYS_getrandom, arg1, arg2, arg3);
        SGX_SYSCALL_DISPATCH(SYS_mmap, arg1, arg2, arg3, arg4, arg5, arg6);
        SGX_SYSCALL_DISPATCH(SYS_munmap, arg1, arg2);
    }

    errno = ENOSYS;
    return -1;
}

long syscall(long number, ...)
{
    long ret;

    va_list ap;
    va_start(ap, number);
    long arg1 = va_arg(ap, long);
    long arg2 = va_arg(ap, long);
    long arg3 = va_arg(ap, long);
    long arg4 = va_arg(ap, long);
    long arg5 = va_arg(ap, long);
    long arg6 = va_arg(ap, long);
    va_end(ap);
    ret = _syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);

    return ret;
}
