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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <sys/uio.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <unistd.h>
#include "sys/time.h"
#include "sgx_stdc_ex_u.h"

int u_gethostname(char* name, size_t len)
{
    errno = 0;

    return gethostname(name, len);
}

int u_getdomainname(char* name, size_t len)
{
    errno = 0;

    return getdomainname(name, len);
}

char* u_getcwd(char* buf, size_t size)
{
    errno = 0;

    return getcwd(buf, size);
}
int u_chdir(const char* path)
{
    errno = 0;

    return chdir(path);
}

int u_nanosleep(struct timespec* req, struct timespec* rem)
{
    errno = 0;

    return nanosleep(req, rem);
}

int u_clock_nanosleep(
    int clockid,
    int flag,
    struct timespec* req,
    struct timespec* rem)
{
    errno = 0;

    return clock_nanosleep(clockid, flag, req, rem);
}

pid_t u_getpid(void)
{
    return getpid();
}

pid_t u_getppid(void)
{
    return getppid();
}

pid_t u_getpgrp(void)
{
    return getpgrp();
}

uid_t u_getuid(void)
{
    return getuid();
}

uid_t u_geteuid(void)
{
    return geteuid();
}

gid_t u_getgid(void)
{
    return getgid();
}

gid_t u_getegid(void)
{
    return getegid();
}

pid_t u_getpgid(int pid)
{
    errno = 0;

    return getpgid(pid);
}

int u_getgroups(size_t size, gid_t* list)
{
    int ret = -1;

    errno = 0;

    if (size > INT_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    ret = getgroups((int)size, list);

done:
    return ret;
}

ssize_t u_read(int fd, void* buf, size_t count)
{
    errno = 0;

    return read(fd, buf, count);
}

ssize_t u_write(int fd, const void* buf, size_t count)
{
    errno = 0;

    return write(fd, buf, count);
}

int u_close(int fd)
{
    errno = 0;

    return close(fd);
}

int u_flock(int fd, int operation)
{
    errno = 0;

    return flock(fd, operation);
}

int u_fsync(int fd)
{
    errno = 0;

    return fsync(fd);
}

int u_fdatasync(int fd)
{
    errno = 0;

    return fdatasync(fd);
}

int u_fchown(int fd, unsigned int uid, unsigned int gid)
{
    errno = 0;

    return fchown((int)fd, uid, gid);
}

int u_dup(int oldfd)
{
    errno = 0;

    return dup(oldfd);
}

int u_dup2(int oldfd, int newfd)
{
    errno = 0;

    return dup2(oldfd, newfd);
}

int u_rmdir(const char* pathname)
{
    errno = 0;

    return rmdir(pathname);
}

int u_link(const char* oldpath, const char* newpath)
{
    errno = 0;

    return link(oldpath, newpath);
}

int u_unlink(const char* pathname)
{
    errno = 0;

    return unlink(pathname);
}

int u_truncate(const char* path, off_t length)
{
    errno = 0;

    return truncate(path, length);
}

int u_ftruncate(int fd, off_t length)
{
    errno = 0;

    return ftruncate(fd, length);
}

off_t u_lseek(int fd, off_t offset, int whence)
{
    errno = 0;

    return lseek(fd, offset, whence);
}

ssize_t u_pread(
    int fd,
    void* buf,
    size_t count,
    off_t offset)
{
    errno = 0;

    return pread(fd, buf, count, offset);
}

ssize_t u_pwrite(
    int fd,
    const void* buf,
    size_t count,
    off_t offset)
{
    errno = 0;

    return pwrite(fd, buf, count, offset);
}

ssize_t u_readv(
    int fd,
    struct _iovec_t* iov,
    int iovcnt)
{
    errno = 0;

    return readv(fd, (struct iovec *)iov, iovcnt);
}

ssize_t u_writev(
    int fd,
    struct _iovec_t* iov,
    int iovcnt)
{
    errno = 0;

    return writev(fd, (const struct iovec *)iov, iovcnt);
}

int u_access(const char* pathname, int mode)
{
    errno = 0;

    return access(pathname, mode);
}

ssize_t u_readlink(const char * pathname, char * buf, size_t bufsize)
{
    errno = 0;

    return readlink(pathname, buf, bufsize);
}

long u_sysconf (int name)
{
    errno = 0;

    return sysconf(name);
}

int u_getgrgid_r(gid_t gid, struct group *grp, char *buf, size_t buflen, struct group **result)
{
    errno = 0;

    int ret = getgrgid_r(gid, grp, buf, buflen, result);

    return ret;
}
struct passwd *u_getpwuid(uid_t uid)
{
    errno = 0;

    return (struct passwd *)getpwuid(uid);
}
int u_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
    errno = 0;

    int ret = getpwuid_r(uid, pwd, buf, buflen, result);

    return ret;
}

int u_getpeername(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getpeername(sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int u_getsockname(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getsockname((int)sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int u_close_socket(int fd)
{
    errno = 0;

    return close((int)fd);
}

long u_fpathconf(int fd, int name)
{
    errno = 0;

    return fpathconf(fd, name);
}
long u_pathconf(const char *path, int name)
{
    errno = 0;

    return pathconf(path, name);
}

time_t u_time(time_t *tloc)
{
    errno = 0;

    return time(tloc);
}

int u_utimes(const char *filename, const struct timeval times[2])
{
    errno = 0;

    return utimes(filename, times);
}

struct tm *u_localtime(const time_t *t)
{
    errno = 0;
    return localtime(t);
}

int u_gettimeofday (struct timeval *tv)
{
    errno = 0;
    return gettimeofday(tv, NULL);
}

int u_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    errno = 0;
    return clock_gettime(clk_id, tp);
}

int u_sched_yield()
{
    errno = 0;
    return sched_yield();
}
