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

#include "sgx_stdc_ex_t.h"
#include "errno.h"
#include "util.h"
#include "string.h"
#include "unistd.h"
#include "sched.h"
#include "sys/stat.h"
#include "sys/uio.h"
#include "sys/time.h"
#include "sys/file.h"
#include "sgx_trts.h"
#include "se_trace.h"

#define MAX_PATH 260

int gethostname(char* name, size_t len)
{
    int ret = -1;

    errno = 0;

    if (u_gethostname(&ret, name, len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    // if truncation occurs, then it is unspecified whether the returned buffer includes a terminating null byte.
    // so add null byte to avoid misuse.
    if(len > 0) name[len-1] = '\0';

    return ret;
}

int getdomainname(char* name, size_t len)
{
    int ret = -1;

    errno = 0;

    if (u_getdomainname(&ret, name, len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    if(len > 0) name[len-1] = '\0';

    return ret;
}

char* getcwd(char* buf, size_t size)
{
    char* ret = NULL;
    char* p = NULL;
    size_t n;

    errno = 0;

    if (buf && size == 0)
    {
        SE_TRACE_ERROR("[stdc_ex] getcwd - invalid parameter\n");
        errno = EINVAL;
        return NULL;
    }

    if (!buf)
    {
        if (size == 0)
        {
            n = MAX_PATH;
        }
        else
        {
            n = size;
        }
        p = (char *)malloc(n);
        if (!p)
        {
            SE_TRACE_ERROR("[stdc_ex] getcwd - malloc failed\n");
            errno = ENOMEM;
            return NULL;
        }
    }
    else
    {
        n = size;
        p = buf;
    }

    if (u_getcwd(&ret, p, n) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if (ret == NULL && buf == NULL)
    {
        free(p);
        p = NULL;
    }
    return p;
}

int chdir(const char* path)
{
    int ret = -1;

    errno = 0;

    if (u_chdir(&ret, path) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int nanosleep(struct timespec* req, struct timespec* rem)
{
    int ret = 0;

    errno = 0;

    if (u_nanosleep(&ret, req, rem) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int clock_nanosleep(
    int clockid,
    int flag,
    struct timespec* req,
    struct timespec* rem)
{
    int ret = 0;
    if(u_clock_nanosleep(&ret, clockid, flag, req, rem) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
    }
    return ret;
}

pid_t getpid(void)
{
    pid_t ret = 0;

    errno = 0;

    if (u_getpid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

pid_t getppid(void)
{
    pid_t ret = 0;

    errno = 0;

    if (u_getppid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

pid_t getpgrp(void)
{
    pid_t ret = 0;

    errno = 0;

    if (u_getpgrp(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

uid_t getuid(void)
{
    uid_t ret = 0;

    errno = 0;

    if (u_getuid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

uid_t geteuid(void)
{
    uid_t ret = 0;

    errno = 0;

    if (u_geteuid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

gid_t getgid(void)
{
    gid_t ret = 0;

    errno = 0;

    if (u_getgid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

gid_t getegid(void)
{
    gid_t ret = 0;

    errno = 0;

    if (u_getegid(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

pid_t getpgid(pid_t pid)
{
    pid_t ret = -1;

    errno = 0;

    if (u_getpgid(&ret, pid) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int getgroups(int size, gid_t list[])
{
    int ret = -1;

    errno = 0;

    if (u_getgroups(&ret, size, list) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t read(int fd, void* buf, size_t count)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_read(&ret, fd, buf, count) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t write(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_write(&ret, fd, buf, count) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int close(int fd)
{
    int ret = -1;

    errno = 0;

    if (u_close(&ret, fd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int flock(int fd, int operation)
{
    int ret = -1;

    errno = 0;

    if (u_flock(&ret, fd, operation) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int fsync(int fd)
{
    int ret = -1;

    errno = 0;

    if (u_fsync(&ret, fd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int fdatasync(int fd)
{
    int ret = -1;

    errno = 0;

    if (u_fdatasync(&ret, fd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int fchown(int fd, uid_t uid, gid_t gid)
{
    int ret = -1;

    errno = 0;

    if (u_fchown(&ret, fd, uid, gid) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int dup(int oldfd)
{
    int ret = -1;

    errno = 0;

    if (u_dup(&ret, oldfd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int dup2(int oldfd, int newfd)
{
    int ret = -1;

    errno = 0;

    if (u_dup2(&ret, oldfd, newfd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int rmdir(const char* pathname)
{
    int ret = -1;

    errno = 0;

    if (u_rmdir(&ret, pathname) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int link(const char* oldpath, const char* newpath)
{
    int ret = -1;

    errno = 0;

    if (u_link(&ret, oldpath, newpath) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int unlink(const char* pathname)
{
    int ret = -1;

    errno = 0;

    if (u_unlink(&ret, pathname) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int truncate(const char* pathname, off_t length)
{
    int ret = -1;

    errno = 0;

    if (u_truncate(&ret, pathname, length) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int ftruncate(int fd, off_t length)
{
    int ret = -1;

    errno = 0;

    if (u_ftruncate(&ret, fd, length) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

weak_alias(ftruncate, ftruncate64);

off_t lseek(int fd, off_t offset, int whence)
{
    off_t ret = -1;

    errno = 0;

    if (u_lseek(&ret, fd, offset, whence) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(lseek, lseek64);

ssize_t pread(int fd, void* buf, size_t count, off_t offset)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_pread(&ret, fd, buf, count, offset) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(pread, pread64);

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_pwrite(&ret, fd, buf, count, offset) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(pwrite, pwrite64);

ssize_t readv(int fd, const struct iovec* iov, int iovcnt)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_readv(&ret, fd, (struct _iovec_t *)iov, iovcnt) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_writev(&ret, fd, (struct _iovec_t *)iov, iovcnt) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int access(const char* pathname, int mode)
{
    int ret = -1;

    errno = 0;

    if (u_access(&ret, pathname, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t readlink(const char * pathname, char * buf, size_t bufsize)
{
    ssize_t ret = -1;

    errno = 0;

    if (u_readlink(&ret, pathname, buf, bufsize) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

long sysconf (int name)
{
    long ret = -1;

    errno = 0;

    if (u_sysconf(&ret, name) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
long fpathconf(int fd, int name)
{
    long ret = -1;

    errno = 0;

    if (u_fpathconf(&ret, fd, name) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

long pathconf(const char *path, int name)
{
    long ret = -1;

    errno = 0;

    if (u_pathconf(&ret, path, name) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

time_t time(time_t *tloc)
{
    time_t ret = 0;

    errno = 0;

    if (u_time(&ret, tloc) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
int utimes(const char *filename, const struct timeval times[2])
{
    int ret = -1;

    errno = 0;

    if (u_utimes(&ret, filename, times) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    int ret = -1;

    errno = 0;

    if(tz != NULL)
    {
        SE_TRACE_ERROR("[stdc_ex] gettimeofday - tz must be NULL\n");
        errno = EINVAL;
	return -1;
    }

    if (u_gettimeofday(&ret, tv) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
struct tm *localtime(const time_t *t)
{
    struct tm *ret = NULL;

    errno = 0;

    if(u_localtime(&ret, t) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }
    if(!sgx_is_outside_enclave(ret, sizeof(struct tm)))
    {
        SE_TRACE_ERROR("[stdc_ex] localtime - return value should be outside enclave\n");
        errno = EINVAL;
        return NULL;
    }
    return ret;
}
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    int ret = 0;

    errno = 0;

    if(u_clock_gettime(&ret, clk_id, tp) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }
    return ret;
}

int sched_yield()
{
    int ret = 0;

    errno = 0;

    if(u_sched_yield(&ret) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }
    return ret;
}
