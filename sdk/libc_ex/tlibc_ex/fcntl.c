// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_stdc_ex_t.h"
#include "errno.h"
#include "util.h"
#include "string.h"
#include "fcntl.h"
#include "netinet/in.h"
#include "se_trace.h"

int open(const char* pathname, int flags, mode_t mode)
{
    int ret = -1;

    errno = 0;

    if (u_open(&ret, pathname, flags, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(open, open64);

int openat(int dirfd, const char* pathname, int flags, mode_t mode)
{
    int ret = -1;

    errno = 0;

    if (u_openat(&ret, dirfd, pathname, flags, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(openat, openat64);

int fcntl(int fd, int cmd, ...)
{
    int ret = -1;

    errno = 0;

    va_list ap;
    va_start(ap, cmd);
    int arg = 0;
    void* argout = NULL;
    uint64_t argsize = 0;

    switch (cmd)
    {
        case F_GETFD:
        case F_GETFL:
            break;
        case F_SETFD:
        case F_SETFL:
        {
            arg = va_arg(ap, int);
            break;
        }

        case F_GETLK64:
        case F_OFD_GETLK:
        {
            argsize = sizeof(struct flock64);
            argout = va_arg(ap, void*);
	    memset(argout, 0, argsize);
            break;
        }

        case F_SETLKW64:
        case F_SETLK64:
        case F_OFD_SETLK:
        case F_OFD_SETLKW:
        {
            argsize = sizeof(struct flock64);
            argout = va_arg(ap, void*);
            break;
        }

        // for sockets
        default:
        case F_DUPFD: // Should be handled in posix layer
        case F_SETOWN:
        case F_GETOWN:
        case F_SETSIG:
        case F_GETSIG:
        case F_SETOWN_EX:
        case F_GETOWN_EX:
        case F_GETOWNER_UIDS:
	{
            SE_TRACE_ERROR("[stdc_ex] unsupported fcntl command\n");
            errno = EINVAL;
            return -1;
	}
    }

    if (u_fcntl(&ret, fd, cmd, arg, argsize, argout) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
weak_alias(fcntl, fcntl64);

int stat(const char *pathname, struct stat *statbuf)
{
    int ret = -1;

    errno = 0;

    if (u_stat(&ret, pathname, statbuf) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;

}
int lstat(const char *pathname, struct stat *statbuf)
{
    int ret = -1;

    errno = 0;

    if (u_lstat(&ret, pathname, statbuf) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;

}

int fstat(int fd, struct stat *statbuf)
{
    int ret = -1;

    errno = 0;

    if (u_fstat(&ret, fd, statbuf) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int fchmod(int fd, mode_t mode)
{
    int ret = -1;

    errno = 0;

    if (u_fchmod(&ret, fd, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    int ret = -1;
    errno = 0;

    if (u_mkdir(&ret, pathname, mode) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;

}


