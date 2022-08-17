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
#include "util.h"
#include "stdlib.h"
#include "errno.h"
#include "dirent.h"
#include "fcntl.h"
#include "unistd.h"
#include "sgx_trts.h"
#include "se_trace.h"

DIR* opendir(const char* pathname)
{
    DIR *ret = 0;

    errno = 0;

    if (u_opendir(&ret, pathname) != SGX_SUCCESS) 
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if(!sgx_is_outside_enclave(ret, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] opendir return value should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    return ret;
}

struct dirent* readdir(DIR* dir)
{
    struct dirent *ret = NULL;

    errno = 0;

    if(!sgx_is_outside_enclave(dir, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] readdir input parametre dir should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_readdir(&ret, dir) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if(!sgx_is_outside_enclave(ret, sizeof(struct dirent)))
    {
        SE_TRACE_ERROR("[stdc_ex] readdir return value should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    return ret;
}
weak_alias(readdir, readdir64);

int closedir(DIR* dir)
{
    int ret = -1;

    errno = 0;

    if(!sgx_is_outside_enclave(dir, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] closedir input parametre dir should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_closedir(&ret, dir) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

void rewinddir(DIR* dir)
{
    errno = 0;

    if(!sgx_is_outside_enclave(dir, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] rewinddir input parametre dir should be outside enclave\n");
        errno = EINVAL;
    }
    else if (u_rewinddir(dir) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }
}

int getdents64(unsigned int fd, struct dirent* dirp, unsigned int count)
{
    int ret = -1;

    errno = 0;

    if (u_getdents64(&ret, fd, dirp, count) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }
    return ret;
}

long telldir(DIR *dirp)
{
    long ret = -1;
    errno = 0;

    if(!sgx_is_outside_enclave(dirp, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] telldir input parametre dir should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_telldir(&ret, dirp) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

void seekdir(DIR *dirp, long loc)
{
    errno = 0;

    if(!sgx_is_outside_enclave(dirp, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] telldir input parametre dir should be outside enclave\n");
        errno = EINVAL;
    }
    else if(u_seekdir(dirp, loc) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }
    return;
}

