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
#include "stdio.h"
#include "stdlib.h"
#include "util.h"
#include "string.h"
#include "unistd.h"
#include "sys/mman.h"
#include "mbusafecrt.h"
#include "sgx_trts.h"
#include "se_trace.h"

#define PATH_MAX 4096
char* realpath(const char* path, char* resolved_path)
{
    char *ret = NULL;
    char *p = NULL;

    errno = 0;

    if (!path)
    {
        SE_TRACE_ERROR("[stdc_ex] realpath - invalid parameter\n");
        errno = EINVAL;
        return NULL;
    }

    // imposible to determin the resolved_path length, so do not support resolved_path != NULL scenario
    if (resolved_path)
    {
        SE_TRACE_ERROR("[stdc_ex] realpath - resolved path must be NULL\n");
        errno = EINVAL;
	resolved_path[0] = '\0';
        return NULL;
    }

    if (u_realpath(&ret, path) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if (ret == NULL)
    {
	return NULL;
    }

    size_t len = strlen(ret) + 1;
    if(len > PATH_MAX)
    {
        SE_TRACE_ERROR("[stdc_ex] realpath - invalid return length\n");
        errno = ENAMETOOLONG;
	return NULL;
    }
    if(!sgx_is_outside_enclave(ret, len))
    {
        SE_TRACE_ERROR("[stdc_ex] realpath - return value must be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    p = (char *) malloc(len);
    if (!p)
    {
        SE_TRACE_ERROR("[stdc_ex] realpath - malloc failed\n");
        errno = ENOMEM;
        return NULL;
    }
    memcpy_s(p, len, ret, len);
    ofree(ret);
    return p;
}

_TLIBC_NORETURN_ void exit(int status)
{
    UNUSED(status);

    abort();

    /* Never return. */
    for (;;)
        ;
}

char *getenv (const char *name)
{
    char* ret = NULL;

    errno = 0;

    if (u_getenv(&ret, name) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    size_t len = strlen(ret) + 1;
    if(!sgx_is_outside_enclave(ret, len))
    {
        SE_TRACE_ERROR("[stdc_ex] getenv - return value should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }

    return ret;
}

// malloc on host 
void *omalloc(size_t size)
{
    void *ret = NULL;
 
    errno = 0;

    if (u_malloc(&ret, size) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if (!sgx_is_outside_enclave(ret, size)) {
        SE_TRACE_ERROR("[stdc_ex] omalloc - return value should be outside enclave\n");
        errno = EINVAL;
        return NULL;
    }

    return ret;  
}

void ofree(void *ptr)
{
    errno = 0;

    if (!sgx_is_outside_enclave(ptr, 1)) {
        SE_TRACE_ERROR("[stdc_ex] ofree - ptr should be outside enclave\n");
        errno = EINVAL;
    }
    else if(u_free(ptr) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }

    return; 
}

