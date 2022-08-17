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
#include "sgx_trts.h"
#include "se_trace.h"

int getgrgid_r(gid_t gid, struct group *grp,
                 char *buf, size_t buflen, struct group **result)
{
    int ret = -1;

    errno = 0;

    if (!sgx_is_outside_enclave(grp, sizeof(struct group) 
     || !sgx_is_outside_enclave(buf, buflen)))
    {
        SE_TRACE_ERROR("[stdc_ex] getgrgid_r parameter grp and buf must be outside enclave\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }
    if(u_getgrgid_r(&ret, gid, grp, buf, buflen, result) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }

    if (*result && *result != grp)
    {
        SE_TRACE_ERROR("[stdc_ex] getgrgid_r output (*result == grp) is expected\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }
    return ret;
}
struct passwd *getpwuid(uid_t uid)
{
    struct passwd *ret = NULL;
    errno = 0;
    if(u_getpwuid(&ret, uid) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return NULL;
    }
    return ret;
}
int getpwuid_r(uid_t uid, struct passwd *pwd,
               char *buf, size_t buflen, struct passwd **result)
{
    int ret = -1;

    errno = 0;

    if (!sgx_is_outside_enclave(pwd, sizeof(struct passwd) 
     || !sgx_is_outside_enclave(buf, buflen)))
    {
        SE_TRACE_ERROR("[stdc_ex] getpwuid_r parameter pwd and buf must be outside enclave\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }
    if(u_getpwuid_r(&ret, uid, pwd, buf, buflen, result) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }

    if (*result && *result != pwd)
    {
        SE_TRACE_ERROR("[stdc_ex] getpwuid_r output (*result == pwd) is expected\n");
        errno = EINVAL;
	*result = NULL;
	return -1;
    }
    return ret;
}
