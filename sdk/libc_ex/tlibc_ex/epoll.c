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

#include <stdlib.h>
#include <util.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>
#include "sgx_stdc_ex_t.h"
#include "se_trace.h"

int epoll_create(int size)
{
    UNUSED(size);

    int ret = -1;

    errno = 0;

    if (u_epoll_create1(&ret, 0) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int epoll_create1(int flags)
{
    int ret = -1;

    errno = 0;

    if (u_epoll_create1(&ret, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    int ret = -1;

    errno = 0;

    if (u_epoll_ctl(&ret, epfd, op, fd, event) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
{
    int ret = -1;

    errno = 0;

    if (u_epoll_wait(&ret, epfd, events, maxevents, timeout) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int epoll_pwait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout,
    const sigset_t* sigmask)
{
    int ret = -1;

    errno = 0;

    if (sigmask)
    {
        SE_TRACE_ERROR("[stdc_ex] epoll_pwait parameter sigmask must be NULL\n");
        errno = ENOSYS;
	return -1;
    }

    ret = epoll_wait(epfd, events, maxevents, timeout);

    return ret;
}

