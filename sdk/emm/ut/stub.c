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

#include "../sgx_mm_primitives.h"
#include "../sgx_mm_rt_abstraction.h"

struct _sgx_mm_mutex {
    void *impl;
} g_mm_lock;

int do_eaccept(const sec_info_t* si, size_t addr)
{
    return 0;
}

int do_eacceptcopy(const sec_info_t* si, size_t addr, size_t src)
{
    return 0;
}

int do_emodpe(const sec_info_t* si, size_t addr)
{
    return 0;
}

int sgx_mm_alloc_ocall(size_t addr, size_t length, int flags)
{
    return 0;
}

int sgx_mm_modify_ocall(size_t addr, size_t length, int flags_from, int flags_to)
{
    return 0;
}

size_t get_rts_base()
{
    return 0;
}

size_t get_rts_end()
{
    return 0x7FFFFF000000;
}

size_t get_user_base()
{
    return 0x7FFFFF000000;
}

size_t get_user_end()
{
    return 0x7FFFFFFFFFFF;
}
bool sgx_mm_is_within_enclave(const void *ptr, size_t size){
    return true;
}


sgx_mm_mutex* sgx_mm_mutex_create(void)
{
    return &g_mm_lock;
}
int sgx_mm_mutex_lock(sgx_mm_mutex *mutex)
{
    return 0;
}
int sgx_mm_mutex_unlock(sgx_mm_mutex *mutex)
{
    return 0;
}

int sgx_mm_mutex_destroy(sgx_mm_mutex *mutex)
{
    return 0;
}
bool sgx_mm_register_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    return true;
}
