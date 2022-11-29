/**
 *
 * INTEL CONFIDENTIAL
 * Copyright(c) 2011-2017 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code ("Material") are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and treaty
 * provisions. No part of the Material may be used, copied, reproduced, modified,
 * published, uploaded, posted, transmitted, distributed, or disclosed in any
 * way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel(R) in writing.
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

int sgx_mm_alloc_ocall(size_t addr, size_t length, int props, int flags)
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
