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

#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include "sgx_mm.h"
#include "ema.h"
#include "emalloc.h"
#include "sgx_mm_rt_abstraction.h"

extern ema_root_t g_user_ema_root;
extern ema_root_t g_rts_ema_root;
#define  LEGAL_ALLOC_PAGE_TYPE (SGX_EMA_PAGE_TYPE_REG | SGX_EMA_PAGE_TYPE_SS_FIRST | SGX_EMA_PAGE_TYPE_SS_REST)
sgx_mm_mutex *mm_lock = NULL;
size_t mm_user_base = 0;
size_t mm_user_end = 0;
//!FIXME: assume user and system EMAs are not interleaved
// user EMAs are above the last system EMA
int mm_alloc_internal(void *addr, size_t size, int flags,
                 sgx_enclave_fault_handler_t handler,
                 void *private, void **out_addr, ema_root_t* root)
{
    int status = -1;
    size_t tmp_addr = 0;
    ema_t *node = NULL, *next_ema = NULL;
    bool ret = false;

    uint32_t alloc_flags = (uint32_t)flags & SGX_EMA_ALLOC_FLAGS_MASK;
    //Must have one of these:
    if (!(alloc_flags & (SGX_EMA_RESERVE | SGX_EMA_COMMIT_NOW | SGX_EMA_COMMIT_ON_DEMAND)))
        return EINVAL;

    uint64_t page_type = (uint64_t)flags & SGX_EMA_PAGE_TYPE_MASK;
    if ((uint64_t)(~LEGAL_ALLOC_PAGE_TYPE) & page_type) return EINVAL;
    if (page_type == 0)  page_type = SGX_EMA_PAGE_TYPE_REG;

    if (size % SGX_PAGE_SIZE) return EINVAL;

    uint8_t align_flag = (uint8_t) (((uint32_t)flags & SGX_EMA_ALIGNMENT_MASK) >> SGX_EMA_ALIGNMENT_SHIFT);
    if (align_flag == 0) align_flag = 12;
    if (align_flag < 12)
        return EINVAL;

    uint64_t align_mask = (uint64_t)(1ULL << align_flag) - 1ULL;

    tmp_addr = (size_t) addr;
    //If an address is given, user must align it
    if ((tmp_addr & align_mask))
        return EINVAL;
    if (addr && (!sgx_mm_is_within_enclave(addr, size)))
         return EACCES;

    if(sgx_mm_mutex_lock(mm_lock))
        return EFAULT;

    if (mm_user_base == 0){
        //the rts is not initialized
        status = EFAULT;
        goto unlock;
    }

    uint64_t si_flags = (uint64_t)SGX_EMA_PROT_READ_WRITE | page_type ;
    if (alloc_flags & SGX_EMA_RESERVE)
    {
        si_flags = SGX_EMA_PROT_NONE;
    }

    if (tmp_addr) {
        bool fixed_alloc = (alloc_flags & SGX_EMA_FIXED);
        bool in_system_but_not_allowed = false;
        size_t end = tmp_addr + size;
        size_t start = tmp_addr;
        if(root != &g_rts_ema_root &&
                    ema_exist_in(&g_rts_ema_root, start, size))
        {
            in_system_but_not_allowed = true;
            if(fixed_alloc){
                status = EPERM;
                goto unlock;
            }
        }
        ema_t* first = NULL;
        ema_t* last = NULL;
        bool exist_in_root = !search_ema_range(root, start, end, &first, &last);

        if(exist_in_root){
            // Use the reserved space earlier
            node = ema_realloc_from_reserve_range(first, last, start, end,
                            alloc_flags, si_flags,
                            handler, private);
            if (node){
                goto alloc_action;
            }
            //can't fit with the address but fixed alloc is asked
            if (fixed_alloc) {
                status = EEXIST;
                goto unlock;
            }
            // Not a fixed alloc,
            // fall through to find a free space anywhere
            assert(!ret);
        } else {
            // No existing ema overlapping with requested range
            // Use the address unless it is not allowed by rts
            if(!in_system_but_not_allowed){
                // make sure not in rts if this is user
                ret = find_free_region_at(root,
                                      tmp_addr, size, &next_ema);
            }
            //We can't use the address, fall through
        }
    }
    // At this point, ret == false means:
    // Either no address given or the given address can't be used
    if (!ret)
        ret = find_free_region(root,
            size, (1ULL << align_flag), &tmp_addr, &next_ema);
    if (!ret) {
        status = ENOMEM;
        goto unlock;
    }
/**************************************************
*      create and operate on a new node
***************************************************/
    assert(tmp_addr);//found address
    assert(next_ema);//found where to insert
    // create and insert the node
    node = ema_new(tmp_addr, size, alloc_flags, si_flags,
                         handler, private, next_ema);
    if (!node) {
        status = ENOMEM;
        goto unlock;
    }
alloc_action:
    assert(node);
    status = ema_do_alloc(node);
    if (status != 0) {
        goto alloc_failed;
    }
    if (out_addr) {
        *out_addr = (void *)tmp_addr;
    }
    status = 0;
    goto unlock;
alloc_failed:
    ema_destroy(node);

unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return status;
}

int sgx_mm_alloc(void *addr, size_t size, int flags,
                 sgx_enclave_fault_handler_t handler,
                 void *private, void **out_addr)
{
    if (flags & SGX_EMA_SYSTEM) return EINVAL;
    if(addr)
    {
        size_t tmp = (size_t)addr;
        if (tmp >= mm_user_end || tmp < mm_user_base)
           return EPERM;
    }
    return mm_alloc_internal(addr, size, flags,
            handler, private, out_addr, &g_user_ema_root);
}

int mm_commit_internal(void *addr, size_t size, ema_root_t* root)
{
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;
    ema_t *first = NULL, *last = NULL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);
    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }

    ret = ema_do_commit_loop(first, last, start, end);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_commit(void *addr, size_t size)
{
    return mm_commit_internal(addr, size, &g_user_ema_root);
}

int mm_uncommit_internal(void *addr, size_t size, ema_root_t* root)
{
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;
    ema_t *first = NULL, *last = NULL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);
    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }

    ret = ema_do_uncommit_loop(first, last, start, end);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_uncommit(void *addr, size_t size)
{
     return mm_uncommit_internal(addr, size, &g_user_ema_root);
}

int mm_dealloc_internal(void *addr, size_t size, ema_root_t* root)
{
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;
    ema_t *first = NULL, *last = NULL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);
    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }

    ret = ema_do_dealloc_loop(first, last, start, end);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_dealloc(void *addr, size_t size)
{
    return mm_dealloc_internal(addr, size, &g_user_ema_root);
}

int mm_commit_data_internal(void *addr, size_t size, uint8_t *data, int prot, ema_root_t* root)
{
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;
    ema_t *first = NULL, *last = NULL;

    if (size == 0)
        return EINVAL;
    if (size % SGX_PAGE_SIZE != 0)
        return EINVAL;
    if (start % SGX_PAGE_SIZE != 0)
        return EINVAL;
    if (((size_t)data) % SGX_PAGE_SIZE != 0)
        return EINVAL;
    if (((uint32_t)prot) & (uint32_t)(~SGX_EMA_PROT_MASK))
        return EINVAL;
    if (!sgx_mm_is_within_enclave(data, size))
        return EINVAL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);

    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }

    ret = ema_do_commit_data_loop(first, last, start, end, data, prot);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_commit_data(void *addr, size_t size, uint8_t *data, int prot)
{
    return mm_commit_data_internal (addr, size, data, prot, &g_user_ema_root);
}

int mm_modify_type_internal(void *addr, size_t size, int type, ema_root_t* root)
{
    // for this API, TCS is the only valid page type
    if (type != SGX_EMA_PAGE_TYPE_TCS) {
        return EPERM;
    }

    // TCS occupies only one page
    if (size != SGX_PAGE_SIZE) {
        return EINVAL;
    }
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;
    ema_t *first = NULL, *last = NULL;

    if (start % SGX_PAGE_SIZE != 0)
        return EINVAL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);

    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }

    // one page only, covered by a single ema node
    assert(ema_next(first) == last);
    ret = ema_change_to_tcs(first, (size_t)addr);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_modify_type(void *addr, size_t size, int type)
{
    return mm_modify_type_internal(addr, size, type, &g_user_ema_root);
}

int mm_modify_permissions_internal(void *addr, size_t size, int prot, ema_root_t* root)
{
    int ret = EFAULT;
    size_t start = (size_t)addr;
    size_t end = start + size;

    if (size == 0) return EINVAL;
    if (size % SGX_PAGE_SIZE) return EINVAL;
    if (start % SGX_PAGE_SIZE) return EINVAL;

    ema_t *first = NULL, *last = NULL;

    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ret = search_ema_range(root, start, end, &first, &last);
    if (ret < 0) {
        ret = EINVAL;
        goto unlock;
    }
    ret = ema_modify_permissions_loop(first, last, start, end, prot);
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

int sgx_mm_modify_permissions(void *addr, size_t size, int prot)
{
    return mm_modify_permissions_internal(addr, size, prot, &g_user_ema_root);
}

int sgx_mm_enclave_pfhandler(const sgx_pfinfo *pfinfo)
{
    int ret = SGX_MM_EXCEPTION_CONTINUE_SEARCH;
    size_t addr = TRIM_TO((pfinfo->maddr), SGX_PAGE_SIZE);
    if(sgx_mm_mutex_lock(mm_lock)) return ret;
    ema_t *ema = search_ema(&g_user_ema_root, addr);
    if (!ema) {
        ema = search_ema(&g_rts_ema_root, addr);
        if(!ema)
            goto unlock;
    }
    void* data = NULL;
    sgx_enclave_fault_handler_t eh = ema_fault_handler(ema, &data);
    if(eh){
        //don't hold the lock as handlers can longjmp
        sgx_mm_mutex_unlock(mm_lock);
        return eh(pfinfo, data);
    }
    if (ema_page_committed(ema, addr))
    {
        if (is_ema_transition(ema))
        {//as long as permissions expected, transition will be done
        // TODO: check EXEC?
        //This is never reached because of global lock
            if ((pfinfo->pfec.rw == 0 && 0 == (get_ema_si_flags(ema) & SGX_EMA_PROT_READ)) ||
                (pfinfo->pfec.rw == 1 && 0 == (get_ema_si_flags(ema) & SGX_EMA_PROT_WRITE)))
            {
                ret = SGX_MM_EXCEPTION_CONTINUE_SEARCH;
            }
            else
                ret = SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
        }
        goto unlock;
    }
    if (get_ema_alloc_flags(ema) & SGX_EMA_COMMIT_ON_DEMAND)
    {
        if ((pfinfo->pfec.rw == 0 && 0 == (get_ema_si_flags(ema) & SGX_EMA_PROT_READ)) ||
            (pfinfo->pfec.rw == 1 && 0 == (get_ema_si_flags(ema) & SGX_EMA_PROT_WRITE))) {
            ret = SGX_MM_EXCEPTION_CONTINUE_SEARCH;
            goto unlock;
        }

        //!TODO: Check GROWSUP/GROWSDOWN flags and optimize accordingly.
        if (ema_do_commit(ema, addr, addr + SGX_PAGE_SIZE)){
            sgx_mm_mutex_unlock(mm_lock);
            abort();
        }

        ret = SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
        goto unlock;
    }
    else
    {
        sgx_mm_mutex_unlock(mm_lock);
        //we found the EMA and nothing should cause the PF
        //Can't continue as we know something is wrong
        abort();
    }

    ret = SGX_MM_EXCEPTION_CONTINUE_SEARCH;
unlock:
    sgx_mm_mutex_unlock(mm_lock);
    return ret;
}

void sgx_mm_init(size_t user_base, size_t user_end)
{
    mm_lock = sgx_mm_mutex_create();
    mm_user_base = user_base;
    mm_user_end = user_end;
    sgx_mm_register_pfhandler(sgx_mm_enclave_pfhandler);
    emalloc_init();
}
