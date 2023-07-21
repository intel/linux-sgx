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


#include <string.h>
#include "sgx_utils.h"
#include "trts_inst.h"
#include "util.h"
#include "trts_emm.h"
#include "trts_util.h"
#include "global_data.h"
#include "se_memcpy.h"
#include "se_page_attr.h"
#include "trts_internal.h"
#include "emm_private.h"

#ifndef SE_SIM

struct dynamic_flags_attributes
{
    si_flags_t si_flags;
    uint16_t    attributes;
};

const volatile layout_t *get_dynamic_layout_by_id(uint16_t id)
{
    for(uint32_t i = 0; i < g_global_data.layout_entry_num; i++)
    {
        if(g_global_data.layout_table[i].entry.id == id)
        {
            return &(g_global_data.layout_table[i]);
        }
    }
    return NULL;
}

static int check_heap_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    size_t heap_dyn_start, heap_dyn_size;

    heap_dyn_start = (size_t)get_heap_base() + get_heap_min_size();
    heap_dyn_size = get_heap_size() - get_heap_min_size();

    if ((size_t)addr >= heap_dyn_start
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= heap_dyn_start + heap_dyn_size)
    {
        if (fa != NULL)
        {
            fa->si_flags = SI_FLAGS_RW;
            fa->attributes = PAGE_ATTR_POST_ADD;
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

extern void *rsrv_mem_base;
extern size_t rsrv_mem_size;
extern size_t rsrv_mem_min_size;

static int check_rsrv_dyn_range(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    size_t rsrv_mem_dyn_start, rsrv_mem_dyn_size;

    rsrv_mem_dyn_start = (size_t)rsrv_mem_base + rsrv_mem_min_size;
    rsrv_mem_dyn_size = rsrv_mem_size - rsrv_mem_min_size;

    if ((size_t)addr >= rsrv_mem_dyn_start
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= rsrv_mem_dyn_start + rsrv_mem_dyn_size)
    {
        if (fa != NULL)
        {
            fa->si_flags = SI_FLAGS_RW;
            fa->attributes = PAGE_ATTR_POST_ADD;
        }
        return 0;
    }
    else
    {
        return -1;
    }
}


static int check_dynamic_entry_range(void *addr, size_t page_count, uint16_t entry_id, size_t entry_offset, struct dynamic_flags_attributes *fa)
{
    const volatile layout_t *layout = NULL;
    size_t entry_start_addr;
    uint32_t entry_page_count;

    if (entry_id < LAYOUT_ID_HEAP_MIN
            || entry_id > LAYOUT_ID_STACK_DYN_MIN
            || (NULL == (layout = get_dynamic_layout_by_id(entry_id))))
    {
        return -1;
    }

    entry_start_addr = (size_t)get_enclave_base() + (size_t)layout->entry.rva + entry_offset;
    entry_page_count = layout->entry.page_count;
    if ((size_t)addr >= entry_start_addr
            && (size_t)addr + (page_count << SE_PAGE_SHIFT) <= entry_start_addr + ((size_t)entry_page_count << SE_PAGE_SHIFT))
    {
        if (fa != NULL)
        {
            fa->si_flags = layout->entry.si_flags;
            fa->attributes = layout->entry.attributes;
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

static int check_utility_thread_dynamic_stack(void *addr, size_t page_count, struct dynamic_flags_attributes *fa)
{
    return check_dynamic_entry_range(addr, page_count, LAYOUT_ID_STACK_MAX, 0, fa);
}

// Verify if the range specified belongs to a dynamic range recorded in metadata.
static int check_dynamic_range(void *addr, size_t page_count, size_t *offset, struct dynamic_flags_attributes *fa)
{
    const volatile layout_t *dt_layout = NULL;

    // check for integer overflow
    if ((size_t)addr > SIZE_MAX - (page_count << SE_PAGE_SHIFT))
        return -1;

    // check heap dynamic range
    if (0 == check_heap_dyn_range(addr, page_count, fa))
        return 0;

    // check dynamic stack within utility thread
    if (0 == check_utility_thread_dynamic_stack(addr, page_count, fa))
        return 0;

    if (0 == check_rsrv_dyn_range(addr, page_count, fa))
        return 0;

    // check dynamic thread entries range
    if (NULL != (dt_layout = get_dynamic_layout_by_id(LAYOUT_ID_THREAD_GROUP_DYN)))
    {
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
            for (uint32_t i = 0; i < dt_layout->group.load_times + 1; i++)
            {
                if (0 == check_dynamic_entry_range(addr, page_count, id, i * ((size_t)dt_layout->group.load_step), fa))
                {
                    if (offset != NULL) *offset = i * ((size_t)dt_layout->group.load_step);
                    return 0;
                }
            }
    }
    else
    {
        // LAYOUT_ID_THREAD_GROUP_DYN does not exist, but possibly there is one single dynamic thead
        for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
            if (0 == check_dynamic_entry_range(addr, page_count, id, 0, fa))
            {
                if (offset != NULL) *offset = 0;
                return 0;
            }
    }
    return -1;
}

int is_dynamic_thread(void *tcs)
{
    struct dynamic_flags_attributes fa;

    if ((tcs != NULL) && (check_dynamic_range(tcs, 1, NULL, &fa) == 0) &&
            (fa.si_flags == SI_FLAGS_TCS))
    {
        return true;
    }

    return false;
}

int is_dynamic_thread_exist()
{
    if(!EDMM_supported)
        return false;
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_DYN_MIN);
    if (!layout)
        return false;
    else
        return true;
}


uint32_t get_dynamic_stack_max_page()
{
    const volatile layout_t * layout = get_dynamic_layout_by_id(LAYOUT_ID_STACK_MAX);
    if (!layout)
        return 0;
    else
        return layout->entry.page_count;
}
#endif

// Create a thread dynamically.
// It will add necessary pages and transform one of them into type TCS.
sgx_status_t do_add_thread(void *ptcs)
{
#ifdef SE_SIM
    (void)ptcs;
    return SGX_SUCCESS;
#else
    int ret = SGX_ERROR_UNEXPECTED;
    tcs_t *tcs = (tcs_t *)ptcs;
    tcs_t *tcs_template = NULL;
    size_t offset = 0;
    size_t enclave_base = (size_t)get_enclave_base();

    if ( 0 != check_dynamic_range((void *)tcs, 1, &offset, NULL))
        return SGX_ERROR_UNEXPECTED;

    // check if the tcs provided exactly matches the one in signtool
    const volatile layout_t *tcs_layout = get_dynamic_layout_by_id(LAYOUT_ID_TCS_DYN);
    if (!tcs_layout)
        return SGX_ERROR_UNEXPECTED;

    if ((size_t)(enclave_base + tcs_layout->entry.rva + offset) != (size_t)(tcs))
        return SGX_ERROR_UNEXPECTED;

    // adding page for all the dynamic entries
    for (uint16_t id = LAYOUT_ID_TCS_DYN; id <= LAYOUT_ID_STACK_DYN_MIN; id++)
    {
        const volatile layout_t *layout =  get_dynamic_layout_by_id(id);
        if (layout && (layout->entry.attributes & PAGE_ATTR_DYN_THREAD))
        {
            ret = mm_commit((void *)(enclave_base + layout->entry.rva + offset), (uint64_t)layout->entry.page_count << SE_PAGE_SHIFT);
            if (ret != 0)
                return SGX_ERROR_UNEXPECTED;
        }
    }

    //Copy and initialize TCS
    tcs_template = (tcs_t *)g_global_data.tcs_template;
    memcpy_s(tcs, TCS_SIZE, tcs_template, sizeof(g_global_data.tcs_template));

    //Adjust the tcs fields
    tcs->ossa = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ossa) - enclave_base;
    tcs->ofs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ofs_base) - enclave_base;
    tcs->ogs_base = (size_t)GET_PTR(size_t, (void *)tcs, tcs->ogs_base) - enclave_base;

    ret = mm_modify_type((void *)tcs, SE_PAGE_SIZE, SGX_EMA_PAGE_TYPE_TCS);
    if (ret != 0)
        return SGX_ERROR_UNEXPECTED;

    return SGX_SUCCESS;

#endif
}

