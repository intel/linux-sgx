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
#include "emm_private.h"
#include "metadata.h"
//#include "se_trace.h"
#include "util.h"
#include "se_page_attr.h"
#include "trts_internal.h"
#include "trts_util.h"

#if 0
void dump_layout_entry(layout_entry_t *entry)
{
    se_trace(SE_TRACE_DEBUG, "\t%s\n", __FUNCTION__);
    se_trace(SE_TRACE_DEBUG, "\tEntry Id     = %4u, %-16s, ", entry->id,
             entry[entry->id & ~(GROUP_FLAG)]);
    se_trace(SE_TRACE_DEBUG, "Page Count = %5u, ", entry->page_count);
    se_trace(SE_TRACE_DEBUG, "Attributes = 0x%02X, ", entry->attributes);
    se_trace(SE_TRACE_DEBUG, "Flags = 0x%016llX, ", entry->si_flags);
    se_trace(SE_TRACE_DEBUG, "RVA = 0x%016llX -> ", entry->rva);
}

void dump_layout_group(layout_t *layout)
{
    se_trace(SE_TRACE_DEBUG, "\tEntry Id(%2u) = %4u, %-16s, ", 0,
            layout->entry.id, layout_id_str[layout->entry.id & ~(GROUP_FLAG)]);
    se_trace(SE_TRACE_DEBUG, "Entry Count = %4u, ", layout->group.entry_count);
    se_trace(SE_TRACE_DEBUG, "Load Times = %u,    ", layout->group.load_times);
    se_trace(SE_TRACE_DEBUG, "LStep = 0x%016llX\n", layout->group.load_step);
}
#endif

static int build_rts_context_nodes(layout_entry_t *entry, uint64_t offset)
{
    uint64_t rva = offset + entry->rva;
    assert(IS_PAGE_ALIGNED(rva));

    size_t addr = (size_t)get_enclave_base() + rva;
    size_t size = entry->page_count << SE_PAGE_SHIFT;

    // entry is guard page or has EREMOVE, build a reserved ema
    if ((entry->si_flags == 0) ||
        (entry->attributes & PAGE_ATTR_EREMOVE)) {
        int ret = mm_init_ema((void*)addr,
                         size,
                         SGX_EMA_RESERVE | SGX_EMA_SYSTEM,
                         SGX_EMA_PROT_NONE,
                         NULL, NULL);
        if (ret) {
            return SGX_ERROR_UNEXPECTED;
        }
        return SGX_SUCCESS;
    }
    bool post_remove = (entry->attributes & PAGE_ATTR_POST_REMOVE);
    bool post_add = (entry->attributes & PAGE_ATTR_POST_ADD);
    bool static_min = (entry->attributes & PAGE_ATTR_EADD) && (!post_remove);

    if(post_remove)
    {
        if( mm_init_ema((void*)addr, size, SGX_EMA_SYSTEM,
                                    SGX_EMA_PROT_READ_WRITE,
                                    NULL, NULL))
            return SGX_ERROR_UNEXPECTED;
        if( 0 != mm_dealloc((void*)addr, size))
            return SGX_ERROR_UNEXPECTED;
        //fall through for POST_ADD to realloc as COMMIT_ON_DEMAND
    }

    if (post_add) {
        // build commit-on-demand ema node
        uint32_t commit_direction = SGX_EMA_GROWSUP;
        uint32_t type = SGX_EMA_PAGE_TYPE_REG;

        if (entry->id == LAYOUT_ID_STACK_MAX ||
            entry->id == LAYOUT_ID_STACK_DYN_MAX ||
            entry->id == LAYOUT_ID_STACK_DYN_MIN) {
            commit_direction = SGX_EMA_GROWSDOWN;
        }

        int ret = mm_alloc((void*)addr,
                         ((size_t)entry->page_count) << SE_PAGE_SHIFT,
                         SGX_EMA_COMMIT_ON_DEMAND | commit_direction
                         | SGX_EMA_SYSTEM | SGX_EMA_FIXED | type,
                         NULL, NULL, NULL);
        if (ret) {
            return SGX_ERROR_UNEXPECTED;
        }

    } else if (static_min) {
        // build static ema node
        int type = SGX_EMA_PAGE_TYPE_REG;
        int prot = entry->si_flags & (SGX_EMA_PROT_MASK);

        if (entry->id == LAYOUT_ID_TCS) {
            type = SGX_EMA_PAGE_TYPE_TCS;
            prot = SGX_EMA_PROT_NONE;
        }
        int ret = mm_init_ema((void*)addr,
                         size,
                         SGX_EMA_SYSTEM | type,
                         prot,
                         NULL,
                         NULL);
        if (ret) {
            return SGX_ERROR_UNEXPECTED;
        }

    }
    return SGX_SUCCESS;
}

static int init_rts_contexts_emas(layout_t *start, layout_t *end, uint64_t delta)
{
    int ret = SGX_ERROR_UNEXPECTED;

    for(layout_t *layout = start; layout < end; layout++) {
        //se_trace(SE_TRACE_DEBUG, "%s, step = 0x%016llX\n", __FUNCTION__, delta);

        if (!IS_GROUP_ID(layout->group.id)) {
            ret = build_rts_context_nodes(&layout->entry, delta);
            if (ret != SGX_SUCCESS) {
                return ret;
            }
        } else {
            uint64_t step = 0;
            for(uint32_t i = 0; i < layout->group.load_times; i++) {
                step += layout->group.load_step;
                ret = init_rts_contexts_emas(&layout[-layout->group.entry_count],
                                               layout, step);
                if (ret != SGX_SUCCESS) {
                    return ret;
                }
            }
        }
    }
    return SGX_SUCCESS;
}

extern "C" int init_segment_emas(void* enclave_base);

extern "C" int init_rts_emas(size_t rts_base, layout_t *layout_start, layout_t *layout_end)
{
    int ret = SGX_ERROR_UNEXPECTED;

    ret = init_segment_emas((void *)rts_base);
    if (SGX_SUCCESS != ret) {
        return ret;
    }

    ret = init_rts_contexts_emas(layout_start, layout_end, 0);
    return ret;
}

