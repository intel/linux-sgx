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


/**
 * File: trts_aex.cpp
 * Description: 
 *     This file implements the APIs for AEX notify support.
 */

#include "sgx_trts_aex.h"
#include <stdlib.h>
#include "sgx_trts.h"
#include "arch.h"
#include "thread_data.h"
#include "trts_internal.h"
#include "trts_inst.h"
#include "util.h"
#include "trts_util.h"
#include "trts_shared_constants.h"
#include "se_cdefs.h"
#include "sgx_utils.h"


sgx_status_t SGXAPI sgx_set_ssa_aexnotify(int flag)
{
    thread_data_t *thread_data = get_thread_data();
    ssa_gpr_t *ssa_gpr = NULL;

    if(thread_data == NULL)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    auto *report = sgx_self_report();
    if(!(report->body.attributes.flags & SGX_FLAGS_AEX_NOTIFY))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    if (flag)
        ssa_gpr->aex_notify|= SSA_AEXNOTIFY_MASK;
    else
        ssa_gpr->aex_notify &= (uint8_t)(~SSA_AEXNOTIFY_MASK);
    return SGX_SUCCESS;
}


sgx_status_t SGXAPI sgx_register_aex_handler(sgx_aex_mitigation_node_t *aex_node, sgx_aex_mitigation_fn_t handler, const void *argv)
{
    if (aex_node == NULL || handler == NULL)
       return SGX_ERROR_INVALID_PARAMETER;
    thread_data_t *thread_data = get_thread_data();
    sgx_aex_mitigation_node_t *head = (sgx_aex_mitigation_node_t *)thread_data->aex_mitigation_list;

    aex_node->handler = handler;
    aex_node->args = argv;
    aex_node->next = head;
    head = aex_node;

    thread_data->aex_mitigation_list = (sys_word_t) head;

    return SGX_SUCCESS;
}

sgx_status_t SGXAPI sgx_unregister_aex_handler(sgx_aex_mitigation_fn_t handler)
{
    if(handler == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    // Search and find out the aex_node corresponding to the handler
    thread_data_t *thread_data = get_thread_data();
    sgx_aex_mitigation_node_t *node = (sgx_aex_mitigation_node_t *)thread_data->aex_mitigation_list;
    sgx_aex_mitigation_node_t *prev_node = NULL;
    if(node == NULL)
        return SGX_ERROR_UNEXPECTED;

    while(node)
    {
        if(node->handler == handler)
            break;
        prev_node = node;
        node = node->next;
    }
    // Remove the node from the list
    if(node != NULL)
    {
        if(prev_node == NULL)
        {
            // It is the first node
            thread_data->aex_mitigation_list = (sys_word_t)node->next;
        }
        else
        {
            prev_node->next = node->next;
        }
    }
    else // node not found
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return SGX_SUCCESS;
}


extern "C" sgx_status_t sgx_apply_mitigations(const sgx_exception_info_t *info)
{
    thread_data_t *thread_data = get_thread_data();
    sgx_aex_mitigation_node_t *node = (sgx_aex_mitigation_node_t *)thread_data->aex_mitigation_list;
    while(node)
    {
        // Call mitigation handlers
        node->handler(info, node->args);
        node = node->next;
    }
    return SGX_SUCCESS;
}


