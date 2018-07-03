/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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

#include <sgx_error.h>
#include <sgx_trts.h>
#include <sgx_edger8r.h>
#include <internal/thread_data.h>
#include <internal/util.h>
#include <sl_uswitchless.h>
#include <sl_fcall_mngr.h>
#include <sl_init.h>
#include <sl_once.h>
#include <sl_util.h>
#include <sl_debug.h>
#include <sl_atomic.h>
#include <rts.h>


/*=========================================================================
 * Initialization
 *========================================================================*/

static struct sl_fcall_mngr g_focall_mngr_t;

static sl_once_t g_init_ocall_mngr_done_t = SL_ONCE_INITIALIZER;

static uint64_t init_tswitchless_ocall_mngr(void) 
{
    if (sl_uswitchless_handle == NULL) return (uint64_t)(-1);

    struct sl_fcall_mngr* mngr_u = &sl_uswitchless_handle->us_focall_mngr;
    int ret = sl_fcall_mngr_clone(&g_focall_mngr_t, mngr_u);
    if (ret) 
		return (uint64_t)ret;

    PANIC_ON(sl_fcall_mngr_get_type(&g_focall_mngr_t) != SL_FCALL_TYPE_OCALL);
    return 0;
}

/*=========================================================================
 * The implementation of switchless OCall
 *========================================================================*/

sgx_status_t sgx_ocall_switchless(const unsigned int index, void* ms) 
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    struct sl_fcall_buf* buf_u = NULL;
    int error = 0;

    /* If Switchless SGX is not enabled at enclave creation, then switchless OCalls
     * fallback to the traditional OCalls */
    if (sl_call_once(&g_init_ocall_mngr_done_t, init_tswitchless_ocall_mngr)) 
        return sgx_ocall(index, ms);

    /* If no untrusted workers are running, then fallback */ //

    if (sl_uswitchless_handle->us_uworkers.num_running == 0) 
        goto on_fallback;

    if (sl_uswitchless_handle->us_uworkers.num_sleeping > 0)
    {
        if (sgx_ocall(SL_WAKE_WORKERS, (void*)&sl_uswitchless_handle->us_uworkers) != SGX_SUCCESS)
            goto on_fallback;
    }
    
    if (ms) 
    {
        buf_u = CONTAINER_OF(ms, struct sl_fcall_buf, fbf_ms);
    }
    else 
    {
        buf_u = sgx_ocalloc(sizeof(*buf_u));
        if (buf_u == NULL) 
            goto on_fallback;
    }
    
    buf_u->fbf_status = SL_FCALL_STATUS_INIT;
    buf_u->fbf_ret = SGX_ERROR_UNEXPECTED;
    buf_u->fbf_fn_id = index;
    buf_u->fbf_ms_ptr = ms;

    error = sl_fcall_mngr_call(&g_focall_mngr_t, buf_u, sl_uswitchless_handle->us_config.retries_before_fallback);
    if (error) 
    {
        if (ms == NULL) 
            sgx_ocfree_switchless();

        goto on_fallback;
    }

    ret = buf_u->fbf_ret;

    if (ms == NULL)
        sgx_ocfree_switchless(); // buf_u is now freeed

    lock_inc64(&sl_uswitchless_handle->us_uworkers.stats.processed);
    return ret;
on_fallback:
    lock_inc64(&sl_uswitchless_handle->us_uworkers.stats.missed);
    sl_uswitchless_handle->us_has_new_ocall_fallback = 1;
    return sgx_ocall(index, ms);
}

void* sgx_ocalloc_switchless(size_t size) 
{
    BUG_ON(size == 0);
    struct sl_fcall_buf* buf = sgx_ocalloc(sizeof(*buf) + size);
    if (buf == NULL) return NULL;
    return &buf->fbf_ms;
}

void sgx_ocfree_switchless(void) 
{
    sgx_ocfree();
}
