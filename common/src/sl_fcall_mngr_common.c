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

#include <sl_fcall_mngr_common.h>
#ifdef SL_INSIDE_ENCLAVE /* trusted */
#include "sgx_trts.h"
#endif


sl_siglines_dir_t fcall_type2direction(sl_fcall_type_t type) 
{
    /* Use C99's designated initializers to make this conversion more readable */
    static sl_siglines_dir_t table[2] = {
        [SL_FCALL_TYPE_OCALL] = SL_SIGLINES_DIR_T2U,
        [SL_FCALL_TYPE_ECALL] = SL_SIGLINES_DIR_U2T
    };
    return table[type];
}

//returns true if calling thread can process this type of calls
int can_type_process(sl_fcall_type_t type) 
{
#ifdef SL_INSIDE_ENCLAVE /* Trusted */
    return type == SL_FCALL_TYPE_ECALL;
#else /* Untrusted */
    return type == SL_FCALL_TYPE_OCALL;
#endif
}

//returns true if calling thread can initiate this type of calls
int can_type_call(sl_fcall_type_t type) 
{
#ifdef SL_INSIDE_ENCLAVE /* Trusted */
    return type == SL_FCALL_TYPE_OCALL;
#else /* Untrusted */
    return type == SL_FCALL_TYPE_ECALL;
#endif
}


void sl_fcall_mngr_register_calls(struct sl_fcall_mngr* mngr,
                                  const sl_fcall_table_t* call_table)
{
    BUG_ON(call_table == NULL);
    mngr->fmn_call_table = call_table;
}


void process_fcall(struct sl_siglines* siglns, sl_sigline_t line) 
{
    struct sl_fcall_mngr* mngr = CONTAINER_OF(siglns, struct sl_fcall_mngr, fmn_siglns);

    const sl_fcall_table_t* call_table = mngr->fmn_call_table;
    BUG_ON(call_table == NULL);

    struct sl_fcall_buf* buf_u = mngr->fmn_bufs[line]; 
    BUG_ON(buf_u->fbf_status != SL_FCALL_STATUS_SUBMITTED);
    buf_u->fbf_status = SL_FCALL_STATUS_ACCEPTED;

	uint32_t func_id = buf_u->fbf_fn_id;

    /* Get the function pointer */
    sl_fcall_func_t fcall_func = NULL;
    if (unlikely(func_id >= call_table->ftb_size)) 
	{
        buf_u->fbf_ret = SGX_ERROR_INVALID_FUNCTION;
        goto on_done;
    }
	
	sgx_lfence();

    fcall_func = call_table->ftb_func[func_id];
    if (unlikely(fcall_func == NULL)) 
	{
        buf_u->fbf_ret = mngr->fmn_type == SL_FCALL_TYPE_ECALL ?
                            SGX_ERROR_ECALL_NOT_ALLOWED :
                            SGX_ERROR_OCALL_NOT_ALLOWED ;
        goto on_done;
    }

	sgx_lfence();
    /* Do the call */
    buf_u->fbf_ret = fcall_func(buf_u->fbf_ms_ptr);

on_done:
    /* Notify the caller that the Fast Call is done by updating the status.
     * The memory barrier ensures that Fast Call results are visible to the
     * caller when it finds out that the status becomes DONE. */
    sgx_mfence();
    buf_u->fbf_status = SL_FCALL_STATUS_DONE;
}

uint32_t sl_fcall_mngr_process(struct sl_fcall_mngr* mngr) 
{
    BUG_ON(!can_type_process(mngr->fmn_type));
    return sl_siglines_process_signals(&mngr->fmn_siglns);
}


int sl_fcall_mngr_call(struct sl_fcall_mngr* mngr, struct sl_fcall_buf* buf_u,
                       uint32_t max_tries)
{
    BUG_ON(!can_type_call(mngr->fmn_type));

    int ret = 0;

    /* Allocate a free signal line to send signal */
    struct sl_siglines* siglns = &mngr->fmn_siglns;
    sl_sigline_t line = sl_siglines_alloc_line(siglns);
    if (line == SL_INVALID_SIGLINE) 
        return -EAGAIN;

    BUG_ON(buf_u->fbf_status != SL_FCALL_STATUS_INIT);
    buf_u->fbf_status = SL_FCALL_STATUS_SUBMITTED;

    /* Send a signal so that workers will access the buffer for Fast Call
     * requests. Here, a memory barrier is used to make sure the buffer is
     * visible when the signal is received on other CPUs. */
    mngr->fmn_bufs[line] = buf_u;
    sgx_mfence();

    sl_siglines_trigger_signal(siglns, line);

	while ((buf_u->fbf_status == SL_FCALL_STATUS_SUBMITTED) && (--max_tries > 0))
	{
        #ifdef SL_INSIDE_ENCLAVE /* trusted */
        if (sgx_is_enclave_crashed())
            return SGX_ERROR_ENCLAVE_CRASHED;
        #endif
		asm_pause();
	}

    if (unlikely(max_tries == 0))
	{
        if (sl_siglines_revoke_signal(siglns, line) == 0) 
		{
            ret = -EAGAIN;
            goto on_exit;
        }
        /* Otherwise, the signal is not revoked succesfully, meaning this
         * call is being or has been processed by workers. So we continue. */
    }

    /* The request must has been accepted. Now wait for its completion */
    while (buf_u->fbf_status != SL_FCALL_STATUS_DONE)
    {
        #ifdef SL_INSIDE_ENCLAVE /* trusted */
        if (sgx_is_enclave_crashed())
            return SGX_ERROR_ENCLAVE_CRASHED;
        #endif
        asm_pause();
    }

on_exit:
    mngr->fmn_bufs[line] = NULL;
    sl_siglines_free_line(siglns, line);
    return ret;
}


