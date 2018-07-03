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

#include <sgx_trts.h>
#include "sl_fcall_mngr_common.h"

int sl_fcall_mngr_clone(struct sl_fcall_mngr* mngr, struct sl_fcall_mngr* untrusted)
{
    PANIC_ON(!sgx_is_outside_enclave(untrusted, sizeof(*untrusted)));
    sgx_lfence();

    BUG_ON(mngr == NULL);
    BUG_ON(untrusted == NULL);

    sl_fcall_type_t type_u = untrusted->fmn_type;
    PANIC_ON((type_u != SL_FCALL_TYPE_ECALL) && (type_u != SL_FCALL_TYPE_OCALL));
    
    mngr->fmn_type = type_u;

    int ret = sl_siglines_clone(&mngr->fmn_siglns,
                                &untrusted->fmn_siglns,
                                can_type_process(type_u) ? process_fcall : NULL);
    if (ret) return ret;

    //check that we have right call managers. 
    //i.e ecall manager on untrusted or ocall manager on trusted side
    PANIC_ON(fcall_type2direction(type_u) != sl_siglines_get_direction(&mngr->fmn_siglns));

    uint32_t num_lines = sl_siglines_size(&mngr->fmn_siglns);
    
    BUG_ON(untrusted->fmn_bufs == NULL);

	struct sl_fcall_buf** bufs_u = untrusted->fmn_bufs;
    PANIC_ON(!sgx_is_outside_enclave(bufs_u, sizeof(bufs_u[0]) * num_lines));
    sgx_lfence();
    
	mngr->fmn_bufs = bufs_u;
	mngr->fmn_call_table = NULL;
    
	return 0;
}
