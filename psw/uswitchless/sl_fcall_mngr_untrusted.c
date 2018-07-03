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

#include "sl_fcall_mngr_common.h"

int sl_fcall_mngr_init(struct sl_fcall_mngr* mngr,
                       sl_fcall_type_t type,
                       uint32_t max_pending_calls)
{
    mngr->fmn_type = type;

    struct sl_fcall_buf** bufs = (struct sl_fcall_buf**)calloc(max_pending_calls, sizeof(bufs[0]));
    if (bufs == NULL) 
        return -ENOMEM;
    
    mngr->fmn_bufs = bufs;

    int ret = sl_siglines_init(&mngr->fmn_siglns,
                                fcall_type2direction(type),
                                max_pending_calls,
                                can_type_process(type) ? process_fcall : NULL);
    if (ret) 
    { 
        free(bufs); 
        return ret; 
    }

    mngr->fmn_call_table = NULL;
    return 0;
}

void sl_fcall_mngr_destroy(struct sl_fcall_mngr* mngr) 
{
    sl_siglines_destroy(&mngr->fmn_siglns);
    free(mngr->fmn_bufs);
}
