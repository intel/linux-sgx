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

#ifndef _SL_FCALL_MNGR_H_
#define _SL_FCALL_MNGR_H_

/*
 * sl_fcall_mngr - switchless Call manager
 *
 * sl_fcall_mngr is a cross-enclave data structure. switchless OCall requests can be
 * made via a trusted object of sl_fcall_mngr, which is "cloned" from an
 * untrusted object of sl_fcall_mngr. The latter is created by the untrusted
 * code and are used by untrusted workers to process switchless OCall requests.
 * The same is true for switchless ECalls.
 *
 * What is cross-enclave data structures?
 *
 * A cross-enclave data structure is a data structure that are designed to be
 * shared by both non-enclave and enclave code, and to be used securely by the
 * enclave code.
 *
 * The life cycle of a cross-enclave data structure is as follows. First, the
 * non-enclave code allocates and initializes an object of the cross-enclave
 * data structure and then passes the pointer of the object to the enclave
 * code. Then, the enclave code creates an trusted object out of the given,
 * untrusted object; this is called "clone". This clone operation will do all
 * proper security checks. Finally, the enclave code can access and manipuate
 * its cloned object securely. Note that the states of an (untrusted) original
 * object and its (trusted) cloned object are linked, e.g., updates on one
 * party can be observed by the other (yes, just like a pair of entanged
 * particles in quantum physics).
 *
 */

#include <sgx_error.h>
#include <sl_siglines.h>
#ifndef SL_INSIDE_ENCLAVE /* Untrusted */
#include <internal/routine.h>
#endif

typedef enum {
    SL_FCALL_TYPE_OCALL,
    SL_FCALL_TYPE_ECALL
} sl_fcall_type_t;

typedef sgx_status_t(*sl_fcall_func_t)(const void* /* ms */);

typedef struct {
    uint32_t                    ftb_size;
    sl_fcall_func_t             ftb_func[];
} sl_fcall_table_t; /* compatible with sgx_ocall_table_t */

typedef enum {
    SL_FCALL_STATUS_INIT,
    SL_FCALL_STATUS_SUBMITTED,
    SL_FCALL_STATUS_ACCEPTED,
    SL_FCALL_STATUS_DONE
} sl_fcall_status_t;

struct sl_fcall_buf {
    volatile sl_fcall_status_t  fbf_status;
    sgx_status_t                fbf_ret;
    uint32_t                    fbf_fn_id;
    /* For OCall, fbf_ms_ptr is NULL or &fbf_ms[0];
     * For ECall, fbf_ms_ptr is the ms passed from sgx_ecall_switchless() */
    void*                       fbf_ms_ptr;
    char                        fbf_ms[0];
};

struct sl_fcall_mngr {
    sl_fcall_type_t             fmn_type;
    struct sl_siglines          fmn_siglns;
    struct sl_fcall_buf**       fmn_bufs;
    const sl_fcall_table_t*     fmn_call_table;
};

__BEGIN_DECLS

#ifndef SL_INSIDE_ENCLAVE /* Untrusted */

int sl_fcall_mngr_init(struct sl_fcall_mngr* mngr,
                        sl_fcall_type_t type,
                        uint32_t max_pending_ocalls);
void sl_fcall_mngr_destroy(struct sl_fcall_mngr* mngr);

#else /* Trusted */

int sl_fcall_mngr_clone(struct sl_fcall_mngr* mngr,
                         struct sl_fcall_mngr* untrusted);

#endif /* SL_INSIDE_ENCLAVE */

static inline sl_fcall_type_t sl_fcall_mngr_get_type(struct sl_fcall_mngr* mngr) {
    return mngr->fmn_type;
}

void sl_fcall_mngr_register_calls(struct sl_fcall_mngr* mngr,
                                  const sl_fcall_table_t* call_table);

uint32_t sl_fcall_mngr_process(struct sl_fcall_mngr* mngr);

int sl_fcall_mngr_call(struct sl_fcall_mngr* mngr, struct sl_fcall_buf* buf_u,
                       uint32_t max_tries);

__END_DECLS

#endif /* _SL_FCALL_MNGR_H_ */
