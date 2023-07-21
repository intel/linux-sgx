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
 * File: sgx_trts_aex.h
 * Description:
 *     Header file for aex notify handling APIs.
 */

#ifndef _SGX_TRTS_AEX_H_
#define _SGX_TRTS_AEX_H_

#include <stdint.h>
#include <stddef.h>
#include "sgx_defs.h"
#include "sgx_trts_exception.h"
#include "sgx_error.h"

typedef void (*sgx_aex_mitigation_fn_t)(const sgx_exception_info_t *info, const void * args);

typedef struct _aex_mitigation_node_t
{
    sgx_aex_mitigation_fn_t handler;
    const void *args;
    struct _aex_mitigation_node_t * next;
} sgx_aex_mitigation_node_t;


#ifdef __cplusplus
extern "C" {
#endif

/* sgx_set_ssa_aexnotify()
 * Parameters:
 *      flag - 0 to disable AEX-Notify
 *             non-zero to enable AEX-Notify
 * Return Value:
 *      SGX_SUCCESS - success
 *      SGX_ERROR_UNEXPECTED - unexpected error
 */
sgx_status_t SGXAPI sgx_set_ssa_aexnotify(int flag);


/* sgx_register_aex_handler()
 * Parameters:
 *      aex_node - A pointer to an AEX mitigation node. The mitigation node must exist and be valid until it is unregistered.
 *      handler  - A function handler to call after being notified of an AEX
 *      args     - Arguments to pass to the handler
 * Return Value:
 *      SGX_SUCCESS - success
 *      SGX_ERROR_INVALID_PARAMETER - aex_node or handler are NULL
 */
sgx_status_t SGXAPI sgx_register_aex_handler(sgx_aex_mitigation_node_t *aex_node, sgx_aex_mitigation_fn_t handler, const void *args);

/* sgx_unregister_aex_handler()
 * Parameters:
 *      handler  - A function handler that was previously registered
 * Return Value:
 *      SGX_SUCCESS - success
 *      SGX_ERROR_INVALID_PARAMETER - handler was NULL or has not been previously registered
 *      SGX_ERROR_UNEXPECTED - There currently are no registered handlers
 */
sgx_status_t SGXAPI sgx_unregister_aex_handler(sgx_aex_mitigation_fn_t handler);

#ifdef __cplusplus
}
#endif

#endif
