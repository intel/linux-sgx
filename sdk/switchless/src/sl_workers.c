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


#include <sl_workers.h>
#include <sl_uswitchless.h>
#include <sl_once.h>
#include <sl_debug.h>
#include <sl_atomic.h>
#include <sl_init.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "sgx_trts.h"

/*=========================================================================
 * Retrieve ECall table
 *========================================================================*/

/*
 * Copied from trts_internal.h
 * */
typedef struct 
{
    const void     *ecall_addr;
    uint8_t         is_priv;
} ecall_info_t;

typedef struct 
{
    size_t          nr_ecall;
    ecall_info_t    ecall_table[0];
} ecall_table_t;

extern const ecall_table_t g_ecall_table;

static sl_fcall_table_t* new_fecall_table(void) 
{
    uint32_t num_ecalls = (uint32_t)g_ecall_table.nr_ecall;

    size_t table_size = sizeof(sl_fcall_table_t)
                      + sizeof(sl_fcall_func_t) * num_ecalls;
    sl_fcall_table_t* fcall_table = malloc(table_size);
    if (fcall_table == NULL) return NULL;

    fcall_table->ftb_size = num_ecalls;

    for (uint32_t fi = 0; fi < num_ecalls; fi++) 
    {
        const ecall_info_t* ecall_info = &g_ecall_table.ecall_table[fi];
        fcall_table->ftb_func[fi] = ecall_info->is_priv == 0 ? (sl_fcall_func_t) ecall_info->ecall_addr : NULL;
    }

    return fcall_table;
}

/*=========================================================================
 * Initialisation
 *========================================================================*/

static struct sl_fcall_mngr g_fecall_mngr_t;
static sl_once_t g_init_ecall_mngr_done_t = SL_ONCE_INITIALIZER;

static uint64_t init_tswitchless_ecall_mngr(void)
{
    if (sl_uswitchless_handle == NULL) return EINVAL;

    struct sl_fcall_mngr* mngr_u = &sl_uswitchless_handle->us_fecall_mngr;
    int ret = sl_fcall_mngr_clone(&g_fecall_mngr_t, mngr_u);
    if (ret) 
		return (uint64_t)ret;

    PANIC_ON(sl_fcall_mngr_get_type(&g_fecall_mngr_t) != SL_FCALL_TYPE_ECALL);

    sl_fcall_table_t* fecall_table = new_fecall_table();
    
    if (fecall_table == NULL) 
		return ENOMEM;

    sl_fcall_mngr_register_calls(&g_fecall_mngr_t, fecall_table);

    return 0;
}

/*=========================================================================
 * Process Fast ECalls
 *========================================================================*/

/* The builtin ECMD_RUN_SWITCHLESS_TWORKER ECall calls this function eventually */
sgx_status_t do_run_switchless_tworker(void* ms)
{
	(void)ms;
    if (sl_call_once(&g_init_ecall_mngr_done_t, init_tswitchless_ecall_mngr)) return SGX_ERROR_UNEXPECTED;

	uint32_t max_retries = sl_uswitchless_handle->us_config.retries_before_sleep;
	uint32_t retries = 0;

    while (retries < max_retries)
	{
		if (sl_fcall_mngr_process(&g_fecall_mngr_t) == 0) 
		{
            if (sgx_is_enclave_crashed())
                return SGX_ERROR_ENCLAVE_CRASHED;

            retries++;
			asm_pause();
		}
		else
		{
			retries = 0;
		}
	}

    /* Return when the worker is being idle for some time */
    return SGX_SUCCESS;
}
