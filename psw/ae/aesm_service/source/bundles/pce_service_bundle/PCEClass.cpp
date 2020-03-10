/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#ifndef __GNUC__
#include "StdAfx.h"
#include <intrin.h>
#endif
#include <assert.h>
#include "PCEClass.h"
//#include "QEClass.h"
//#include "PVEClass.h"
#include "util.h"
#include "prof_fun.h"
#include "sgx_report.h"
#include "sgx_tseal.h"
#include "epid_pve_type.h"
#include "pce_u.h"
#include "metadata.h"

extern "C" bool get_metadata(const char* enclave_file, metadata_t *metadata);

void CPCEClass::before_enclave_load() {
    // always unload qe/pve enclave before loading pce enclave
    //CQEClass::instance().unload_enclave();
    //CPVEClass::instance().unload_enclave();
}

uint32_t CPCEClass::pce_get_target(sgx_target_info_t *p_target,
                    sgx_isv_svn_t *p_isvsvn)
{
    ae_error_t ae_err;
    metadata_t metadata;
    char enclave_path[MAX_PATH]= {0};
    if ((NULL == p_target) || (NULL == p_isvsvn))
        return AE_INVALID_PARAMETER;
    
    /* We need to make sure the PCE is successfully loaded */
    assert(m_enclave_id);
    memset(p_target, 0, sizeof(sgx_target_info_t));
    if(SGX_SUCCESS != sgx_get_target_info(m_enclave_id, p_target))
        return AE_FAILURE;

    if((ae_err = aesm_get_pathname(FT_ENCLAVE_NAME, get_enclave_fid(), enclave_path, MAX_PATH)) != AE_SUCCESS){
        AESM_DBG_ERROR("fail to get PCE pathname");
        return AE_FAILURE;
    }
    if (!get_metadata(enclave_path, &metadata))
        return AE_FAILURE;
    *p_isvsvn = metadata.enclave_css.body.isv_svn;
    return AE_SUCCESS;
}

uint32_t CPCEClass::get_pce_info(const sgx_report_t *p_report,
                    const uint8_t *p_pek,
                    uint32_t pek_size,
                    uint8_t crypto_suite,
                    uint8_t *p_encrypted_ppid,
                    uint32_t encrypted_ppid_size,
                    uint32_t *p_encrypted_ppid_out_size,
                    sgx_isv_svn_t *p_isv_svn,
                    uint16_t *p_pce_id,
                    uint8_t *p_signature_scheme)
{
    sgx_status_t status = SGX_SUCCESS;
    uint32_t ret_val = 0;
    int retry = 0;
    pce_info_t pce_info;
    AESM_PROFILE_FUN;
    if (m_enclave_id == 0){
        AESM_DBG_ERROR("call get_pc_info without loading PCE");
        return AE_FAILURE;
    }
    
    if ((NULL == p_report) || (NULL == p_pek) || (NULL == p_encrypted_ppid) ||
        (NULL == p_encrypted_ppid_out_size) || (NULL == p_isv_svn) ||
        (NULL == p_pce_id) || (NULL == p_signature_scheme))
        return AE_INVALID_PARAMETER;

    status = ::get_pc_info(m_enclave_id, &ret_val, p_report, p_pek, pek_size, crypto_suite, p_encrypted_ppid,
                           encrypted_ppid_size, p_encrypted_ppid_out_size, &pce_info, p_signature_scheme);
    for(; status == SGX_ERROR_ENCLAVE_LOST && retry < AESM_RETRY_COUNT; retry++)
    {
        unload_enclave();
        if(AE_SUCCESS != load_enclave())
            return AE_FAILURE;
        status = ::get_pc_info(m_enclave_id, &ret_val, p_report, p_pek, pek_size, crypto_suite, p_encrypted_ppid,
                               encrypted_ppid_size, p_encrypted_ppid_out_size, &pce_info, p_signature_scheme);
    }
    if(status != SGX_SUCCESS)
        return AE_FAILURE;
    if (ret_val != AE_SUCCESS)
        return ret_val;
    *p_pce_id = pce_info.pce_id;
    *p_isv_svn = pce_info.pce_isvn;
    return AE_SUCCESS;
}

uint32_t CPCEClass::pce_sign_report(const sgx_isv_svn_t *p_isv_svn,
                    const sgx_cpu_svn_t *p_cpu_svn,
                    const sgx_report_t *p_report,
                    uint8_t *p_sig,
                    uint32_t sig_size,
                    uint32_t *p_sig_out_size)
{
    sgx_status_t status = SGX_SUCCESS;
    uint32_t ret_val = 0;
    int retry = 0;
    psvn_t psvn;
    AESM_PROFILE_FUN;
    if (m_enclave_id == 0){
        AESM_DBG_ERROR("call certify_enclave without loading PCE");
        return AE_FAILURE;
    }
    if ((NULL == p_cpu_svn) || (NULL == p_isv_svn) || (NULL == p_report) ||
        (NULL == p_sig) || (NULL == p_sig_out_size))
        return AE_INVALID_PARAMETER;
    
    psvn.cpu_svn = *p_cpu_svn;
    psvn.isv_svn = *p_isv_svn;
    
    status = ::certify_enclave(m_enclave_id, &ret_val, &psvn, p_report, (uint8_t*)p_sig, sig_size, p_sig_out_size);
    for(; status == SGX_ERROR_ENCLAVE_LOST && retry < AESM_RETRY_COUNT; retry++)
    {
        unload_enclave();
        if(AE_SUCCESS != load_enclave())
            return AE_FAILURE;
        status = ::certify_enclave(m_enclave_id, &ret_val, &psvn, p_report, (uint8_t*)p_sig, sig_size, p_sig_out_size);
    }
    if(status != SGX_SUCCESS)
        return AE_FAILURE;
    if(ret_val != AE_SUCCESS){
        return ret_val;
    }
    return AE_SUCCESS;
}
