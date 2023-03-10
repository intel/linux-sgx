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

#include <pce_service.h>

#include <cppmicroservices/BundleActivator.h>
#include <cppmicroservices/BundleContext.h>
#include <cppmicroservices/GetBundleContext.h>
#include "cppmicroservices_util.h"

#include <iostream>
#include "aesm_logic.h"
#include "sgx_pce.h"

using namespace cppmicroservices;

class PceServiceImp : public IPceService
{
private:
    bool initialized;
    AESMLogicMutex pce_mutex;

    ae_error_t pce_error_to_ae_error(sgx_pce_error_t input)
    {
        ae_error_t ret = AE_SUCCESS;
        switch(input)
        {
        case SGX_PCE_SUCCESS:
            ret = AE_SUCCESS;
            break;
        case SGX_PCE_INVALID_PARAMETER:
            ret = AE_INVALID_PARAMETER;
            break;
        case SGX_PCE_INVALID_REPORT:
            ret = PCE_INVALID_REPORT;
            break;
        case SGX_PCE_CRYPTO_ERROR:
            ret = PCE_CRYPTO_ERROR;
            break;
        case SGX_PCE_INVALID_PRIVILEGE:
            ret = PCE_INVALID_PRIVILEGE;
            break;
        case SGX_PCE_OUT_OF_EPC:
            ret = AE_OUT_OF_MEMORY_ERROR;
            break;
        default:
            ret = AE_FAILURE;
            break;
        }
        return ret;
    }

public:
    PceServiceImp():initialized(false){}

    ae_error_t start()
    {
        AESMLogicLock lock(pce_mutex);
        if (initialized == true)
        {
            AESM_DBG_INFO("pce bundle has been started");
            return AE_SUCCESS;
        }
        AESM_DBG_INFO("Starting pce bundle");
        auto context = cppmicroservices::GetBundleContext();

        if (AE_SUCCESS != load_enclave())
        {
            AESM_DBG_INFO("failed to load pce");
            return AE_FAILURE;
        }
        initialized = true;
        AESM_DBG_INFO("pce bundle started");
        return AE_SUCCESS;
    }
    void stop()
    {
        unload_enclave();
        initialized = false;
        AESM_DBG_INFO("pce bundle stopped");
    }

    ae_error_t load_enclave()
    {
        // pce_logic will load PCE on demand
        return AE_SUCCESS;
    }

    void unload_enclave()
    {
        sgx_set_pce_enclave_load_policy(SGX_QL_EPHEMERAL);
    }

    uint32_t pce_get_target(
        sgx_target_info_t *p_target,
        sgx_isv_svn_t *p_isvsvn)
    {
        return pce_error_to_ae_error(sgx_pce_get_target(p_target, p_isvsvn));
    }

    uint32_t get_pce_info(
        const sgx_report_t *p_report,
        const uint8_t *p_pek,
        uint32_t pek_size,
        uint8_t crypto_suite,
        uint8_t *p_encrypted_ppid,
        uint32_t encrypted_ppid_size,
        uint32_t *p_encrypted_ppid_out_size,
        sgx_isv_svn_t* p_pce_isvsvn,
        uint16_t* p_pce_id,
        uint8_t *p_signature_scheme)
    {
        return pce_error_to_ae_error(sgx_get_pce_info(p_report,
                p_pek, pek_size, crypto_suite, p_encrypted_ppid,
                encrypted_ppid_size, p_encrypted_ppid_out_size,
                p_pce_isvsvn, p_pce_id, p_signature_scheme));
    }

    uint32_t pce_sign_report(
        const sgx_isv_svn_t *p_isv_svn,
        const sgx_cpu_svn_t *p_cpu_svn,
        const sgx_report_t *p_report,
        uint8_t *p_sig,
        uint32_t sig_size,
        uint32_t *p_sig_out_size)
    {
        return pce_error_to_ae_error(sgx_pce_sign_report(p_isv_svn,
                p_cpu_svn, p_report, p_sig, sig_size, p_sig_out_size));
    }

};

class Activator : public BundleActivator
{
  void Start(BundleContext ctx)
  {
    auto service = std::make_shared<PceServiceImp>();
    ctx.RegisterService<IPceService>(service);
  }

  void Stop(BundleContext)
  {
    // Nothing to do
  }
};

CPPMICROSERVICES_EXPORT_BUNDLE_ACTIVATOR(Activator)

// [no-cmake]
// The code below is required if the CMake
// helper functions are not used.
#ifdef NO_CMAKE
CPPMICROSERVICES_INITIALIZE_BUNDLE(pce_service_bundle_name)
#endif
