/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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


#include "PSEPRClass.h"
#include "pseop_service.h"
#include <cstddef>

#include "upse.h"
#include "oal/oal.h"

#include "cppmicroservices/BundleContext.h"
#include <cppmicroservices/GetBundleContext.h>
using namespace cppmicroservices;
extern std::shared_ptr<IPseopService> g_pseop_service;

CPSEPRClass::CPSEPRClass():m_is_sigma20_supported(false) {

    if(!g_pseop_service){
        AESM_DBG_ERROR("failed to load pseop service");
        return;
    }
    else
        m_is_sigma20_supported = g_pseop_service->PSDA_is_sigma20_supported();
}


void CPSEPRClass::before_enclave_load() {
    if(!g_pseop_service){
        AESM_DBG_ERROR("failed to load pseop service");
        return;
    }
    else
        g_pseop_service->unload_enclave();
}

ae_error_t CPSEPRClass::certificate_provisioning(platform_info_blob_wrapper_t* pib_wrapper)
{
    ae_error_t status = AE_FAILURE;
    AESM_DBG_TRACE("enter fun");

    do
    {
        if ((status = CPSEPRClass::instance().load_enclave()) != AE_SUCCESS)
            break;

        status = upse_certificate_provisioning(m_enclave_id, pib_wrapper);

    } while (0);

    CPSEPRClass::instance().unload_enclave();


    return status;
}

ae_error_t CPSEPRClass::long_term_pairing(bool* p_new_pairing)
{
    ae_error_t status = AE_FAILURE;
    AESM_DBG_TRACE("enter fun");

    do
    {
        if ((status = CPSEPRClass::instance().load_enclave()) != AE_SUCCESS)
            break;

        status = upse_long_term_pairing(m_enclave_id, p_new_pairing);

    } while (0);

    CPSEPRClass::instance().unload_enclave();

    if(!g_pseop_service){
        AESM_DBG_ERROR("failed to load pseop service");
    }
    else
        g_pseop_service->save_psda_capability();

    return status;
}
