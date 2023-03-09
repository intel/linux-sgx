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

#ifndef EPID_QUOTE_SERVICE_EXPORT_H
#define EPID_QUOTE_SERVICE_EXPORT_H
#include "quote_service.h"
#include "aesm_error.h"
#include "aeerror.h"
#include "es_info.h"
#include "tlv_common.h"
#include "platform_info_blob.h"


struct IEpidQuoteService : public IQuoteService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 2};
    virtual ~IEpidQuoteService() = default;

    virtual aesm_error_t get_extended_epid_group_id(
        uint32_t* x_group_id) = 0;
    virtual aesm_error_t switch_extended_epid_group(
        uint32_t x_group_id) = 0;
    virtual uint32_t endpoint_selection(
        endpoint_selection_infos_t& es_info) = 0;
    virtual ae_error_t need_epid_provisioning(
        const platform_info_blob_wrapper_t* p_platform_info_blob) = 0;
    virtual aesm_error_t provision(
        bool performance_rekey_used,
        uint32_t timeout_usec) = 0;
    virtual const char *get_server_url(
        aesm_network_server_enum_type_t type) = 0;
    virtual const char *get_pse_provisioning_url(
        const endpoint_selection_infos_t& es_info) = 0;
    virtual aesm_error_t report_attestation_status(
        uint8_t* platform_info, uint32_t platform_info_size,
        uint32_t attestation_status,
        uint8_t* update_info, uint32_t update_info_size) = 0;
    
    virtual aesm_error_t check_update_status(
        uint8_t* platform_info, uint32_t platform_info_size,
        uint8_t* update_info, uint32_t update_info_size,
        uint32_t attestation_status, uint32_t* status) = 0;        
};

#endif /* EPID_QUOTE_SERVICE_EXPORT_H */
