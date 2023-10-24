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

#include "sgx_utls.h"
#include "sgx_utils.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"
#include "sgx_quote_4.h"
#include "cert_header.h"
#include "se_memcpy.h"

#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"

#include <openssl/sha.h>
#include <string.h>

static const char* oid_sgx_quote = X509_OID_FOR_QUOTE_STRING;

extern "C" quote3_error_t sgx_tls_get_qe_target_info_ocall(sgx_target_info_t *p_target_info, size_t target_info_size)
{
    if (p_target_info == NULL || target_info_size != sizeof(sgx_target_info_t))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    return sgx_qe_get_target_info(p_target_info);

}

extern "C" quote3_error_t sgx_tls_get_quote_size_ocall(uint32_t *p_quote_size)
{
    return sgx_qe_get_quote_size(p_quote_size);
}

extern "C" quote3_error_t sgx_tls_get_quote_ocall(sgx_report_t* p_report, size_t report_size, uint8_t *p_quote, uint32_t quote_size)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    uint32_t tmp_quote_size = 0;

    if (p_report == NULL || p_quote == NULL || report_size != sizeof(sgx_report_t))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        //Use DCAP quote generation in-proc mode by default
        ret = sgx_qe_get_quote_size(&tmp_quote_size);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }

        if (tmp_quote_size != quote_size) {
            ret = SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_qe_get_quote(p_report, quote_size, p_quote);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }

        ret = SGX_QL_SUCCESS;

    } while(0);

    return ret;
}

extern "C" quote3_error_t sgx_tls_get_supplemental_data_size_ocall(uint32_t *p_supplemental_data_size)
{
    return sgx_qv_get_quote_supplemental_data_size(p_supplemental_data_size);
}

extern "C" quote3_error_t sgx_tls_verify_quote_ocall(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t expiration_check_date,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    size_t qve_report_info_size,
    uint8_t *p_supplemental_data,
    uint32_t supplemental_data_size)
{
    uint32_t collateral_expiration_status = 1;


    if (p_quote == NULL ||
        p_quote_verification_result == NULL ||
        p_supplemental_data == NULL ||
        (p_qve_report_info == NULL && qve_report_info_size != 0) ||
        (p_qve_report_info != NULL && qve_report_info_size <= 0))
        return SGX_QL_ERROR_INVALID_PARAMETER;

     return sgx_qv_verify_quote(
                p_quote,
                quote_size,
                NULL,
                expiration_check_date,
                &collateral_expiration_status,
                p_quote_verification_result,
                p_qve_report_info,
                supplemental_data_size,
                p_supplemental_data);
}

extern "C" quote3_error_t tee_verify_certificate_with_evidence_host(
    const uint8_t *p_cert_in_der,
    size_t cert_in_der_len,
    const time_t expiration_check_date,
    sgx_ql_qv_result_t *p_qv_result,
    uint8_t **pp_supplemental_data,
    uint32_t *p_supplemental_data_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t func_ret = SGX_QL_ERROR_UNEXPECTED;
    uint8_t *p_quote = NULL;
    uint32_t quote_size = 0;
    uint8_t *p_cbor_evidence = NULL;
    uint32_t cbor_evidence_size = 0;
    sgx_cert_t cert = {0};
    uint8_t *pub_key_buff = NULL;
    size_t pub_key_buff_size = KEY_BUFF_SIZE;

    if (p_cert_in_der == NULL ||
        p_qv_result == NULL ||
        pp_supplemental_data == NULL ||
        p_supplemental_data_size == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        //verify X.509 certificate
        pub_key_buff = (uint8_t*)malloc(KEY_BUFF_SIZE);
        if (!pub_key_buff) {
            func_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }
        memset(pub_key_buff, 0, KEY_BUFF_SIZE);

        try {
            ret = sgx_read_cert_in_der(&cert, p_cert_in_der, cert_in_der_len);
            if (ret != SGX_SUCCESS)
                break;

            // validate the certificate signature
            ret = sgx_cert_verify(&cert, NULL, NULL, 0);
            if (ret != SGX_SUCCESS)
                break;

            ret = sgx_get_pubkey_from_cert(&cert, pub_key_buff, &pub_key_buff_size);
            if (ret != SGX_SUCCESS) {
                func_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }

            p_quote = (uint8_t*)malloc(RAW_QUOTE_MAX_SIZE);
            if (!p_quote) {
                func_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }

            p_cbor_evidence = (uint8_t*)malloc(CBOR_QUOTE_MAX_SIZE);
            if (!p_cbor_evidence) {
                func_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }
            
            if (sgx_cert_find_extension(
                &cert,
                g_evidence_oid,
                p_cbor_evidence,
                &cbor_evidence_size) == SGX_SUCCESS)
            {
                if (cbor_evidence_size > CBOR_QUOTE_MAX_SIZE)
                {
                    // buffer overflow, return error
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
                // if tcg tagged evidence oid found, extract it here
                ret = extract_cbor_evidence_and_compare_hash(p_cbor_evidence, cbor_evidence_size,
                            pub_key_buff, pub_key_buff_size,
                            p_quote, &quote_size);
                if (ret != SGX_SUCCESS)
                {
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
            }
            else if (sgx_cert_find_extension(
                    &cert,
                    oid_sgx_quote,
                    p_quote,
                    &quote_size) == SGX_SUCCESS)
           {
                // if no tcg tagged evidence oid found, try to find the legacy
                // oid
                if (quote_size > RAW_QUOTE_MAX_SIZE)
                {
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
                ret = sgx_tls_compare_quote_hash(p_quote,
                            pub_key_buff, pub_key_buff_size);
                if (ret != SGX_SUCCESS){
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
            }
            else
            {
                func_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }
        }
        catch (...) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        // check supplemental data
        func_ret = sgx_tls_get_supplemental_data_size_ocall(p_supplemental_data_size);
        if (func_ret != SGX_QL_SUCCESS) {
            break;
        }

        *pp_supplemental_data = (uint8_t *) malloc (*p_supplemental_data_size);
        if (*pp_supplemental_data == NULL) {
            func_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }

        func_ret = sgx_tls_verify_quote_ocall (p_quote,
                                    quote_size,
                                    expiration_check_date,
                                    p_qv_result,
                                    NULL,
                                    0,
                                    *pp_supplemental_data,
                                    *p_supplemental_data_size);

        if (func_ret != SGX_QL_SUCCESS)
            break;
    } while(0);

    SGX_TLS_SAFE_FREE(pub_key_buff);
    SGX_TLS_SAFE_FREE(p_quote);
    SGX_TLS_SAFE_FREE(p_cbor_evidence);

    if (func_ret != SGX_QL_SUCCESS)
        SGX_TLS_SAFE_FREE(*pp_supplemental_data);

    return func_ret;
}

extern "C" quote3_error_t tee_free_supplemental_data_host(uint8_t* p_supplemental_data)
{
    SGX_TLS_SAFE_FREE(p_supplemental_data);
    return SGX_QL_SUCCESS;
}
