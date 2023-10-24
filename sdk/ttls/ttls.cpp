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

#include "sgx_ttls.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "sgx_quote_3.h"
#include "sgx_quote_4.h"
#include "cert_header.h"
#include "sgx_dcap_tvl.h"
#include <string.h>
#include <sgx_trts.h>

#include "sgx_ttls_t.h"

#include "cbor.h"
#include <openssl/pem.h>


#ifdef TDX_ENV
#include <openssl/sha.h>
#include "tdx_attest.h"
#endif

static const char* oid_sgx_quote = X509_OID_FOR_QUOTE_STRING;

//The ISVSVN threshold of Intel signed QvE
const sgx_isv_svn_t qve_isvsvn_threshold = 7;

#ifdef TDX_ENV
quote3_error_t tdx_attest_to_sgx_ql_error(tdx_attest_error_t err) {
    switch (err) {
        case TDX_ATTEST_ERROR_INVALID_PARAMETER:
            return SGX_QL_ERROR_INVALID_PARAMETER;
        case TDX_ATTEST_ERROR_OUT_OF_MEMORY:
            return SGX_QL_ERROR_OUT_OF_MEMORY;
        default:
            return SGX_QL_ERROR_UNEXPECTED;
    }
}
#endif

sgx_status_t cbor_bstr_from_pk_sha(const uint8_t *pub_key, size_t key_len, cbor_item_t** hash)
{
    uint8_t pk_sha[SHA512_DIGEST_LENGTH] = {0}; // big enough to hold hash for different algo
    uint8_t pk_der[PUB_KEY_MAX_SIZE] = {0};
    size_t pk_der_size_byte = 0;
    uint8_t *temp_sha = NULL;
    size_t sha_len = 0;
    uint8_t *ret_sha = NULL;

    memset(pk_der, 0x00, PUB_KEY_MAX_SIZE);
    if (PEM2DER_PublicKey_converter(pub_key, key_len, pk_der, &pk_der_size_byte))
      return SGX_ERROR_UNEXPECTED;
#ifndef TDX_ENV
    ret_sha = SHA256(pk_der, pk_der_size_byte, pk_sha);
    sha_len = SHA256_DIGEST_LENGTH;

    if (ret_sha == NULL || memcmp(ret_sha, pk_sha, SHA256_DIGEST_LENGTH)!=0)
        return SGX_ERROR_UNEXPECTED;

#else // for TDX, need to use sha384 
    ret_sha = SHA384(pk_der, pk_der_size_byte, pk_sha);
    sha_len = SHA384_DIGEST_LENGTH;

    if (ret_sha == NULL || memcmp(ret_sha, pk_sha, SHA384_DIGEST_LENGTH)!=0)
        return SGX_ERROR_UNEXPECTED;
#endif

    temp_sha = (uint8_t*)malloc(sha_len);
    if (temp_sha == NULL) return SGX_ERROR_OUT_OF_MEMORY;

    memcpy(temp_sha, pk_sha, sha_len);
    cbor_item_t* cbor_bstr = cbor_build_bytestring(temp_sha, sha_len);

    free(temp_sha);
    if (!cbor_bstr)
        return SGX_ERROR_OUT_OF_MEMORY;

    *hash = cbor_bstr;
    return SGX_SUCCESS;
}

sgx_status_t generate_cbor_pkhash_entry(const uint8_t *p_pub_key, size_t key_size,
            uint8_t **out_hash_entry_buf,
            size_t *out_hash_entry_buf_size)
{
    cbor_item_t* cbor_hash_entry = cbor_new_definite_array(2);
    if (!cbor_hash_entry)
        return SGX_ERROR_OUT_OF_MEMORY;

#ifndef TDX_ENV
    /* SGX : RA-TLS always generates SHA256 hash over pubkey */
    cbor_item_t* cbor_hash_alg_id = cbor_build_uint8(IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256);
    if (!cbor_hash_alg_id) {
        cbor_decref(&cbor_hash_entry);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
#else
    /* TDX : for RA-TLS always generates SHA384 hash over pubkey */
    cbor_item_t* cbor_hash_alg_id = cbor_build_uint8(IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384);
    if (!cbor_hash_alg_id) {
        cbor_decref(&cbor_hash_entry);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
#endif
    cbor_item_t* cbor_hash_value;
    sgx_status_t ret = cbor_bstr_from_pk_sha(p_pub_key, key_size, &cbor_hash_value);
    if (ret < 0) {
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return ret;
    }

    int bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_alg_id);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_value);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    /* cbor_hash_entry took ownership of hash_alg_id and hash_value cbor items */
    cbor_decref(&cbor_hash_alg_id);
    cbor_decref(&cbor_hash_value);

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    /* for the serialize_alloced buf, we need to free it seperately, as the pointer */
    /* passed to outside invoker, free it in outside invoker */
    cbor_serialize_alloc(cbor_hash_entry, &hash_entry_buf, &hash_entry_buf_size);

    cbor_decref(&cbor_hash_entry);

    if (!hash_entry_buf)
        return SGX_ERROR_OUT_OF_MEMORY;

    *out_hash_entry_buf = hash_entry_buf;
    *out_hash_entry_buf_size = hash_entry_buf_size;
    return SGX_SUCCESS;
}

sgx_status_t generate_cbor_claims(const uint8_t *p_pub_key,
            size_t pub_key_size,
            uint8_t **out_claims_buf,
            size_t *out_claims_buf_size)
{
    /* currentl implement only claim "pubkey-hash", but there may be more "e.g. nonce" */
    cbor_item_t* cbor_claims = cbor_new_definite_map(1);
    if (!cbor_claims)
        return SGX_ERROR_OUT_OF_MEMORY;

    cbor_item_t* cbor_pubkey_hash_key = cbor_build_string("pubkey-hash");
    if (!cbor_pubkey_hash_key) {
        cbor_decref(&cbor_claims);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    int ret = generate_cbor_pkhash_entry(p_pub_key, pub_key_size, &hash_entry_buf, &hash_entry_buf_size);
    if (ret < 0) {
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return SGX_ERROR_UNEXPECTED;
    }

    cbor_item_t* cbor_pubkey_hash_val = cbor_build_bytestring(hash_entry_buf, hash_entry_buf_size);

    free(hash_entry_buf);

    if (!cbor_pubkey_hash_val) {
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    struct cbor_pair cbor_pubkey_hash_pair = { .key = cbor_pubkey_hash_key,
                                               .value = cbor_pubkey_hash_val };
    bool bool_ret = cbor_map_add(cbor_claims, cbor_pubkey_hash_pair);
    if (!bool_ret) {
        cbor_decref(&cbor_pubkey_hash_val);
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    /* for the serialize_alloced buf, we need to free it seperately, as the pointer */
    /* passed to outside invoker, free it in outside invoker */
    uint8_t* claims_buf;
    size_t claims_buf_size;
    cbor_serialize_alloc(cbor_claims, &claims_buf, &claims_buf_size);

    cbor_decref(&cbor_pubkey_hash_val);
    cbor_decref(&cbor_pubkey_hash_key);
    cbor_decref(&cbor_claims);

    if (!claims_buf)
        return SGX_ERROR_OUT_OF_MEMORY;

    *out_claims_buf = claims_buf;
    *out_claims_buf_size = claims_buf_size;
    return SGX_SUCCESS;
}

sgx_status_t generate_cbor_evidence(uint8_t *quote, size_t quote_size,
            uint8_t *claim, size_t claim_size,
            uint8_t **out_evidence, size_t *evidence_size)
{
    cbor_item_t* cbor_evidence = cbor_new_definite_array(2);
    if (!cbor_evidence)
        return SGX_ERROR_OUT_OF_MEMORY;

    cbor_item_t* cbor_quote = cbor_build_bytestring(quote, quote_size);
    if (!cbor_quote) {
        cbor_decref(&cbor_evidence);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    cbor_item_t* cbor_claims = cbor_build_bytestring(claim, claim_size);
    if (!cbor_claims) {
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    int bool_ret = cbor_array_push(cbor_evidence, cbor_quote);
    if (!bool_ret) {
        cbor_decref(&cbor_claims);
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    bool_ret = cbor_array_push(cbor_evidence, cbor_claims);
    if (!bool_ret) {
        cbor_decref(&cbor_claims);
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    /* cbor_evidence took ownership of quote and claims cbor bstrs */
    cbor_decref(&cbor_claims);
    cbor_decref(&cbor_quote);

    cbor_item_t* cbor_tagged_evidence = cbor_new_tag(TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG);
    if (!cbor_tagged_evidence) {
        cbor_decref(&cbor_evidence);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    cbor_tag_set_item(cbor_tagged_evidence, cbor_evidence);

    uint8_t* evidence_buf;
    size_t evidence_buf_size;
    cbor_serialize_alloc(cbor_tagged_evidence, &evidence_buf, &evidence_buf_size);

    cbor_decref(&cbor_evidence);
    cbor_decref(&cbor_tagged_evidence);

    if (!evidence_buf)
        return SGX_ERROR_OUT_OF_MEMORY;

    *out_evidence = evidence_buf;
    *evidence_size = evidence_buf_size;
    return SGX_SUCCESS;
}

extern "C" quote3_error_t tee_get_certificate_with_evidence(
    const unsigned char *p_subject_name,
    const uint8_t *p_prv_key,
    size_t private_key_size,
    const uint8_t *p_pub_key,
    size_t public_key_size,
    uint8_t **pp_output_cert,
    size_t *p_output_cert_size)
{
#ifndef TDX_ENV
    sgx_report_t app_report;
    sgx_target_info_t target_info;
    sgx_report_data_t report_data = { 0 };
#else
    tdx_attest_error_t tdx_ret = TDX_ATTEST_ERROR_UNEXPECTED;
    tdx_uuid_t selected_att_key_id = { 0 };
    tdx_report_data_t report_data = { 0 };
#endif
    uint8_t* claims = NULL;
    size_t claims_size;

    uint8_t* p_evidence = NULL;
    size_t evidence_size;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t func_ret = SGX_QL_ERROR_UNEXPECTED;
    uint8_t *p_quote = NULL;
    uint32_t quote_size = 0;

    if (p_subject_name == NULL ||
        p_prv_key == NULL || private_key_size <= 0 ||
        p_pub_key == NULL || public_key_size <= 0 ||
        pp_output_cert == NULL || p_output_cert_size == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    // only support PEM format key
    if (strnlen(reinterpret_cast<const char*>(p_pub_key), public_key_size) != public_key_size - 1 ||
        strnlen(reinterpret_cast<const char*>(p_prv_key), private_key_size) != private_key_size -1)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        // first need to get cbor claims through pub_key
        ret = generate_cbor_claims(p_pub_key, public_key_size, &claims, &claims_size);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

#ifndef TDX_ENV
        if (!SHA256(claims, claims_size, reinterpret_cast<unsigned char *>(&report_data)))
        {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //OCALL to get target info of QE
        ret = sgx_tls_get_qe_target_info_ocall(&func_ret, &target_info, sizeof(sgx_target_info_t));
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (func_ret != SGX_QL_SUCCESS)
            break;

        ret = sgx_create_report(&target_info, &report_data, &app_report);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //OCALL to get quote size
        ret = sgx_tls_get_quote_size_ocall(&func_ret, &quote_size);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (func_ret != SGX_QL_SUCCESS)
            break;

        p_quote = (uint8_t *) malloc (quote_size);
        if (p_quote == NULL) {
            func_ret = SGX_QL_OUT_OF_EPC;
            break;
        }
        memset (p_quote, 0, quote_size);

        //OCALL to get quote
        ret = sgx_tls_get_quote_ocall(&func_ret, &app_report, sizeof(app_report), p_quote, quote_size);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (func_ret != SGX_QL_SUCCESS)
            break;


#else
        if (!SHA384(claims, claims_size, reinterpret_cast<unsigned char *>(&report_data)))
        {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        tdx_ret = tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &p_quote, &quote_size, 0);
        if (tdx_ret != TDX_ATTEST_SUCCESS) {
            func_ret = tdx_attest_to_sgx_ql_error(tdx_ret);
            break;
        }
#endif
        // after generating quote, generating cbor evidence
        ret = generate_cbor_evidence(p_quote, quote_size, claims, claims_size, &p_evidence,
                    &evidence_size);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        
        // generate self-signed X.509 certificate
        // Make SGX quote as an extension
        // Make cbor formalized quote as an extension
        ret = generate_x509_self_signed_certificate(
            (const unsigned char*) oid_sgx_quote,
            strlen(oid_sgx_quote),
            (const unsigned char*) g_evidence_oid,
            (size_t)strlen((const char*)g_evidence_oid),
            p_subject_name,
            p_prv_key,
            private_key_size,
            p_pub_key,
            public_key_size,
            p_quote,
            quote_size,
            p_evidence,
            evidence_size,
            pp_output_cert,
            p_output_cert_size);

        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        func_ret = SGX_QL_SUCCESS;

    } while (0);

    SGX_TLS_SAFE_FREE(p_quote);
    
    /* claims and p_evidece are allocated by cbor_serialize_alloc function */
    /* its default alloc mechanism is by standard lib malloc, realloc, free*/
    /* so do not forget to free them here */
    SGX_TLS_SAFE_FREE(claims);
    SGX_TLS_SAFE_FREE(p_evidence);

    return func_ret;
}

extern "C" quote3_error_t tee_free_certificate(uint8_t* p_certificate)
{
    SGX_TLS_SAFE_FREE(p_certificate);
    return SGX_QL_SUCCESS;
}

#ifndef TDX_ENV
extern "C" quote3_error_t tee_verify_certificate_with_evidence(
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
    sgx_ql_qe_report_info_t qve_report_info;
    uint32_t collateral_expiration_status = 0;
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
            func_ret = SGX_QL_OUT_OF_EPC;
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

            // first find cbor evidence here
            if (sgx_cert_find_extension(
                &cert,
                g_evidence_oid,
                p_cbor_evidence,
                &cbor_evidence_size) == SGX_SUCCESS)
            {
                if (cbor_evidence_size > CBOR_QUOTE_MAX_SIZE)
                {
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
                ret = extract_cbor_evidence_and_compare_hash(p_cbor_evidence, cbor_evidence_size,
                            pub_key_buff, pub_key_buff_size, p_quote, &quote_size);
                if (ret != SGX_SUCCESS)
                {
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
            }
            // otherwise, try to find legacy sgx oid
            else if (sgx_cert_find_extension(
                    &cert,
                    oid_sgx_quote,
                    p_quote,
                    &quote_size) == SGX_SUCCESS)
            {
                if (quote_size > RAW_QUOTE_MAX_SIZE)
                {
                    func_ret = SGX_QL_ERROR_UNEXPECTED;
                    break;
                }
                ret = sgx_tls_compare_quote_hash(p_quote,
                            pub_key_buff, pub_key_buff_size);
                if (ret != SGX_SUCCESS)
                {
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

        //OCALL to get supplemental data size
        ret = sgx_tls_get_supplemental_data_size_ocall(&func_ret, p_supplemental_data_size);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (func_ret != SGX_QL_SUCCESS)
            break;

        *pp_supplemental_data = (uint8_t *) malloc (*p_supplemental_data_size);
        if (*pp_supplemental_data == NULL) {
            func_ret = SGX_QL_OUT_OF_EPC;
            break;
        }

        ret = sgx_read_rand(reinterpret_cast<unsigned char *> (&qve_report_info.nonce), sizeof(sgx_quote_nonce_t));
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        ret = sgx_self_target(&qve_report_info.app_enclave_target_info);
        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }

        //OCALL to verify SGX quote
        ret = sgx_tls_verify_quote_ocall(
            &func_ret,
            p_quote,
            quote_size,
            expiration_check_date,
            p_qv_result,
            &qve_report_info,
            sizeof(sgx_ql_qe_report_info_t),
            *pp_supplemental_data,
            *p_supplemental_data_size);

        if (ret != SGX_SUCCESS) {
            func_ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (func_ret != SGX_QL_SUCCESS)
            break;

        //call TVL API to verify the idenity of Intel signed QvE
        func_ret = sgx_tvl_verify_qve_report_and_identity(
            p_quote,
            quote_size,
            &qve_report_info,
            expiration_check_date,
            collateral_expiration_status,
            *p_qv_result,
            *pp_supplemental_data,
            *p_supplemental_data_size,
            qve_isvsvn_threshold);

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

extern "C" quote3_error_t tee_free_supplemental_data(uint8_t* p_supplemental_data)
{
    SGX_TLS_SAFE_FREE(p_supplemental_data);
    return SGX_QL_SUCCESS;
}
#endif
