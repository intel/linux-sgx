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

#ifndef _SGX_UAE_SERVICE_H_
#define _SGX_UAE_SERVICE_H_

#include <stdint.h>

#include "sgx_quote.h"
#include "sgx_error.h"
#include "sgx_urts.h"

#define PS_CAP_TRUSTED_TIME         0x1
#define PS_CAP_MONOTONIC_COUNTER    0x2

/**
 * Platform service capabilities
 *      ps_cap0
 *       Bit 0 : Trusted Time
 *       Bit 1 : Monotonic Counter
 *       Bit 2-31 : Reserved
 *      ps_cap1 
 *       Bit 0-31 : Reserved
 */
typedef struct _sgx_ps_cap_t
{
    uint32_t ps_cap0;
    uint32_t ps_cap1;
} sgx_ps_cap_t;

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Function used to initialize the process of quoting.
 *
 * @param p_target_info[out] Target info of quoting enclave.
 * @param p_gid[out] ID of platform's current EPID group.
 * @return If outputs are generated, return SGX_SCCUESS, otherwise return general error code
 *             or SGX_ERROR_AE_INVALID_EPIDBLOB to indicate special error condition.
 */
sgx_status_t SGXAPI sgx_init_quote(
    sgx_target_info_t *p_target_info,
    sgx_epid_group_id_t *p_gid);


/*
 * Function used to calculate quote size.
 *
 * @param p_sig_rl[in] OPTIONAL Signature Revocation List.
 * @param sig_rl_size[in] Signature Revocation List size, in bytes.
 * @param p_quote_size[out] Quote size, in bytes.
 * @return If quote size is calculated,return SGX_SUCCESS, otherwise return
 *            SGX_ERROR_INVALID_PARAMETER to indicate special error condition.
 */
sgx_status_t SGXAPI sgx_calc_quote_size(
    const uint8_t *p_sig_rl,
    uint32_t sig_rl_size,
    uint32_t* p_quote_size);

/*
 * [DEPRECATED] Use sgx_calc_quote_size function instead of this one
 * Function used to get quote size.
 *
 * @param p_sig_rl[in] OPTIONAL Signature Revocation List.
 * @param p_quote_size[out] Quote size, in bytes.
 * @return If quote size is calculated,return SGX_SCCUESS, otherwise return
 *            SGX_ERROR_INVALID_PARAMETER to indicate special error condition.
 */
SGX_DEPRECATED
sgx_status_t SGXAPI sgx_get_quote_size(
    const uint8_t *p_sig_rl,
    uint32_t* p_quote_size);

/*
 * Function used to get quote.
 *
 * @param p_report[in] Report of enclave for which quote is being calculated.
 * @param quote_type[in] Linkable or unlinkable quote.
 * @param p_spid[in] Pointer of SPID.
 * @param p_nonce[in] OPTIONAL nonce.
 * @param p_sig_rl[in] OPTIONAL list of signature made fore EPID.
 * @param sig_rl_size[in] The size of p_sig_rl, in bytes.
 * @param p_qe_report[out] OPTIONAL The QE report.
 * @param p_quote[out] The quote buffer, can not be NULL.
 * @param quote_size[in] Quote buffer size, in bytes.
 * @return If quote is generated,return SGX_SCCUESS,
 *         error code or SGX_ERROR_AE_INVALID_EPIDBLOB,
 *         SGX_ERROR_INVALID_PARAMETER to indicate special error condition.
 *         SGX_ERROR_EPID_MEMBER_REVOKED to indicate the EPID group membership has been revoked.
 */
sgx_status_t SGXAPI sgx_get_quote(
    const sgx_report_t *p_report,
    sgx_quote_sign_type_t quote_type,
    const sgx_spid_t *p_spid,
    const sgx_quote_nonce_t *p_nonce,
    const uint8_t *p_sig_rl,
    uint32_t sig_rl_size,
    sgx_report_t *p_qe_report,
    sgx_quote_t *p_quote,
    uint32_t quote_size);

/**
 * Get the platform service capabilities
 *
 * @param sgx_ps_cap Platform capabilities reported by AESM.
 * @return if OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_get_ps_cap(sgx_ps_cap_t* p_sgx_ps_cap);

/**
 * Get the white list's size
 *
 * @param p_whitelist_size Save the size of the white list.
 * @return if OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_get_whitelist_size(uint32_t* p_whitelist_size);

/**
 * Get the white list value
 *
 * @param p_whitelist Save the white list value
 * @param whitelist_size The size of the white list and the read data size is whitelist_size
 * @return if OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_get_whitelist(uint8_t* p_whitelist, uint32_t whitelist_size);

/**
 * Get the extended epid group id
 *
 * @param p_extended_epid_group_id Save the extended epid group id.
 * @return if OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_get_extended_epid_group_id(uint32_t* p_extended_epid_group_id);

#define SGX_IS_TRUSTED_TIME_AVAILABLE(cap)           ((((uint32_t)PS_CAP_TRUSTED_TIME)&((cap).ps_cap0))!=0)
#define SGX_IS_MONOTONIC_COUNTER_AVAILABLE(cap)      ((((uint32_t)PS_CAP_MONOTONIC_COUNTER)&((cap).ps_cap0))!=0)

/*
 * Function used to report the status of the attestation.
 *
 * @param p_platform_info[in] platform information received from Intel Attestation Server.
 * @param attestation_status[in] Value representing status during attestation. 0 if attestation succeeds. 
 * @param p_update_info[out] update information of the SGX platform.
 * @return If OK, return SGX_SUCCESS. If update is needed, return SGX_ERROR_UPDATE_NEEDED and update_info contains update information.
 */

sgx_status_t SGXAPI sgx_report_attestation_status(
    const sgx_platform_info_t* p_platform_info,
    int attestation_status,
    sgx_update_info_bit_t* p_update_info);

/**
 * Register white list certificate chain
 *
 * @param p_wl_cert_chain The white list to be registered.
 * @param wl_cert_chain_size The size of the white list.
 * @return If OK, return SGX_SUCCESS
 */
sgx_status_t SGXAPI sgx_register_wl_cert_chain(uint8_t* p_wl_cert_chain, uint32_t wl_cert_chain_size);

/** 
 * Function used to select the attestation key from the list provided by the off-platform Quote verifier.
 *  
 * @param p_att_key_id_list [In] List of the supported attestation key IDs provided by the quote verifier. Can not be 
 *                          NULL. it will use the p_att_key_id_list and compare it with the
 *                          supported values.
 * @param att_key_id_list_size The size of attestation key ID list.
 * @param pp_selected_key_id [In, Out] Pointer to the selected attestation key in the list. This should be used by the 
 *                           application as input to the quoting and remote attestation APIs.  Must not be NULL.  Note,
 *                           it will point to one of the entries in the p_att_key_id_list and the application must copy
 *                           it if the memory for p_att_key_id_list will not persist for future quoting APIs calls.
 *  
 * @return SGX_SUCCESS Successfully selected an attestation key.  The pp_selected_key_id will point an entry in the 
 *         p_att_key_id_list.
 * @return SGX_ERROR_INVALID_PARAMETER  Invalid parameter if p_att_key_id_list, pp_selected_key_id is NULL,
 *         list header is incorrect, or the number of key IDs in the list exceed the maximum.
 * @return SGX_ERROR_UNSUPPORTED_ATT_KEY_ID The platform quoting infrastructure does not support any of the keys in the
 *         list.  This can be because it doesn't carry the QE that owns the attestation key or the platform is in a
 *         mode that doesn't allow any of the listed keys; for example, for privacy reasons.
 * @return SGX_ERROR_UNEXPECTED Unexpected internal error.
 */
sgx_status_t SGXAPI sgx_select_att_key_id(const uint8_t *p_att_key_id_list, uint32_t att_key_id_list_size,
                                                   sgx_att_key_id_t **pp_selected_key_id);



/**
 * The application calls this API to request the selected platform's attestation key owner to generate or obtain
 * the attestation key.  Once called, the QE that owns the attestation key described by the inputted attestation 
 * key id will do what is required to get this platform’s attestation including getting any certification data 
 * required from the PCE.  Depending on the type of attestation key and the attestation key owner, this API will
 * return the same attestation key public ID or generate a new one.  The caller can request that the attestation
 * key owner "refresh" the key.  This will cause the owner to either re-get the key or generate a new one.  The
 * platform's attestation key owner is expected to store the key in persistent memory and use it in the
 * subsequent quote generation APIs described below. 
 *  
 * In an environment where attestation key provisioning and certification needs to take place during a platform 
 * deployment phase, an application can generate the attestation key, certify it with the PCK Cert and register 
 * it with the attestation owners cloud infrastructure.  That way, the key is available during the run time 
 * phase to generate code without requiring re-certification. 
 *  
 * The QE's target info is also returned by this API that will allow the application's enclave to generate a 
 * REPORT that the attestation key owner's QE can verify using local REPORT-based attestation when generating a 
 * quote. 
 *  
 * In order to allow the application to allocate the public key id buffer first, the application can call this 
 * function with the p_pub_key_id set to NULL and the p_pub_key_id_size to a valid size_t pointer.  In this 
 * case, the function will return the required buffer size to contain the p_pub_key_id_size and ignore the other 
 * parameters.  The application can then call this API again with the correct p_pub_key_size and the pointer to 
 * the allocated buffer in p_pub_key_id. 
 *  
 * 
 * @param p_att_key_id The selected att_key_id from the quote verifier's list.  It includes the QE identity as 
 *                     well as the attestation key's algorithm type. It cannot be NULL.
 * @param p_qe_target_info Pointer to QE's target info required by the application to generate an enclave REPORT
 *                         targeting the selected QE.  Must not be NULL when p_pub_key_id is not NULL.
 * @param refresh_att_key A flag indicating the attestation key owner should re-generated and certify or 
 *                        otherwise attempt to re-provision the attestation key.  For example, for ECDSDA, the
 *                        platform will generate a new key and request the PCE to recertify it.  For EPID, the
 *                        platform will attempt to re-provision the EPID key.  The behavior is dependent on the
 *                        key type and the key owner, but it should make an attempt to refresh the key typically
 *                        to update the key to the current platform's TCB.
 * @param p_pub_key_id_size This parameter can be used in 2 ways.  When p_pub_key_id is NULL, the API will 
 *                          return the buffer size required to hold the attestation's public key ID.  The
 *                          application can then allocate the buffer and call it again with p_pub_key_id not set
 *                          to NULL and the other parameters valid.  If p_pub_key_id is not NULL, p_pub_key_size
 *                          must be large enough to hold the return attestation's public key ID.  Must not be
 *                          NULL.
 * @param p_pub_key_id This parameter can be used in 2 ways. When it is passed in as NULL and p_pub_key_id_size
 *                     is not NULL, the API will return the buffer size required to hold the attestation's
 *                     public key ID.  The other parameters will be ignored.  When it is not NULL, it must point
 *                     to a buffer which is at least a long as the value passed in by p_pub_key_id.  Can either
 *                     be NULL or point to the correct buffer.his will point to the buffer that will contain the
 *                     attestation key's public identifier. If first called with a NULL pointer, the API will
 *                     return the required length of the buffer in p_pub_key_id_size.

 * @return SGX_SUCCESS Successfully selected an attestation key.  Either returns the required attestation's 
 *         public key ID size in p_pub_key_id_size when p_pub_key_id is passed in as NULL.  When p_pub_key_id is
 *         not NULL, p_qe_target_info will contain the attestation key's QE target info for REPORT generation
 *         and p_pub_key_id will contain the attestation's public key ID.
 * @return SGX_ERROR_INVALID_PARAMETER Invalid parameter if p_pub_key_id_size, p_att_key_id is NULL.
 *         If p_pub_key_size is not NULL, the other parameters must be valid.
 * @return SGX_ERROR_UNSUPPORTED_ATT_KEY_ID The platform quoting infrastructure does not support the key described 
 *         in p_att_key_id.
 * @return SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE Failed to generate and certify the attestation key. 
 *  
 */  
sgx_status_t SGXAPI sgx_init_quote_ex(const sgx_att_key_id_t* p_att_key_id,
                                            sgx_target_info_t *p_qe_target_info,
                                            bool refresh_att_key,
                                            size_t* p_pub_key_id_size,
                                            uint8_t* p_pub_key_id);

/**
 * The application needs to call this function before generating a quote.  The quote size is variable 
 * depending on the type of attestation key selected and other platform or key data required to generate the 
 * quote.  Once the application calls this API, it will use the returned p_quote_size to allocate the buffer 
 * required to hold the generated quote.  A pointer to this buffer is provided to the ref_get_quote() API. 
 *  
 * If the key is not available, this API may return an error (SGX_ATT_KEY_NOT_INITIALIZED) depending on 
 * the algorithm.  In this case, the caller must call sgx_init_quote() to re-generate and certify the 
 * attestation key. 
 *
 * @param p_att_key_id The selected attestation key ID from the quote verifier's list.  It includes the QE 
 *                     identity as well as the attestation key's algorithm type. It cannot be NULL.
 * @param p_quote_size Pointer to the location where the required quote buffer size will be returned. Must 
 *                     not be NULL.
 *  
 * @return SGX_SUCCESS Successfully calculated the required quote size. The required size in bytes is returned in the 
 *         memory pointed to by p_quote_size.
 * @return SGX_ERROR_INVALID_PARAMETER Invalid parameter. p_quote_size and p_att_key_id must not be NULL. 
 * @return SGX_ERROR_ATT_KEY_UNINITIALIZED The platform quoting infrastructure does not have the attestation 
 *         key available to generate quotes.  sgx_init_quote() must be called again.
 * @return SGX_ERROR_UNSUPPORTED_ATT_KEY_ID The platform quoting infrastructure does not support the key 
 *         described in p_att_key_id.
 * @return SGX_ERROR_INVALID_ATT_KEY_CERT_DATA The data returned by the platform library's sgx_get_quote_config() is 
 *         invalid.
 */
sgx_status_t SGXAPI sgx_get_quote_size_ex(const sgx_att_key_id_t *p_att_key_id,
                                                uint32_t* p_quote_size);

/**
 * This function is c-code wrapper for getting the quote. The function will take the application enclave's REPORT that 
 * will be converted into a quote after the QE verifies the REPORT.  Once verified it will sign it with platform's 
 * attestation key matching the selected attestation key ID.  If the key is not available, this API may return an error 
 * (SGX_ATT_KEY_NOT_INITIALIZED) depending on the algorithm.  In this case, the caller must call sgx_init_quote() 
 * to re-generate and certify the attestation key. an attestation key. 
 *  
 * The caller can request a REPORT from the QE using a supplied nonce.  This will allow the enclave requesting the quote 
 * to verify the QE used to generate the quote. This makes it more difficult for something to spoof a QE and allows the 
 * app enclave to catch it earlier.  But since the authenticity of the QE lies in knowledge of the Quote signing key, 
 * such spoofing will ultimately be detected by the quote verifier.  QE REPORT.ReportData = 
 * SHA256(*p_nonce||*p_quote)||32-0x00's. 
 * 
 * @param p_app_report Pointer to the enclave report that needs the quote. The report needs to be generated using the 
 *                     QE's target info returned by the sgx_init_quote() API.  Must not be NULL.
 * @param p_att_key_id The selected attestation key ID from the quote verifier's list.  It includes the QE identity as 
 *                     well as the attestation key's algorithm type. It cannot be NULL.
 * @param p_qe_report_info Pointer to a data structure that will contain the information required for the QE to generate 
 *                         a REPORT that can be verified by the application enclave.  The inputted data structure
 *                         contains the application's TARGET_INFO, a nonce and a buffer to hold the generated report.
 *                         The QE Report will be generated using the target information and the QE's REPORT.ReportData =
 *                         SHA256(*p_nonce||*p_quote)||32-0x00's.  This parameter is used when the application wants to
 *                         verify the QE's REPORT to provide earlier detection that the QE is not being spoofed by
 *                         untrusted code.  A spoofed QE will ultimately be rejected by the remote verifier.   This
 *                         parameter is optional and will be ignored when NULL.
 * @param p_quote Pointer to the buffer that will contain the quote.
 * @param quote_size Size of the buffer pointed to by p_quote. 
 *  
 * @return SGX_SUCCESS Successfully generated the quote. 
 * @return SGX_ERROR_INVALID_PARAMETER If either p_app_report or p_quote is null. Or, if quote_size isn't large 
 *         enough, p_att_key_id is NULL.
 * @return SGX_ERROR_ATT_KEY_UNINITIALIZED The platform quoting infrastructure does not have the attestation key 
 *         available to generate quotes.  sgx_init_quote() must be called again.
 * @return SGX_ERROR_UNSUPPORTED_ATT_KEY_ID The platform quoting infrastructure does not support the key described in 
 *         p_att_key_id.
 * @return SGX_ERROR_INVALID_ATT_KEY_CERT_DATA The data returned by the platform library's sgx_get_quote_config() is 
 *         invalid.
 * @return SGX_ERROR_MAC_MISMATCH Report MAC check failed on application report.
 */
sgx_status_t SGXAPI  sgx_get_quote_ex(const sgx_report_t *p_app_report,
                                           const sgx_att_key_id_t *p_att_key_id,
                                           sgx_qe_report_info_t *p_qe_report_info,
                                           uint8_t *p_quote,
                                           uint32_t quote_size);


#ifdef  __cplusplus
}
#endif

#endif
