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
#include "sigma_crypto_layer_20.h"
#include "safe_id.h"
#include "assert.h"
#include "util.h"

static ae_error_t MapEpidResultToAEError(EpidStatus    epid_result)
{
    ae_error_t status = PSE_PR_PCH_EPID_UNKNOWN_ERROR;

    switch (epid_result)
    {
    case kEpidNoErr:                            status = AE_SUCCESS; break;
    case kEpidSigInvalid:                       status = PSE_PR_PCH_EPID_SIG_INVALID; break;
    case kEpidSigRevokedInGroupRl:              status = PSE_PR_PCH_EPID_SIG_REVOKED_IN_GROUPRL; break;
    case kEpidSigRevokedInPrivRl:               status = PSE_PR_PCH_EPID_SIG_REVOKED_IN_PRIVRL; break;
    case kEpidSigRevokedInSigRl:                status = PSE_PR_PCH_EPID_SIG_REVOKED_IN_SIGRL; break;
    case kEpidSigRevokedInVerifierRl:           status = PSE_PR_PCH_EPID_SIG_REVOKED_IN_VERIFIERRL; break;
    case kEpidErr:                              status = PSE_PR_PCH_EPID_UNKNOWN_ERROR; break;
    case kEpidNotImpl:                          status = PSE_PR_PCH_EPID_NOT_IMPLEMENTED; break;
    case kEpidBadArgErr:                        status = PSE_PR_PCH_EPID_BAD_ARG_ERR; break;
    case kEpidNoMemErr:                         status = PSE_PR_PCH_EPID_NO_MEMORY_ERR; break;
    case kEpidMemAllocErr:                      status = PSE_PR_PCH_EPID_NO_MEMORY_ERR; break;
    case kEpidMathErr:                          status = PSE_PR_PCH_EPID_MATH_ERR; break;
    case kEpidDivByZeroErr:                     status = PSE_PR_PCH_EPID_DIVIDED_BY_ZERO_ERR; break;
    case kEpidUnderflowErr:                     status = PSE_PR_PCH_EPID_UNDERFLOW_ERR; break;
    case kEpidHashAlgorithmNotSupported:        status = PSE_PR_PCH_EPID_HASH_ALGORITHM_NOT_SUPPORTED; break;
    case kEpidRandMaxIterErr:                   status = PSE_PR_PCH_EPID_RAND_MAX_ITER_ERR; break;
    case kEpidDuplicateErr:                     status = PSE_PR_PCH_EPID_DUPLICATE_ERR; break;
    case kEpidInconsistentBasenameSetErr:       status = PSE_PR_PCH_EPID_INCONSISTENT_BASENAME_SET_ERR; break;
    case kEpidMathQuadraticNonResidueError:     status = PSE_PR_PCH_EPID_MATH_ERR; break;
    default:                                    status = PSE_PR_PCH_EPID_UNKNOWN_ERROR; break;
    }

    return status;
}

Sigma20CryptoLayer::Sigma20CryptoLayer()
{
    m_PubKeyPch = (uint8_t*)malloc(sizeof(GroupPubKey));
}
Sigma20CryptoLayer::~Sigma20CryptoLayer()
{
    if (m_PubKeyPch)
    {
        free(m_PubKeyPch);
        m_PubKeyPch=NULL;
    }
}

ae_error_t Sigma20CryptoLayer::MsgVerifyPch(uint8_t* PubKeyPch, int PubKeyPchLen,
                                    uint8_t* EpidParamsCert,  uint8_t* Msg, int MsgLen,
                                    uint8_t* Bsn, int BsnLen, uint8_t* Signature,
                                    int SignatureLen,
                                    uint8_t* PrivRevList, int PrivRL_Len, uint8_t* SigRevList, int SigRL_Len,
                                    uint8_t* GrpRevList, int GrpRL_Len){
    ae_error_t status = AE_FAILURE;
    EpidStatus SafeIdRes = kEpidNoErr;
    VerifierCtx* ctx = NULL;

    UNUSED(EpidParamsCert);
    UNUSED(Bsn);
    UNUSED(BsnLen);

    do
    {
    // Watch for null pointers
    if ((PubKeyPch == NULL) || (Msg == NULL) || (Signature == NULL))
    {
        status = PSE_PR_PARAMETER_ERROR;
        break;
    }

    // Verify the length of public key
    if ((size_t)PubKeyPchLen < (SAFEID_CERT_LEN - ECDSA_SIGNATURE_LEN))
    {
        status = PSE_PR_PARAMETER_ERROR;
        break;
    }
    // Verify the length of signature
    if (SignatureLen < EPID_SIG_HEADER_OFFSET)
    {
        status = PSE_PR_PARAMETER_ERROR;
        break;
    }

    SafeIdRes = EpidVerifierCreate(
        (GroupPubKey*)(PubKeyPch),
        NULL, &ctx);
    status = MapEpidResultToAEError(SafeIdRes);
    if (AE_FAILED(status)) {
        break;
    }

    if (PrivRevList != NULL) {
        SafeIdRes = EpidVerifierSetPrivRl(ctx, (PrivRl*)PrivRevList, (size_t)PrivRL_Len);
        status = MapEpidResultToAEError(SafeIdRes);
        if (AE_FAILED(status)) {break;}
    }
    if (SigRevList != NULL) {
        SafeIdRes = EpidVerifierSetSigRl(ctx, (SigRl*)SigRevList, (size_t)SigRL_Len);
        status = MapEpidResultToAEError(SafeIdRes);
        if (AE_FAILED(status)) {break;}
    }
    if (GrpRevList != NULL) {
        SafeIdRes = EpidVerifierSetGroupRl(ctx, (GroupRl*)GrpRevList, (size_t)GrpRL_Len);
        status = MapEpidResultToAEError(SafeIdRes);
        if (AE_FAILED(status)) {break;}
    }

    SafeIdRes = EpidVerifierSetHashAlg(ctx, kSha256);
    status = MapEpidResultToAEError(SafeIdRes);
    if (AE_FAILED(status))
        break;

    SafeIdRes = EpidVerify(ctx, (EpidSignature*)(Signature + EPID_SIG_HEADER_OFFSET), 
            (size_t)SignatureLen - EPID_SIG_HEADER_OFFSET,
            (void*)Msg, (size_t)MsgLen);
    status = MapEpidResultToAEError(SafeIdRes);
    if (AE_FAILED(status)){
            break;
         }

    status = AE_SUCCESS;

    } while (false);

    if (NULL != ctx)
    {
        EpidVerifierDelete(&ctx);
    }

    return status;
}

// For sigma20, s2 message contains sig(gb || ba)
void Sigma20CryptoLayer::get_session_pubkey(uint8_t* combined_pubkeys, int combined_pubkeys_length)
{
    (void)combined_pubkeys_length;
    assert(combined_pubkeys_length == SIGMA_SESSION_PUBKEY_LENGTH * 2);
    memcpy(combined_pubkeys, get_pub_key_gb_be(), SIGMA_SESSION_PUBKEY_LENGTH);
    memcpy(combined_pubkeys + SIGMA_SESSION_PUBKEY_LENGTH, get_remote_pub_key_ga_be(), SIGMA_SESSION_PUBKEY_LENGTH);
}

void Sigma20CryptoLayer::set_sigma_pblob_info(pairing_data_t* pairing_data)
{
    pairing_data->plaintext.cse_sec_prop.ps_hw_sec_info.session_prop |= SIGMA_VERSION_20;
}

ae_error_t Sigma20CryptoLayer::check_sigrl_header(const EPID_SIG_RL* pSigRl)
{
    if (pSigRl != NULL)
    {
        const uint16_t* p_sver = reinterpret_cast<const uint16_t*>(pSigRl->sver);
        const uint16_t* p_blob_id = reinterpret_cast<const uint16_t*>(pSigRl->blob_id);
        if (SIGMA20_SVER != lv_htons(*p_sver) ||
            SIG_RL_BLOBID != lv_htons(*p_blob_id))
            return AESM_PSE_PR_RL_RESP_HEADER_ERROR;
    }
    
    return AE_SUCCESS;
}

ae_error_t Sigma20CryptoLayer::check_privrl_header(const EPID_PRIV_RL* pPrivRl)
{
    if (pPrivRl != NULL)
    {
        const uint16_t* p_sver = reinterpret_cast<const uint16_t*>(pPrivRl->sver);
        const uint16_t* p_blob_id = reinterpret_cast<const uint16_t*>(pPrivRl->blob_id);
        if (SIGMA20_SVER != lv_htons(*p_sver) ||
            PRIV_RL_BLOBID != lv_htons(*p_blob_id))
            return AESM_PSE_PR_RL_RESP_HEADER_ERROR;
    }
    
    return AE_SUCCESS;
}
