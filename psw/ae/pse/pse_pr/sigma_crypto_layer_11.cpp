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
#include "sigma_crypto_layer_11.h"
#include "safe_id.h"
#include "assert.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "epid/verifier/1.1/api.h"
#include "epid/common/1.1/types.h"
#ifdef __cplusplus
}
#endif

static ae_error_t MapEpidResultToAEError(EpidStatus epid_result)
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
Sigma11CryptoLayer::Sigma11CryptoLayer()
{
    m_PubKeyPch = (uint8_t*)malloc(sizeof(Epid11GroupPubKey));
}
Sigma11CryptoLayer::~Sigma11CryptoLayer()
{
    if (m_PubKeyPch)
    {
        free(m_PubKeyPch);
        m_PubKeyPch = NULL;
    }
}

ae_error_t Sigma11CryptoLayer::MsgVerifyPch(uint8_t* PubKeyPch, int PubKeyPchLen,
                                    uint8_t* EpidParamsCert,  uint8_t* Msg, int MsgLen,
                                    uint8_t* Bsn, int BsnLen, uint8_t* Signature,
                                    int SignatureLen,
                                    uint8_t* PrivRevList, int PrivRL_Len, uint8_t* SigRevList, int SigRL_Len,
                                    uint8_t* GrpRevList, int GrpRL_Len)
{
    ae_error_t status = AE_FAILURE;
    EpidStatus SafeIdRes = kEpidNoErr;
    Epid11Signature Epid11Sig;
    Epid11Signature *SigPointer = NULL;
    memset_s(&Epid11Sig, sizeof(Epid11Sig), 0, sizeof(Epid11Sig));

    UNUSED(EpidParamsCert);
    UNUSED(Bsn);
    UNUSED(BsnLen);

    Epid11VerifierCtx* ctx = NULL;
    do
    {
        // Watch for null pointers
        if ((PubKeyPch == NULL) || (Msg == NULL) || (Signature == NULL))
        {
            status = PSE_PR_PARAMETER_ERROR;
            break;
        }

        // Verify the length of public key and signature buffers
        if (((size_t)PubKeyPchLen < (SAFEID_CERT_LEN - ECDSA_SIGNATURE_LEN)) ||
                                (SignatureLen < SAFEID_SIG_LEN))
        {
            status = PSE_PR_PARAMETER_ERROR;
            break;
        }

        SafeIdRes = Epid11VerifierCreate(
                (Epid11GroupPubKey* )(PubKeyPch),
                NULL, &ctx);
        status = MapEpidResultToAEError(SafeIdRes);
        if (AE_FAILED(status)){
            break;
        }
        if(PrivRevList != NULL){
            SafeIdRes = Epid11VerifierSetPrivRl(ctx, (Epid11PrivRl *)(PrivRevList), PrivRL_Len);
            status = MapEpidResultToAEError(SafeIdRes);
            if(AE_FAILED(status)) {break;}
        }
        if(SigRevList != NULL){
            SafeIdRes = Epid11VerifierSetSigRl(ctx, (Epid11SigRl *)(SigRevList), SigRL_Len);
            status = MapEpidResultToAEError(SafeIdRes);
            if(AE_FAILED(status)) {break;}
        }

        if(GrpRevList != NULL){
            SafeIdRes = Epid11VerifierSetGroupRl(ctx, (Epid11GroupRl *)(GrpRevList), GrpRL_Len);
            status = MapEpidResultToAEError(SafeIdRes);
            if(AE_FAILED(status)) {break;}
        }

        //verify signature with Pub Key in ctx
        //For epid-sdk-3.0, when the sigRL is null, the signature size includes "rl_ver" and "n2" fields
        //(See structure definition of Epid11Signature)
        //So we must use bigger buffer add 8 bytes to the length
        if(SignatureLen == sizeof(Epid11BasicSignature)){
            memcpy(&Epid11Sig, Signature, SignatureLen);
            SignatureLen = static_cast<int>(SignatureLen + sizeof(Epid11Sig.rl_ver) + sizeof(Epid11Sig.n2));
            SigPointer = &Epid11Sig;
        }
        else
        {
            SigPointer = (Epid11Signature *)Signature;
        }


        SafeIdRes = Epid11Verify(ctx,
                SigPointer, SignatureLen,
                Msg, MsgLen);
        status = MapEpidResultToAEError(SafeIdRes);
        if (AE_FAILED(status)){
            break;
         }

        status = AE_SUCCESS;

    } while (false);

    if (NULL != ctx)
    {
        Epid11VerifierDelete(&ctx);
    }

    return status;
}

// For sigma11, s2 message contains sig(ga || gb)
void Sigma11CryptoLayer::get_session_pubkey(uint8_t* combined_pubkeys, int combined_pubkeys_length)
{
    (void)combined_pubkeys_length;
    assert(combined_pubkeys_length == SIGMA_SESSION_PUBKEY_LENGTH * 2);
    memcpy(combined_pubkeys, get_remote_pub_key_ga_be(), SIGMA_SESSION_PUBKEY_LENGTH);
    memcpy(combined_pubkeys + SIGMA_SESSION_PUBKEY_LENGTH, get_pub_key_gb_be(), SIGMA_SESSION_PUBKEY_LENGTH);
}

ae_error_t Sigma11CryptoLayer::check_sigrl_header(const EPID_SIG_RL* pSigRl)
{
    if (pSigRl != NULL)
    {
        const uint16_t* p_sver = reinterpret_cast<const uint16_t*>(pSigRl->sver);
        const uint16_t* p_blob_id = reinterpret_cast<const uint16_t*>(pSigRl->blob_id);
        if (SIGMA11_SVER != lv_htons(*p_sver) ||
            SIG_RL_BLOBID != lv_htons(*p_blob_id))
            return AESM_PSE_PR_RL_RESP_HEADER_ERROR;
    }
    return AE_SUCCESS;
}

ae_error_t Sigma11CryptoLayer::check_privrl_header(const EPID_PRIV_RL* pPrivRl)
{
    if (pPrivRl != NULL)
    {
        const uint16_t* p_sver = reinterpret_cast<const uint16_t*>(pPrivRl->sver);
        const uint16_t* p_blob_id = reinterpret_cast<const uint16_t*>(pPrivRl->blob_id);
        if (SIGMA11_SVER != lv_htons(*p_sver) ||
            PRIV_RL_BLOBID != lv_htons(*p_blob_id))
            return AESM_PSE_PR_RL_RESP_HEADER_ERROR;
    }
    return AE_SUCCESS;
}
