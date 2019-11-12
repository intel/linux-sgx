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

#include <sgx_secure_align.h>
#include "sigma_crypto_layer.h"
#include "sgx_ecc256_internal.h"
#include "pse_pr_inc.h"
#include "pse_pr_types.h"
#include "safe_id.h"
#include <stddef.h>
#include <time.h>
#include <cstring>
#include "le2be_macros.h"
#include "prepare_hmac_sha256.h"
#include "prepare_hash_sha256.h"
#include "sgx_trts.h"
#include "util.h"

#include "Keys.h"
#include "pairing_blob.h"


ae_error_t sgx_error_to_pse_pr_error(sgx_status_t status)
{
    switch(status){
    case SGX_SUCCESS:
        return AE_SUCCESS;
    case SGX_ERROR_OUT_OF_MEMORY:
        return PSE_PR_INSUFFICIENT_MEMORY_ERROR;
    case SGX_ERROR_INVALID_PARAMETER:
        return PSE_PR_PARAMETER_ERROR;
    default:
        return PSE_PR_ERROR;
    }
}

SigmaCryptoLayer::~SigmaCryptoLayer(void)
{
    memset_s(m_local_private_key_b_little_endian, SIGMA_SESSION_PRIVKEY_LENGTH, 0, SIGMA_SESSION_PRIVKEY_LENGTH);
    memset_s(m_SMK, SIGMA_SMK_LENGTH, 0, SIGMA_SMK_LENGTH);
    memset_s(m_SK, sizeof(m_SK), 0, sizeof(m_SK));
    memset_s(m_MK, sizeof(m_MK), 0, sizeof(m_MK));
}


ae_error_t SigmaCryptoLayer::DeriveSkMk(/* In  */ sgx_ecc_state_handle_t ecc_handle)
{
    ae_error_t ae_status = PSE_PR_DERIVE_SMK_ERROR;
    sgx_status_t    status;
    uint8_t Gab[SGX_ECP256_KEY_SIZE*2] = {0};
    uint8_t Gab_Wth_00[SGX_ECP256_KEY_SIZE*2+1] = {0};
    uint8_t Gab_Wth_01[SGX_ECP256_KEY_SIZE*2+1] = {0};
    //
    // securely align - need to zero
    // [SK,MK] = GabHMACSha256
    //
    //uint8_t GabHMACSha256[SGX_SHA256_HASH_SIZE] = { 0 };
    sgx::custom_alignment_aligned<uint8_t[SGX_SHA256_HASH_SIZE], SGX_SHA256_HASH_SIZE, 0, SGX_SHA256_HASH_SIZE> oGabHMACSha256;
    uint8_t (&GabHMACSha256)[SGX_SHA256_HASH_SIZE] = oGabHMACSha256.v;

    /* convert m_remotePublicKey_ga_big_endian to little endian format */
    uint8_t public_key_little_endian[SIGMA_SESSION_PUBKEY_LENGTH];
    memcpy(public_key_little_endian, m_remote_public_key_ga_big_endian, SIGMA_SESSION_PUBKEY_LENGTH);
    SwapEndian_32B(&(public_key_little_endian[0]));
    SwapEndian_32B(&(public_key_little_endian[32]));

    do
    {
        // Watch for null pointers
        if (ecc_handle == NULL) 
        {
            ae_status = PSE_PR_PARAMETER_ERROR;
            break;
        }

        sgx_status_t sgx_status = sgx_ecc256_compute_shared_point((sgx_ec256_private_t *)m_local_private_key_b_little_endian,
                                           (sgx_ec256_public_t *)public_key_little_endian,
                                           (sgx_ec256_shared_point_t *)Gab,
                                           ecc_handle);
        if (SGX_SUCCESS != sgx_status)
        {
            if (SGX_ERROR_OUT_OF_MEMORY == sgx_status)
                ae_status = PSE_PR_INSUFFICIENT_MEMORY_ERROR;
            break;
        }

        //Initialize Variables required to get SK, SMK, MK
        memcpy(Gab_Wth_00, Gab, sizeof(Gab));
        Gab_Wth_00[sizeof(Gab)] = 0;

        memcpy(Gab_Wth_01, Gab, sizeof(Gab));
        Gab_Wth_01[sizeof(Gab)] = 1;
        uint8_t HMAC_Key[SIGMA_HMAC_LENGTH] = {0};

        //Compute SMK
        status = sgx_hmac_sha256_msg(Gab_Wth_00, sizeof(Gab_Wth_00), HMAC_Key,sizeof(HMAC_Key), m_SMK, sizeof(m_SMK));
        if (status != SGX_SUCCESS)
        {
            ae_status = sgx_error_to_pse_pr_error(status);
            break;
        }

        // Compute SK and MK
        status = sgx_hmac_sha256_msg(Gab_Wth_01, sizeof(Gab_Wth_01), HMAC_Key, sizeof(HMAC_Key), GabHMACSha256, sizeof(GabHMACSha256));
        if (status != SGX_SUCCESS)
        {
            ae_status = sgx_error_to_pse_pr_error(status); 
            break;
        }

        // Derive SK and MK from SHA256(g^ab)
        memcpy(m_SK, (GabHMACSha256), SIGMA_SK_LENGTH);                // SK: bits   0-127
        memcpy(m_MK, (GabHMACSha256 + SIGMA_SK_LENGTH), SIGMA_MK_LENGTH);            // MK: bits 128-255

        ae_status = AE_SUCCESS;

    } while (false);

    // Defense-in-depth: clear secrets in stack before return
    memset_s(Gab, sizeof(Gab), 0, sizeof(Gab));
    memset_s(Gab_Wth_00, sizeof(Gab_Wth_00), 0, sizeof(Gab_Wth_00));
    memset_s(Gab_Wth_01, sizeof(Gab_Wth_00), 0, sizeof(Gab_Wth_00));
    memset_s(GabHMACSha256, sizeof(GabHMACSha256), 0, sizeof(GabHMACSha256));

    return ae_status;
}



ae_error_t SigmaCryptoLayer::calc_s2_hmac(
    SIGMA_HMAC* hmac, const SIGMA_S2_MESSAGE* s2, size_t nS2VLDataLen)
{
    PrepareHMACSHA256 p(m_SMK, sizeof(m_SMK));

    p.Update(s2->Gb, sizeof(s2->Gb));
    p.Update(s2->Basename, sizeof(s2->Basename));
    p.Update(&s2->OcspReq, sizeof(s2->OcspReq));
    p.Update(s2->Data, nS2VLDataLen);

    //NRG:  SIGMA_HMAC - HMAC_SHA256 of [Gb || Basename || OCSP Req ||
    //          Verifier Cert ||  Sig-RL List ], using SMK

    return p.Finalize(hmac);
}

ae_error_t SigmaCryptoLayer::calc_s3_hmac(
    SIGMA_HMAC* hmac, const SIGMA_S3_MESSAGE* s3, size_t nS3VLDataLen)
{
    PrepareHMACSHA256 p(m_SMK, sizeof(m_SMK));

    p.Update(&s3->TaskInfo, sizeof(s3->TaskInfo));
    p.Update(s3->Ga, sizeof(s3->Ga));
    p.Update(s3->Data, nS3VLDataLen);

    //NRG:  SIGMA_HMAC -- HMAC_SHA256 of [TaskInfo || g^a ||
    //          EPIDCertprvr || EPIDSig(g^a || g^b)], using SMK

    return p.Finalize(hmac);
}

ae_error_t SigmaCryptoLayer::ComputePR(SIGMA_SECRET_KEY* oldSK, uint8_t byteToAdd, SIGMA_HMAC* hmac)
{
    //
    // securely align
    //
    //uint8_t Sk_Wth_Added_Byte[sizeof(SIGMA_SIGN_KEY)+1];
    sgx::custom_alignment_aligned<uint8_t[sizeof(SIGMA_SIGN_KEY)+1], sizeof(SIGMA_SIGN_KEY), 0, sizeof(SIGMA_SIGN_KEY)> oSk_Wth_Added_Byte;
    uint8_t (&Sk_Wth_Added_Byte)[sizeof(SIGMA_SIGN_KEY) + 1] = oSk_Wth_Added_Byte.v;

    ae_error_t ae_status = PSE_PR_PR_CALC_ERROR;

    memset(hmac, 0, sizeof(*hmac));

    do
    {
        memcpy(Sk_Wth_Added_Byte, oldSK, SIGMA_SK_LENGTH);
        Sk_Wth_Added_Byte[SIGMA_SK_LENGTH] = byteToAdd;

        //Compute hmac
        sgx_status_t status = sgx_hmac_sha256_msg(Sk_Wth_Added_Byte, SIGMA_SK_LENGTH+1, m_MK, SIGMA_MK_LENGTH, (uint8_t *)hmac, SIGMA_HMAC_LENGTH);

        // defense-in-depth, clear secret data
        memset_s(Sk_Wth_Added_Byte, sizeof(Sk_Wth_Added_Byte), 0, sizeof(Sk_Wth_Added_Byte));

        if (SGX_SUCCESS != status)
        {
            ae_status = sgx_error_to_pse_pr_error(status); 
            break;
        }

        ae_status = AE_SUCCESS;

    } while (0);

    return ae_status;
}


ae_error_t SigmaCryptoLayer::ComputeId(uint8_t byteToAdd,
                                 SHA256_HASH* hash)
{
    memset(hash, 0, sizeof(*hash));

    PrepareHashSHA256 p;

    p.Update(m_SK, sizeof(SIGMA_SIGN_KEY));
    p.Update(m_MK, sizeof(SIGMA_MAC_KEY));
    p.Update(&byteToAdd, sizeof(uint8_t));

    return p.Finalize(hash);
}
