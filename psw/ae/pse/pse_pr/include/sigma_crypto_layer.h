/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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
 
 
#ifndef _SIGMA_CRYPTO_LAYER_H_
#define _SIGMA_CRYPTO_LAYER_H_

#include <string>

#include "pse_pr_inc.h"
#include "pse_pr_types.h"
#include "pse_pr_sigma_defs.h"
#include "sgx_tcrypto.h" 
#include "pairing_blob.h"
#include "Epid_rl.h"
#include "t_pairing_blob.h"
#include "byte_order.h"
class SigmaCryptoLayer
{
public:

    SigmaCryptoLayer() {};
    virtual ~SigmaCryptoLayer();

    ae_error_t DeriveSkMk(sgx_ecc_state_handle_t ecc_handle);

    ae_error_t calc_s2_hmac(SIGMA_HMAC* hmac, 
                      const SIGMA_S2_MESSAGE* s2, 
                      size_t nS2VLDataLen);

    ae_error_t calc_s3_hmac(SIGMA_HMAC* hmac, 
                      const SIGMA_S3_MESSAGE* s3,
                      size_t nS3VLDataLen);

    ae_error_t ComputePR(SIGMA_SECRET_KEY* oldSK, uint8_t byteToAdd, SIGMA_HMAC* hmac);
    ae_error_t ComputeId(uint8_t byteToAdd, SHA256_HASH* hmac);

    const uint8_t* get_pub_key_gb_be() { return m_local_public_key_gb_big_endian; }
    const uint8_t* get_remote_pub_key_ga_be() { return m_remote_public_key_ga_big_endian; }
    void set_prv_key_b_le(uint8_t* pb) { memcpy(m_local_private_key_b_little_endian, pb, sizeof(m_local_private_key_b_little_endian)); }
    void set_pub_key_gb_be(uint8_t* pGb) { memcpy(m_local_public_key_gb_big_endian, pGb, sizeof(m_local_public_key_gb_big_endian)); }
    void set_remote_pub_key_ga_be(uint8_t* pGa) { memcpy(m_remote_public_key_ga_big_endian, pGa, sizeof(m_remote_public_key_ga_big_endian)); }

    const uint8_t* get_SMK() { return m_SMK; }
    const uint8_t* get_SK() { return m_SK; }
    const uint8_t* get_MK() { return m_MK; }

    virtual ae_error_t MsgVerifyPch(uint8_t* PubKeyPch, int PubKeyPchLen, 
        uint8_t* EpidParamsCert,  uint8_t* Msg, int MsgLen, uint8_t* Bsn, int BsnLen, 
        uint8_t* Signature, int SignatureLen, 
        uint8_t* PrivRevList, int PrivRL_Len, uint8_t* SigRevList, int SigRL_Len, uint8_t* GrpRevList, int GrpRL_Len) = 0;
    virtual void get_session_pubkey(uint8_t* combined_pubkeys, int combined_pubkeys_length) = 0;
    virtual void set_sigma_pblob_info(pairing_data_t* pairing_data) = 0;
    virtual ae_error_t check_sigrl_header(const EPID_SIG_RL* pSigRl) = 0;
    virtual ae_error_t check_privrl_header(const EPID_PRIV_RL* pPrivRl) = 0;
    uint8_t* m_PubKeyPch;

private:
    uint8_t m_local_private_key_b_little_endian[SIGMA_SESSION_PRIVKEY_LENGTH];
    uint8_t m_local_public_key_gb_big_endian[SIGMA_SESSION_PUBKEY_LENGTH];
    uint8_t m_remote_public_key_ga_big_endian[SIGMA_SESSION_PUBKEY_LENGTH];
    uint8_t m_SMK[SIGMA_SMK_LENGTH];
    SIGMA_SECRET_KEY m_SK;
    SIGMA_MAC_KEY  m_MK;

    // Disable class operations (default constructor, copy constructor, assignment operator, and address-of operator)
    //SigmaCryptoLayer(void);                                     // default constructor
    SigmaCryptoLayer(const SigmaCryptoLayer& rhs);              // copy constructor
    SigmaCryptoLayer& operator=(const SigmaCryptoLayer& rhs);   // assignment operator
    SigmaCryptoLayer* operator&();                              // address-of operator
    const SigmaCryptoLayer* operator&() const;                  // address-of operator

};

#endif
