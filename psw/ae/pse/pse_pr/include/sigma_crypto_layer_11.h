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
 
 
#ifndef _SIGMA_CRYPTO_LAYER_11_H
#define _SIGMA_CRYPTO_LAYER_11_H

#include "sigma_crypto_layer.h"
#include "util.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "epid/verifier/1.1/api.h"
#include "epid/common/1.1/types.h"
#ifdef __cplusplus
}
#endif

#define SIGMA11_SVER   0x0001
#define SIG_RL_BLOBID  0x000e
#define PRIV_RL_BLOBID 0x000d 

class Sigma11CryptoLayer : public SigmaCryptoLayer
{
public:
	Sigma11CryptoLayer();
	~Sigma11CryptoLayer();

    ae_error_t MsgVerifyPch(uint8_t* PubKeyPch, int PubKeyPchLen, 
        uint8_t* EpidParamsCert,  uint8_t* Msg, int MsgLen, uint8_t* Bsn, int BsnLen, 
        uint8_t* Signature, int SignatureLen, 
        uint8_t* PrivRevList, int PrivRL_Len, uint8_t* SigRevList, int SigRL_Len, uint8_t* GrpRevList, int GrpRL_Len);

    void get_session_pubkey(uint8_t* combined_pubkeys, int combined_pubkeys_length);
    void set_sigma_pblob_info(pairing_data_t* pairing_data) { UNUSED(pairing_data);}
    ae_error_t check_sigrl_header(const EPID_SIG_RL* pSigRl);
    ae_error_t check_privrl_header(const EPID_PRIV_RL* pPrivRl);
};

#endif
