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


#include "se_memcpy.h"
#include "util.h"
#include "uae_service_internal.h"
#include "crypto_wrapper.h"

static sgx_status_t get_launch_token_internal(
    const enclave_css_t *p_signature,
    const sgx_attributes_t *p_attributes,
    token_t *p_token)
{
    memset(p_token, 0xEE, sizeof(token_t));
    memset(&(p_token->body.reserved1), 0,
        sizeof(p_token->body.reserved1));
    memset(&(p_token->reserved2), 0,
        sizeof(p_token->reserved2));

    p_token->body.valid = 1;
    // In spec, lic_token.cpu_svn = 1, which 1 should be the least significate one.
    memset(&p_token->cpu_svn_le, 0, sizeof(p_token->cpu_svn_le));
    memset(&p_token->cpu_svn_le, 1, 1);
    p_token->isv_svn_le = 1;
    if(memcpy_s(&(p_token->body.attributes),
        sizeof(p_token->body.attributes),
        p_attributes,
        sizeof(sgx_attributes_t))){
            return SGX_ERROR_UNEXPECTED;
    }
    if(memcpy_s(&(p_token->body.mr_enclave),
        sizeof(p_token->body.mr_enclave),
        &(p_signature->body.enclave_hash),
        sizeof(p_signature->body.enclave_hash))){
            return SGX_ERROR_UNEXPECTED;
    }
    p_token->attributes_le.flags = SGX_FLAGS_INITTED;
    p_token->attributes_le.xfrm = SGX_XFRM_LEGACY;
   
    unsigned int signer_len = sizeof(p_token->body.mr_signer);
    sgx_status_t ret = sgx_EVP_Digest(EVP_sha256(), (const uint8_t *)&(p_signature->key.modulus), 
                sizeof(p_signature->key.modulus), 
                (uint8_t *)&(p_token->body.mr_signer), 
                &signer_len);
    if(ret != SGX_SUCCESS && ret != SGX_ERROR_OUT_OF_MEMORY)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    return ret;
}

sgx_status_t get_launch_token(
    const enclave_css_t *p_signature,
    const sgx_attributes_t *p_attribute,
    sgx_launch_token_t *p_launch_token)
{
    if(!p_signature || !p_attribute || !p_launch_token){
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return get_launch_token_internal(p_signature,
        p_attribute,
        (token_t *)p_launch_token);
}
