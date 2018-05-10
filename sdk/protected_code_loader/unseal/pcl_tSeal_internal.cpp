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

/* Content from sdk/tseal/tSeal_internal.cpp */

#include <stdint.h>
#include <stdlib.h>
#include <sgx_tseal.h>
#ifdef SE_SIM
#include <deriv.h>
#endif // #ifdef SE_SIM
#include <pcl_common.h>
#include <pcl_internal.h>
#include <pcl_unseal_internal.h>

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pcl_unseal_data_helper()
//      helper function for pcl_unseal_data, does the actual decryption and MAC compare
// Parameters:
//        [IN] p_sealed_data - pointer to sealed key blob
//        [OUT] p_additional_MACtext - additional text to MAC
//        [IN] additional_MACtext_length - length of additional text
//        [OUT] p_decrypted_text - buffer to fill with decrypted data
//        [IN] decrypted_text_length - length of p_decrypted_text buffer
// Return Value:
//   SGX_SUCCESS or error codes
sgx_status_t pcl_unseal_data_helper(const sgx_sealed_data_t *p_sealed_data, uint8_t *p_additional_MACtext,
    uint32_t additional_MACtext_length, uint8_t *p_decrypted_text, uint32_t decrypted_text_length)
{
    // code based on tSeal_internal.cpp in tseal library

    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_key_128bit_t seal_key;
    pcl_memset(&seal_key, 0, sizeof(sgx_key_128bit_t));
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    pcl_memset(&payload_iv, 0, SGX_SEAL_IV_SIZE);
    const uint8_t* p_aad = NULL;
    uint32_t res = 0;
    sgx_aes_gcm_128bit_tag_t mac;
    //uint8_t mac[16];

    if (decrypted_text_length > 0)
        pcl_memset(p_decrypted_text, 0, decrypted_text_length);

    if (additional_MACtext_length > 0)
    {
        // Verify GUID in sealed blob matches GUID in PCL table: 
        p_aad = const_cast<uint8_t *>(&(p_sealed_data->aes_data.payload[decrypted_text_length]));
        if (pcl_consttime_memequal(p_aad, p_additional_MACtext, additional_MACtext_length) == 0)
        {
            return SGX_ERROR_PCL_GUID_MISMATCH;
        }
        pcl_memset(p_additional_MACtext, 0, additional_MACtext_length);
    }

    // Get the seal key
    err = pcl_sgx_get_key(&p_sealed_data->key_request, &seal_key);
    if (err != SGX_SUCCESS)
    {
        // Provide only error codes that the calling code could act on
        if ((err != SGX_ERROR_INVALID_CPUSVN) && (err != SGX_ERROR_INVALID_ISVSVN))
            err = SGX_ERROR_MAC_MISMATCH;
        goto out;
    }
    err = pcl_gcm_decrypt(
        (uint8_t*)p_decrypted_text,
        (uint8_t*)p_sealed_data->aes_data.payload, 
        decrypted_text_length,
        (uint8_t*)p_aad, 
        additional_MACtext_length, 
        (uint8_t*)(&seal_key), 
        (uint8_t*)(&payload_iv[0]), 
        (uint8_t*)(p_sealed_data->aes_data.payload_tag));

    if (SGX_SUCCESS != err)
    {
        // Scrub p_decrypted_text
        pcl_volatile_memset((volatile void*)p_decrypted_text, 0, decrypted_text_length);
        goto out;
    }

    err = SGX_SUCCESS;
out:
    // Scrub seal_key
    pcl_volatile_memset((volatile void*)(&seal_key), 0, sizeof(sgx_key_128bit_t));
    return err;
}

