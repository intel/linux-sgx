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

/* Content from sdk/tseal/tSeal.cpp */

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
// pcl_unseal_data()
//      PCL version of sgx_unseal_data (needed since the SGX SDK is unavailable at this point)
// Parameters:
//        [IN] p_sealed_data - pointer to sealed key blob
//        [OUT] p_additional_MACtext - additional text to MAC
//        [IN] additional_MACtext_length - length of additional text
//        [OUT] p_decrypted_text - buffer to fill with decrypted data
//        [IN] decrypted_text_length - length of p_decrypted_text buffer
// Return Value:
//   SGX_SUCCESS or error codes
sgx_status_t pcl_unseal_data(const sgx_sealed_data_t *p_sealed_data, uint8_t *p_additional_MACtext,
    uint32_t *p_additional_MACtext_length, uint8_t *p_decrypted_text, uint32_t *p_decrypted_text_length)
{
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    // Ensure the the sgx_sealed_data_t members are all inside enclave before using them.
    if ((p_sealed_data == NULL) || (!pcl_is_within_enclave(p_sealed_data,sizeof(sgx_sealed_data_t))))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t encrypt_text_length = pcl_get_encrypt_txt_len(p_sealed_data);
    if (encrypt_text_length == UINT32_MAX)
    {
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted
    }
    uint32_t aad_text_length = pcl_get_aad_mac_txt_len(p_sealed_data);
    if (aad_text_length == UINT32_MAX)
    {
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted
    }
    uint32_t sealedDataSize = pcl_calc_sealed_data_size(aad_text_length, encrypt_text_length);
    if (sealedDataSize == UINT32_MAX)
    {
        return SGX_ERROR_MAC_MISMATCH; // Return error indicating the blob is corrupted
    }

    //
    // Check parameters
    //
    // Ensure sealed data blob is within an enclave during the sealing process
    if (!pcl_is_within_enclave(p_sealed_data,sealedDataSize))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((aad_text_length > 0) && ((p_additional_MACtext == NULL) || (p_additional_MACtext_length == NULL)))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((encrypt_text_length < 1) || (p_decrypted_text == NULL) || (p_decrypted_text_length == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!pcl_is_within_enclave(p_decrypted_text,encrypt_text_length))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!pcl_is_within_enclave(p_decrypted_text_length,sizeof(p_decrypted_text_length)))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Ensure aad data does not cross enclave boundary
    if ((aad_text_length > 0) &&
        (!(pcl_is_within_enclave(p_additional_MACtext,aad_text_length) || pcl_is_outside_enclave(p_additional_MACtext, aad_text_length))))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((*p_decrypted_text_length) < encrypt_text_length)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t additional_MACtext_length = (NULL != p_additional_MACtext_length) ? *p_additional_MACtext_length : 0;
    if (additional_MACtext_length != aad_text_length) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    err = pcl_unseal_data_helper(p_sealed_data, p_additional_MACtext, aad_text_length,
        p_decrypted_text, encrypt_text_length);
    if (err == SGX_SUCCESS)
    {
        *p_decrypted_text_length = encrypt_text_length;
        if (p_additional_MACtext_length != NULL)
            *p_additional_MACtext_length = aad_text_length;
    }
    else
    {
        // Scrub p_decrypted_text
        pcl_volatile_memset((volatile void*)p_decrypted_text, 0, encrypt_text_length);
    }
    return err;
}

