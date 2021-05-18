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

#include <sgx_tseal.h>
#include "Seal_t.h"
#include <memory>
#include <sgx_pcl_guid.h>

/**
 * @func provision_key_mock assigns the decryption key
 * @param uint8_t* key_ptr: pointer to a key buffer allocated by caller.
 * @param uint32_t key_len: key buffer size.
 * @return sgx_status_t 
 * SGX_ERROR_INVALID_PARAMETER if key size is not SGX_AESGCM_KEY_SIZE or if key_ptr is NULL
 * SGX_SUCCESS if success
 * Notice: Function returns a hardcoded key. Never use in release code!!!
 * ISV must replace with secured key provisioning scheme, e.g. using remote attestation & TLS.
 */
sgx_status_t provision_key_mock (uint8_t* key_ptr, uint32_t key_len )
{
    if ( (NULL == key_ptr) || (SGX_AESGCM_KEY_SIZE != key_len))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    const uint8_t key[SGX_AESGCM_KEY_SIZE] = 
        { 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99 };
    memcpy (key_ptr, key, key_len);
    return SGX_SUCCESS;
}

/*
 * @func provision_key provisions the key to the ISVs platform
 * @param uint8_t* key_ptr is the resulting decryption key
 * @param uint32_t key_len is key size in bytes
 * @return sgx_status_t, SGX_SUCCESS if function passes
 * @warning ISV must replace content of this function with ISVs scheme to provision
 * the decryption key to the platform 
 */
sgx_status_t provision_key( uint8_t* key_ptr, uint32_t key_len )
{
    /* 
     * ISV must replace call to provision_key_mock with an alternative ISV's secured key provisioning scheme, e.g. using remote attestation & TLS.
     * For more details, see 'Intel(R) SGX PCL Linux User Guide.pdf', chapter 'Integration with PCL', sub chapter 'Sealing Enclave'.
     */
    return provision_key_mock(key_ptr, key_len);
}

extern "C" 
{

/*
 * @func ecall_get_sealed_blob_size returns the PCL sealed blob size
 * @return size_t, size of PCL sealed blob size in bytes
 */
size_t ecall_get_sealed_blob_size()
{
    return (size_t)sgx_calc_sealed_data_size ( SGX_PCL_GUID_SIZE, SGX_AESGCM_KEY_SIZE );
}

/*
 * @func ecall_generate_sealed_blob generates the sealed blob
 * @param uint8_t* sealed_blob is the resulting sealed blob
 * @param uint32_t sealed_blob_size is sealed blob size in bytes
 * @return sgx_status_t
 * SGX_ERROR_INVALID_PARAMETER if sealed_blob is NULL or if sealed_blob_size does not match PCL sealed blob size
 * The respective error in case provision_key  or sgx_seal_data fail
 * SGX_SUCCESS if function passes
 */
sgx_status_t ecall_generate_sealed_blob(uint8_t* sealed_blob, size_t sealed_blob_size)
{
    if ((NULL == sealed_blob) || (ecall_get_sealed_blob_size() != sealed_blob_size))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    sgx_status_t retstatus = SGX_ERROR_UNEXPECTED;
    uint8_t key[SGX_AESGCM_KEY_SIZE] = { 0 };
    
    retstatus = provision_key(key, SGX_AESGCM_KEY_SIZE);
    if (retstatus != SGX_SUCCESS )
    {
        return retstatus;
    }
    
    retstatus = sgx_seal_data (
        SGX_PCL_GUID_SIZE,                 // AAD size
        g_pcl_guid,                        // AAD
        SGX_AESGCM_KEY_SIZE,               // Key len
        key,                               // Key
        (uint32_t)sealed_blob_size,                  // Resulting blob size
        (sgx_sealed_data_t*)sealed_blob ); // Resulting blob

    memset(key, 0,SGX_AESGCM_KEY_SIZE); 
    return retstatus;
}

};    // extern "C"

