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

/* Content from sdk/selib/sgx_get_key.cpp */

#include <stdint.h>
#include <stdlib.h>
#include <sgx_tseal.h>
#ifdef SE_SIM
#include <deriv.h>
#endif // #ifdef SE_SIM
#include <pcl_common.h>
#include <pcl_internal.h>
#include <pcl_unseal_internal.h>

PCL_COMPILE_TIME_ASSERT(KEY_ALIGN_SIZE            == SGX_AESGCM_KEY_SIZE) ;
PCL_COMPILE_TIME_ASSERT(sizeof(sgx_key_128bit_t)  == SGX_AESGCM_KEY_SIZE) ;
PCL_COMPILE_TIME_ASSERT(KEY_REQUEST_ALIGN_SIZE    == KEY_REQUEST_SIZE);
PCL_COMPILE_TIME_ASSERT(sizeof(sgx_key_request_t) == KEY_REQUEST_SIZE);
uint8_t ip1_buf[PCL_EGETKEY_BUFFER_SIZE];

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pcl_sgx_get_key()
//      Intel(R) SGX PCL version of sgx_get_key. 
//      It is requried because the Intel(R) SGX SDK is unavailable at
//      this point
// Parameters:
//        [IN] key_request - pointer to key_request structure
//        [OUT] key - resulting key
// Return Value:
//   SGX_SUCCESS or error codes
sgx_status_t pcl_sgx_get_key(IN const sgx_key_request_t *key_request, OUT sgx_key_128bit_t *key)
{
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    void *buffer = NULL;
    size_t size = 0, buf_ptr =0;
    sgx_key_request_t *tmp_key_request = NULL;
    sgx_key_128bit_t *tmp_key = NULL;
    egetkey_status_t egetkey_status = EGETKEY_SUCCESS;
    int i = 0;

    // check parameters
    //
    // key_request must be within the enclave
    if(!key_request || !pcl_is_within_enclave(key_request, sizeof(*key_request)))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }

    if (key_request->reserved1 != 0)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }

    for (i=0; i<SGX_KEY_REQUEST_RESERVED2_BYTES; ++i)
    {
        if (key_request->reserved2[i] != 0)
        {
            err = SGX_ERROR_INVALID_PARAMETER;
            goto CLEANUP;
        }
    }

    // key must be within the enclave
    if(!key || !pcl_is_within_enclave(key, sizeof(*key)))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }
    // check key_request->key_policy reserved bits
    if(key_request->key_policy & ~(SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }

    // allocate memory
    // 
    // To minimize the effort of memory management, the two elements allocation 
    // are combined in a single malloc. The calculation for the required size has
    // an assumption, that
    // the elements should be allocated in descending order of the alignment size. 
    //
    // If the alignment requirements are changed, the allocation order needs to
    // change accordingly.
    //
    // Current allocation order is:
    //     key_request -> key
    //
    // key_request: 512-byte aligned, 512-byte length
    // key:          16-byte aligned,  16-byte length
    size = ROUND_TO(sizeof(*key_request), KEY_REQUEST_ALIGN_SIZE) + ROUND_TO(sizeof(*key), KEY_ALIGN_SIZE);
    size += MAX(KEY_REQUEST_ALIGN_SIZE, KEY_ALIGN_SIZE) - 1;

    // There is no heap during Intel(R) SGX PCL execution. 
    // Must use global memory
    buffer = &ip1_buf[0];
    pcl_memset(buffer, 0, size);
    buf_ptr = reinterpret_cast<size_t>(buffer);

    buf_ptr = ROUND_TO(buf_ptr, KEY_REQUEST_ALIGN_SIZE);
    tmp_key_request = reinterpret_cast<sgx_key_request_t *>(buf_ptr);
    buf_ptr += sizeof(*tmp_key_request);

    buf_ptr = ROUND_TO(buf_ptr, KEY_ALIGN_SIZE);
    tmp_key = reinterpret_cast<sgx_key_128bit_t *>(buf_ptr);

    // Copy data from user buffer to the aligned memory
    pcl_memcpy(tmp_key_request, (void*)key_request, sizeof(*tmp_key_request));

    // Do EGETKEY
#ifndef SE_SIM
    egetkey_status = (egetkey_status_t) do_egetkey(tmp_key_request, tmp_key);
#else
    egetkey_status = (egetkey_status_t)pcl_egetkey(tmp_key_request,(uint8_t *)tmp_key);
#endif
    switch(egetkey_status)
    {
    case EGETKEY_SUCCESS:
        err = SGX_SUCCESS;
        break;
    case  EGETKEY_INVALID_ATTRIBUTE:
        err =  SGX_ERROR_INVALID_ATTRIBUTE;
        break;
    case EGETKEY_INVALID_CPUSVN:
        err =  SGX_ERROR_INVALID_CPUSVN;
        break;
    case EGETKEY_INVALID_ISVSVN:
        err = SGX_ERROR_INVALID_ISVSVN;
        break;
    case EGETKEY_INVALID_KEYNAME:
        err = SGX_ERROR_INVALID_KEYNAME;
        break;
    default:
        err = SGX_ERROR_UNEXPECTED;
        break;
    }


CLEANUP:
    /* 
     * - If success, copy resulting key into key buffer. 
     * - In case of failure, leave the key buffer untouched becuase
     *   Intel(R) SGX PCL does not call sgx_read_rand. 
     */
    if((SGX_SUCCESS == err) && (NULL != key))
    {
        // Copy data to the user buffer
        pcl_memcpy(key, tmp_key, sizeof(*key));
    }

    // cleanup
    if(buffer)
    {
        pcl_volatile_memset((volatile void*)buffer, 0, size);
    }

    return err;
}
