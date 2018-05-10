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

/* Content from sdk/tseal/tSeal_util.cpp */

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
// pcl_calc_sealed_data_size()
//      computes sealedDataSize = payload size + sizeof(sgx_sealed_data_t)
// Parameters:
//        [IN] aad_mac_txt_size - optional additional data size
//        [IN] txt_encrypt_size - the actual encrypted data (payload)
// Return Value:
//      sealedDataSize
uint32_t pcl_calc_sealed_data_size(const uint32_t aad_mac_txt_size, const uint32_t txt_encrypt_size)
{
    // code copied from tseal_util.cpp from the tseal library
    if (aad_mac_txt_size > UINT32_MAX - txt_encrypt_size)
        return UINT32_MAX;
    uint32_t payload_size = aad_mac_txt_size + txt_encrypt_size; //Calculate the payload size

    if (payload_size > UINT32_MAX - sizeof(sgx_sealed_data_t))
        return UINT32_MAX;
    return (uint32_t)(sizeof(sgx_sealed_data_t) + payload_size);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pcl_get_aad_mac_txt_len()
//      computes optional additional data size
// Parameters:
//        [IN] p_sealed_data - pointer to the sealed blob
// Return Value:
//      additional data size
uint32_t pcl_get_aad_mac_txt_len(const sgx_sealed_data_t* p_sealed_data)
{
    if (p_sealed_data == NULL)
        return UINT32_MAX;

    uint32_t data_size = p_sealed_data->aes_data.payload_size - p_sealed_data->plain_text_offset;
    if (data_size > p_sealed_data->aes_data.payload_size)
        return UINT32_MAX;
    return data_size;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pcl_get_encrypt_txt_len()
//      computes encrypted data size
// Parameters:
//        [IN] p_sealed_data - pointer to the sealed blob
// Return Value:
//      encrypted data size
uint32_t pcl_get_encrypt_txt_len(const sgx_sealed_data_t* p_sealed_data)
{
    return ((p_sealed_data == NULL) ? UINT32_MAX : p_sealed_data->plain_text_offset);
}

