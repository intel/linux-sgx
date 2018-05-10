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

/* Includes common to PCL unsealing files*/

#ifndef SGX_PCL_UNSEAL_INTERNAL_H
#define SGX_PCL_UNSEAL_INTERNAL_H

#define BIT_ERROR(x)            (1 << (x))


// Key request defines: 
#define KEY_ALIGN_SIZE (16)
#define KEY_REQUEST_SIZE (512)
#define KEY_REQUEST_ALIGN_SIZE (512)
#define PCL_EGETKEY_BUFFER_SIZE (2 * KEY_REQUEST_ALIGN_SIZE + KEY_ALIGN_SIZE - 1)
PCL_COMPILE_TIME_ASSERT(KEY_REQUEST_ALIGN_SIZE >= KEY_ALIGN_SIZE);

extern "C" 
{

extern uint8_t ip1_buf[];

int do_egetkey(const sgx_key_request_t *key_request, sgx_key_128bit_t *key);

sgx_status_t pcl_unseal_data_helper(const sgx_sealed_data_t *p_sealed_data, uint8_t *p_additional_MACtext,
    uint32_t additional_MACtext_length, uint8_t *p_decrypted_text, uint32_t decrypted_text_length);
sgx_status_t pcl_sgx_get_key(const sgx_key_request_t *key_request, sgx_key_128bit_t *key);
// Typedefs:
typedef enum _egetkey_status_t
{
    EGETKEY_SUCCESS           = 0,
    EGETKEY_INVALID_ATTRIBUTE = BIT_ERROR(1),
    EGETKEY_INVALID_CPUSVN    = BIT_ERROR(5),
    EGETKEY_INVALID_ISVSVN    = BIT_ERROR(6),
    EGETKEY_INVALID_KEYNAME   = BIT_ERROR(8),
}  egetkey_status_t;

uint32_t pcl_calc_sealed_data_size(const uint32_t aad_mac_txt_size, const uint32_t txt_encrypt_size);
uint32_t pcl_get_aad_mac_txt_len(const sgx_sealed_data_t* p_sealed_data);
uint32_t pcl_get_encrypt_txt_len(const sgx_sealed_data_t* p_sealed_data);

#ifdef SE_SIM

egetkey_status_t pcl_egetkey(sgx_key_request_t* kr, sgx_key_128bit_t okey);
void pcl_derive_key(const derivation_data_t* dd, sgx_key_128bit_t okey);

#endif // #ifdef SE_SIM

}; // extern "C" 

#endif // #ifndef SGX_PCL_UNSEAL_INTERNAL_H

