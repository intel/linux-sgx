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

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/modes.h>
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>
#include <pcl_common.h>
#include <pcl_internal.h>
#include <pcl_crypto_internal.h>

/*
 * @func pcl_gcm_decrypt applies AES-GCM-128
 * @param OUT uint8_t* plaintext, input plain text buffer
 * @param IN uint8_t* ciphertext, output cipher text buffer
 * @param size_t textlen, size of buffer in bytes
 * @param IN uint8_t* aad, aditional authenticated data
 * @param size_t aad_len, size of aditional authenticated data
 * @param IN uint8_t* key, 16 bytes decryption key
 * @param IN uint8_t* iv, 12 bytes IV
 * @param IN uint8_t* tag, 16 bytes TAG result
 * @return sgx_status_t
 * SGX_ERROR_INVALID_PARAMETER if any pointer is NULL except for aad
 * SGX_ERROR_UNEXPECTED if any of the following functions fail: 
 * pcl_vpaes_set_encrypt_key, pcl_CRYPTO_gcm128_aad or pcl_CRYPTO_gcm128_decrypt
 * SGX_ERROR_PCL_MAC_MISMATCH if MAC mismatch when calling pcl_CRYPTO_gcm128_finish
 * SGX_SUCCESS if successfull
 */
sgx_status_t pcl_gcm_decrypt(
                OUT uint8_t* plaintext, 
                IN uint8_t* ciphertext, 
                size_t textlen,
                IN uint8_t* aad, 
                size_t aad_len, 
                IN uint8_t* key, 
                IN uint8_t* iv, 
                IN uint8_t* tag)
{
    sgx_status_t ret_status = SGX_ERROR_INVALID_PARAMETER;
    
    if( NULL == plaintext  ||
        NULL == ciphertext ||
        NULL == key        || 
        NULL == iv         ||
        NULL == tag)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    AES_KEY wide_key = { 0 };
    GCM128_CONTEXT gcm_ctx;
    
    int ret = pcl_vpaes_set_encrypt_key(key, PCL_AES_BLOCK_LEN_BITS, &wide_key);
    if(0 != ret) 
    {
        ret_status = SGX_ERROR_UNEXPECTED;
        goto Label_zero_wide_key;
    }
    
    pcl_CRYPTO_gcm128_init(&gcm_ctx, &wide_key, (block128_f)pcl_vpaes_encrypt);
    
    pcl_CRYPTO_gcm128_setiv(&gcm_ctx, iv, SGX_AESGCM_IV_SIZE);
    
    if(NULL != aad)
    {
        ret = pcl_CRYPTO_gcm128_aad(&gcm_ctx, aad, aad_len);
        if(0 != ret)
        {
            ret_status = SGX_ERROR_UNEXPECTED;
            goto Label_zero_buffers;
        }
    }
    
    ret = pcl_CRYPTO_gcm128_decrypt(
                &gcm_ctx, 
                ciphertext, 
                plaintext, 
                textlen);
    if(0 != ret)
    {
        ret_status = SGX_ERROR_UNEXPECTED;
        goto Label_zero_buffers;
    }
    
    ret = pcl_CRYPTO_gcm128_finish(&gcm_ctx, tag, SGX_CMAC_MAC_SIZE);
    if(0 != ret)
    {
        ret_status =  SGX_ERROR_PCL_MAC_MISMATCH;
        goto Label_zero_buffers;
    }
    
    ret_status = SGX_SUCCESS;
    
    // Scrab secrets from stack:
Label_zero_buffers:
    pcl_volatile_memset((volatile void*)(&gcm_ctx), 0, sizeof(gcm_ctx));
Label_zero_wide_key:
    pcl_volatile_memset((volatile void*)(&wide_key), 0, sizeof(wide_key));

    return ret_status;
}

/*
 * @func pcl_sha256 calculates the payload SHA256
 * @param IN uint8_t* buf, payload buffer
 * @param size_t buflen, buffer size in bytes
 * @param OUT uint8_t* hash, SHA256 result
 */
sgx_status_t pcl_sha256(IN uint8_t* buf, size_t buflen, OUT uint8_t* hash)
{
    if(NULL == buf || NULL == hash)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    SHA256_CTX sha256;
    
    pcl_SHA256_Init(&sha256);
    
    pcl_SHA256_Update(&sha256, buf, buflen);
    
    pcl_SHA256_Final(hash, &sha256);
    
    pcl_volatile_memset((volatile void*)(&sha256), 0, sizeof(SHA256_CTX));
    
    return SGX_SUCCESS;
}

#ifdef SE_SIM

/*
 * @func pcl_cmac calcualtes CMAC-128 on payload
 * @param IN const sgx_cmac_128bit_key_t *p_key, CMAC key
 * @param IN const uint8_t *p_src, input buffer
 * @param uint32_t src_len, buffer size in bytes
 * @param OUT sgx_cmac_128bit_tag_t *p_mac, 16 bytes resulting MAC
 * @return int, -1 if p_key, p_src or p_mac are NULL, 0 if success
 */
int pcl_cmac(
    const sgx_cmac_128bit_key_t *p_key, 
    const uint8_t *p_src,
    uint32_t src_len,
    sgx_cmac_128bit_tag_t *p_mac)
{
    if(NULL == p_key || NULL == p_src || NULL == p_mac)
    {
        return -1;
    }
    unsigned char iv[PCL_COUNTER_SIZE] = { 0 };
    unsigned char aux[PCL_AES_BLOCK_LEN] = { 0 };
    unsigned char k1[PCL_AES_BLOCK_LEN] = { 0 };

    AES_KEY wide_key;
    pcl_vpaes_set_encrypt_key((const unsigned char *)p_key, PCL_AES_BLOCK_LEN_BITS, &wide_key);
    
    // Apply AES-CBC encrypt on input = 0^16 and IV = 0^16: 
    pcl_vpaes_cbc_encrypt(iv, aux, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
    
    // Use result to generate K1:
    make_kn(k1, aux, PCL_AES_BLOCK_LEN);
    
    // Digest message except for last block:
    pcl_memset(iv, 0, PCL_COUNTER_SIZE);
    while(src_len >  PCL_AES_BLOCK_LEN)
    {
        pcl_vpaes_cbc_encrypt((uint8_t *)p_src, aux, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
        src_len -= PCL_AES_BLOCK_LEN;
        p_src += PCL_AES_BLOCK_LEN;
    }
    
    
    // XOR K1 with last block of message: 
    for (int i = 0; i < PCL_AES_BLOCK_LEN; i++)aux[i] = p_src[i] ^ k1[i];
        
    // Apply AES-CBC encrypt on result and IV
    pcl_vpaes_cbc_encrypt(aux, (uint8_t*)p_mac, PCL_AES_BLOCK_LEN, &wide_key, iv, 1);
    return 0;
}

#endif // #ifdef SE_SIM

