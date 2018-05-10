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
 
#include <stdint.h>
#include <stdlib.h>
#include <sgx_tseal.h>
#include <sgx_lfence.h>
#include <pcl_common.h>
#include <pcl_internal.h>

/*
 * g_tbl holds the PCL table. Its content is set by enclave encryption tool at build time
 * It is located in its own section (PCLTBL_SECTION_NAME) so that 
 * enclave encryption tool can find it. 
 */
pcl_table_t g_tbl __attribute__((section(PCLTBL_SECTION_NAME))) = {PCL_PLAIN};

/* 
 * g_pcl_imagebase is set at runtime to ELF base address. 
 * It is used by functions pcl_is_outside_enclave and pcl_is_within_enclave
 */
uintptr_t g_pcl_imagebase = 0;

/*
 * @func pcl_entry is the PCL entry point. It is called from init_enclave in 
 * trusted runtime entry point. It extracts the decryption key from the sealed blob 
 * and use it to decrypt the encrypted portions of the enclave binary. 
 * @param INOUT void* elf_base, base address of enclave
 * @param IN void* sealed_blob, the sealed blob
 * @return sgx_status_t
 * SGX_ERROR_UNEXPECTED if
 *    1. Table inconsistencies:
 *        a. PCL state in PCL table is not PCL_CIPHER
 *        b. PCL_SEALED_BLOB_MAX_SIZE < tbl->sealed_blob_size
 *    2. pcl_unseal_data returns incorrect values for either guid size or key size 
 * Respective error returned from pcl_unseal_data, pcl_sha256, pcl_gcm_decrypt or pcl_increment_iv
 * SGX_SUCCESS if successfull
 */
sgx_status_t pcl_entry(void* elf_base, void* sealed_blob)
{
    sgx_status_t ret = SGX_SUCCESS;  
    pcl_table_t* tbl = &g_tbl;
    unsigned char* iv = NULL;
    int memcmpret = 0;
    sgx_sha256_hash_t hash = {0};
    sgx_aes_gcm_128bit_key_t key = {0};

    // Verify PCL state:
    if(PCL_CIPHER != tbl->pcl_state)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    tbl->pcl_state = PCL_RUNNING;

    // ELF base address used by pcl_is_outside_enclave and pcl_is_within_enclave
    g_pcl_imagebase = (uintptr_t)elf_base;

    // Get key from sealed blob:
    uint32_t guid_size = SGX_PCL_GUID_SIZE;
    uint32_t key_size = SGX_AESGCM_KEY_SIZE;

    // Verify the buffer size: 
    if(PCL_SEALED_BLOB_SIZE != tbl->sealed_blob_size)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    if(!(pcl_is_outside_enclave(sealed_blob, PCL_SEALED_BLOB_SIZE)))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    // LFENCE after boundary check 
    sgx_lfence();

    // Copy sealed blob into enclave binary. 
    pcl_memcpy(tbl->sealed_blob, sealed_blob, PCL_SEALED_BLOB_SIZE);
    
    // Unseal the sealed blob: 
    ret = pcl_unseal_data(
            (const sgx_sealed_data_t*)tbl->sealed_blob, // Sealed data
            tbl->pcl_guid,                              // AAD buffer
            &guid_size,                                 // pointer to AAD buffer length 
            key,                                        // Resulting key
            &key_size);                                 // Size of resulting key
    if(SGX_SUCCESS != ret)
    {
        goto Label_erase_key;
    }
    if((sizeof(tbl->pcl_guid) != guid_size) ||
       (sizeof(key)           != key_size ))
    {
        ret = SGX_ERROR_UNEXPECTED;
        goto Label_erase_key;
    }
    
    // Verify key hash matches:
    ret = pcl_sha256(key, SGX_AESGCM_KEY_SIZE, hash);
    if(SGX_SUCCESS != ret)
    {
        goto Label_erase_key; 
    }
    memcmpret = pcl_consttime_memequal(hash, tbl->decryption_key_hash, sizeof(sgx_sha256_hash_t));
    pcl_volatile_memset((volatile void*)hash, 0, sizeof(sgx_sha256_hash_t)); // Scrub hash
    if(1 != memcmpret)
    {
        ret = SGX_ERROR_PCL_SHA_MISMATCH;
        goto Label_erase_key;
    }

    for(uint32_t i = 0;i< tbl->num_rvas;i++)
    {
        size_t size = tbl->rvas_sizes_tags_ivs[i].size;
        unsigned char* ciphertext = (unsigned char *)((uint64_t)elf_base + tbl->rvas_sizes_tags_ivs[i].rva);
        unsigned char* plaintext = ciphertext; // decrypt in place
        unsigned char* tag = (unsigned char *)&(tbl->rvas_sizes_tags_ivs[i].tag);
        unsigned char* iv  = (unsigned char *)&(tbl->rvas_sizes_tags_ivs[i].iv.val);
        // Verify ciphertext is inside the enclave:
        if(!(pcl_is_within_enclave(ciphertext, size)))
        {
            ret = SGX_ERROR_UNEXPECTED; 
            goto Label_erase_key;
        }
        ret = pcl_gcm_decrypt(plaintext, ciphertext, size, NULL, 0, key, iv, tag);
        if(SGX_SUCCESS != ret)
        {
            goto Label_erase_key;
        }
    }

    // Return success:
    ret = SGX_SUCCESS;
    
Label_erase_key:
    // Erase key:
    pcl_volatile_memset((volatile void*)key, 0, sizeof(sgx_aes_gcm_128bit_key_t));
    tbl->pcl_state = PCL_DONE;
    return ret;
}

/*
 * @func pcl_bswap32 swaps a 32bit value endianity
 * @param uint32_t val, input value
 * @return uint32_t, val in opposite endianity
 */
uint32_t pcl_bswap32(uint32_t val)
{
    uint32_t ret=(val);
    asm ("bswap %0":"+r"(ret));
    return ret;          
}

