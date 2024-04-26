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

#include "sgx_tcrypto.h"
#include "ippcp.h"
#include "ippcp/fips_cert.h"
#include "se_cpu_feature.h"
#include "se_cdefs.h"
#include "sgx_error.h"
#include "ipp_wrapper.h"
#include "global_data.h"

#define ERROR_SELFTEST_BREAK(test_result)     \
    if (test_result != IPPCP_ALGO_SELFTEST_OK) \
    {                                          \
        break;                                 \
    }
#define ALLOC_ERROR_BREAK(pointer, ret)  \
    if (pointer == NULL)                 \
    {                                  \
        ret = SGX_ERROR_OUT_OF_MEMORY; \
        break;                         \
    }

#define FIPS_SELFTEST_FUNC(result, func) \
    result = func();                     \
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_1(result, func, para) \
    result = func(para);                       \
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_2(result, func, para1, para2) \
    result = func(para1, para2);\
    ERROR_SELFTEST_BREAK(result)

#define FIPS_SELFTEST_FUNC_3(result, func, para1, para2, para3) \
    result = func(para1, para2, para3);\
    ERROR_SELFTEST_BREAK(result)


/* Encrypt/Decrypt */
static sgx_status_t encrypt_decrypt_self_test()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
    int buf_size = 0;
    uint8_t *p_buf = NULL;
    int key_buf_size = 0;
    uint8_t *p_key_buf = NULL;
    do
    {
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptDecrypt_get_size, &buf_size);
        p_buf = (uint8_t *)malloc(buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCBC, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCBC, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCBC_CS1, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCBC_CS2, p_buf); 
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCBC_CS3, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCBC_CS1, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCBC_CS2, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCBC_CS3, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCFB, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCFB, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptOFB, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptOFB, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptCTR, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESDecryptCTR, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAESEncryptDecryptCCM_get_size, &buf_size);
        p_buf = (uint8_t *)realloc(p_buf, buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_CCMEncrypt, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_CCMDecrypt, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_GCM_get_size, &buf_size);
        p_buf = (uint8_t *)realloc(p_buf, buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_GCMEncrypt, p_buf);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_GCMDecrypt, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_CMAC_get_size, &buf_size);
        p_buf = (uint8_t *)realloc(p_buf, buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsAES_CMACUpdate, p_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size_keys, &key_buf_size);
        p_key_buf = (uint8_t *)malloc(key_buf_size);
        ALLOC_ERROR_BREAK(p_key_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size, &buf_size, p_key_buf);
        p_buf = (uint8_t *)realloc(p_buf, buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSAEncrypt_OAEP_rmf, p_buf, p_key_buf);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSADecrypt_OAEP_rmf, p_buf, p_key_buf);
        ret = SGX_SUCCESS;
    } while (0);
    SAFE_FREE(p_buf);
    SAFE_FREE(p_key_buf);
    return ret;
}

/* Hash */
static sgx_status_t hash_self_test()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
    int buf_size = 0;
    uint8_t *p_buf = NULL;
    do
    {
        // Hashes
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHash_rmf_get_size, &buf_size);
        p_buf = (uint8_t *)malloc(buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);

        // We only check below HASH algorithms
        IppHashAlgId ids[] = {ippHashAlg_SHA224, ippHashAlg_SHA256, ippHashAlg_SHA384, ippHashAlg_SHA512};
        for (uint32_t i = 0; i < sizeof(ids)/sizeof(ids[0]); i++)
        {
            FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsHashUpdate_rmf, (IppHashAlgId)ids[i], p_buf);
            FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHashMessage_rmf, (IppHashAlgId)ids[i]);
        }
        ret = SGX_SUCCESS;
    } while (0);
    SAFE_FREE(p_buf);
    return ret;
}

/* HMAC */
static sgx_status_t hmac_self_test()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
    int buf_size = 0;
    uint8_t *p_buf = NULL;
    do
    {
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHMAC_rmf_get_size, &buf_size);
        p_buf = (uint8_t *)malloc(buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsHMACUpdate_rmf, p_buf);
        FIPS_SELFTEST_FUNC(test_result, fips_selftest_ippsHMACMessage_rmf);
        ret = SGX_SUCCESS;
    } while (0);
    SAFE_FREE(p_buf);
    return ret;
}

/* RSA sign/verify */
static sgx_status_t rsa_sign_verfy_self_test()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
    int buf_size = 0;
    uint8_t *p_buf = NULL;
    int key_buf_size = 0;
    uint8_t *p_key_buf = NULL;
    do
    {
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsRSASignVerify_PKCS1v15_rmf_get_size_keys, &key_buf_size);
        p_key_buf = (uint8_t *)malloc(key_buf_size);
        ALLOC_ERROR_BREAK(p_key_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSASignVerify_PKCS1v15_rmf_get_size, &buf_size, p_key_buf);
        p_buf = (uint8_t *)malloc(buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSASign_PKCS1v15_rmf, p_buf, p_key_buf);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSAVerify_PKCS1v15_rmf, p_buf, p_key_buf);

        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys, &key_buf_size);
        p_key_buf = (uint8_t *)realloc(p_key_buf, key_buf_size);
        ALLOC_ERROR_BREAK(p_key_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size, &buf_size, p_key_buf);
        p_buf = (uint8_t *)realloc(p_buf, buf_size);
        ALLOC_ERROR_BREAK(p_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSASign_PSS_rmf, p_buf, p_key_buf);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSAVerify_PSS_rmf, p_buf, p_key_buf);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsRSA_GenerateKeys, p_buf, p_key_buf);
        ret = SGX_SUCCESS;
    } while (0);
    SAFE_FREE(p_buf);
    SAFE_FREE(p_key_buf);
    return ret;
}

/* ECDSA sign/verify */
static sgx_status_t ecdsa_sign_verify_self_test()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;
    int gfp_buf_size = 0;
    uint8_t *p_gfp_buf = NULL;
    int ec_buf_size = 0;
    uint8_t *p_ec_buf = NULL;
    int data_buf_size = 0;
    uint8_t *p_data_buf = NULL;
    do
    {
        FIPS_SELFTEST_FUNC_1(test_result, fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFp_buff, &gfp_buf_size);
        p_gfp_buf = (uint8_t *)malloc(gfp_buf_size);
        ALLOC_ERROR_BREAK(p_gfp_buf, ret);
        FIPS_SELFTEST_FUNC_2(test_result, fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFpEC_buff, &ec_buf_size, p_gfp_buf);
        p_ec_buf = (uint8_t *)malloc(ec_buf_size);
        ALLOC_ERROR_BREAK(p_ec_buf, ret);
        FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECSignVerifyDSA_get_size_data_buff, &data_buf_size, p_gfp_buf, p_ec_buf);
        p_data_buf = (uint8_t *)malloc(data_buf_size);
        ALLOC_ERROR_BREAK(p_data_buf, ret);        
        FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECSignDSA, p_gfp_buf, p_ec_buf, p_data_buf);
        FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECVerifyDSA, p_gfp_buf, p_ec_buf, p_data_buf);
        FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECPublicKey, p_gfp_buf, p_ec_buf, p_data_buf);
        FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECSharedSecretDH, p_gfp_buf, p_ec_buf, p_data_buf);

        ret = SGX_SUCCESS;
    } while (0);
    SAFE_FREE(p_gfp_buf);
    SAFE_FREE(p_ec_buf);
    SAFE_FREE(p_data_buf);
    return ret;
}

/* FIPS selftest
 *   Should only be called if require to run in FIPS mode */
extern "C" sgx_status_t sgx_crypto_fips_selftest()
{
    sgx_status_t ret = encrypt_decrypt_self_test();
    if (ret != SGX_SUCCESS)
        return ret;
    ret = hash_self_test();
    if (ret != SGX_SUCCESS)
        return ret;
    ret = hmac_self_test();
    if (ret != SGX_SUCCESS)
        return ret;
    ret = rsa_sign_verfy_self_test();
    if (ret != SGX_SUCCESS)
        return ret;
    ret = ecdsa_sign_verify_self_test();
    return ret;
}

sgx_status_t sgx_is_fips_approved_func(sgx_fips_func_t func, func_fips_approved_t *is_approved)
{
    if (is_approved == NULL)
        return SGX_ERROR_INVALID_PARAMETER;
    bool ret = func > 0 ? true : false;

    if (ret == true)
    {
        *is_approved = 1;
    }
    else
    {
        *is_approved = 0;
    }
    return SGX_SUCCESS;
}
