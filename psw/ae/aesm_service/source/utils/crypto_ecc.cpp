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

#include "ssl_crypto.h"
#include "ssl_compat_wrapper.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/*
* Elliptic Curve Cryptography - Based on GF(p), 256 bit
*/
/* Allocates and initializes ecc context
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Output: sgx_ecc_state_handle_t *p_ecc_handle - Pointer to the handle of ECC crypto system  */
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle)
{
    if (p_ecc_handle == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t retval = SGX_SUCCESS;

    /* construct a curve p-256 */
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (NULL == ec_group)
    {
        retval = SGX_ERROR_UNEXPECTED;
    }
    else
    {
        *p_ecc_handle = (void*)ec_group;
    }
    return retval;
}

/* Cleans up ecc context
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Output: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system  */
sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle)
{
    if (ecc_handle == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    EC_GROUP_free((EC_GROUP*)ecc_handle);

    return SGX_SUCCESS;
}

static EVP_PKEY *get_pub_key_from_coords(const sgx_ec256_public_t *p_public, sgx_ecc_state_handle_t ecc_handle)
{
    EVP_PKEY *evp_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    BIGNUM *bn_pub_x = NULL;
    BIGNUM *bn_pub_y = NULL;
    EC_POINT *point = NULL;
    EC_GROUP *group = (EC_GROUP *)ecc_handle;
    OSSL_PARAM_BLD *params_build = NULL;
    OSSL_PARAM *params = NULL;
    const char *curvename = NULL;
    int nid = 0;
    size_t key_len;
    unsigned char pub_key[SGX_ECP256_KEY_SIZE+4];

    do {
        // converts the x value of public key, represented as positive integer in little-endian into a BIGNUM
        bn_pub_x = BN_lebin2bn((unsigned char*)p_public->gx, sizeof(p_public->gx), bn_pub_x);
        if (NULL == bn_pub_x) {
            break;
        }
        // converts the y value of public key, represented as positive integer in little-endian into a BIGNUM
        bn_pub_y = BN_lebin2bn((unsigned char*)p_public->gy, sizeof(p_public->gy), bn_pub_y);
        if (NULL == bn_pub_y) {
            break;
        }
        // creates new point and assigned the group object that the point relates to
        point = EC_POINT_new(group);
        if (NULL == point) {
            break;
        }

        // sets point based on public key's x,y coordinates
        if (1 != EC_POINT_set_affine_coordinates(group, point, bn_pub_x, bn_pub_y, NULL)) {
            break;
        }

        // check point if the point is on curve
        if (1 != EC_POINT_is_on_curve(group, point, NULL)) {
            break;
        }

        // convert point to octet string
        key_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pub_key, sizeof(pub_key), NULL);
        if (key_len == 0) {
            break;
        }

        // build OSSL_PARAM
        params_build = OSSL_PARAM_BLD_new();
        if (NULL == params_build) {
            break;
        }
        nid = EC_GROUP_get_curve_name((EC_GROUP *)ecc_handle);
        if (nid == NID_undef) {
            break;
        }
        curvename = OBJ_nid2sn(nid);
        if (curvename == NULL) {
            break;
        }
        if (1 != OSSL_PARAM_BLD_push_utf8_string(params_build, "group", curvename, 0)) {
            break;
        }
        if (1 != OSSL_PARAM_BLD_push_octet_string(params_build, OSSL_PKEY_PARAM_PUB_KEY, pub_key, key_len)) {
            break;
        }
        params = OSSL_PARAM_BLD_to_param(params_build);
        if (NULL == params) {
            break;
        }

        // get pkey from params
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (NULL == pkey_ctx) {
            break;
        }
        if (1 != EVP_PKEY_fromdata_init(pkey_ctx)) {
            break;
        }
        if (1 != EVP_PKEY_fromdata(pkey_ctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params)) {
            EVP_PKEY_free(evp_key);
            evp_key = NULL;
        }
    } while(0);

    BN_clear_free(bn_pub_x);
    BN_clear_free(bn_pub_y);
    EC_POINT_clear_free(point);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(pkey_ctx);

    return evp_key;
}

/* Verifies the signature for the given data based on the public key
*
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
*           sgx_ec256_public_t *p_public - Pointer to the public key
*           uint8_t *p_data - Pointer to the data to be signed
*           uint32_t data_size - Size of the data to be signed
*           sgx_ec256_signature_t *p_signature - Pointer to the signature
*   Output: uint8_t *p_result - Pointer to the result of verification check  */
sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data,
                              uint32_t data_size,
                              const sgx_ec256_public_t *p_public,
                              const sgx_ec256_signature_t *p_signature,
                              uint8_t *p_result,
                              sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_public == NULL) || (p_signature == NULL) ||
        (p_data == NULL) || (data_size < 1) || (p_result == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    BIGNUM *bn_r = NULL;
    BIGNUM *bn_s = NULL;
    EVP_PKEY *evp_pkey = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;
    unsigned char *sig = NULL;
    int siglen = 0;
    unsigned char digest[SGX_SHA256_HASH_SIZE] = { 0 };
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
    int valid = 0;

    *p_result = SGX_EC_INVALID_SIGNATURE;


    do {
        evp_pkey = get_pub_key_from_coords(p_public, ecc_handle);
        if (NULL == evp_pkey)
        {
            break;
        }
        // converts the x value of the signature, represented as positive integer in little-endian into a BIGNUM
        //
        bn_r = BN_lebin2bn((unsigned char*)p_signature->x, sizeof(p_signature->x), 0);
        if (NULL == bn_r)
        {
            break;
        }

        // converts the y value of the signature, represented as positive integer in little-endian into a BIGNUM
        //
        bn_s = BN_lebin2bn((unsigned char*)p_signature->y, sizeof(p_signature->y), 0);
        if (NULL == bn_s)
        {
            break;
        }

        // allocates a new ECDSA_SIG structure (note: this function also allocates the BIGNUMs) and initialize it
        //
        ecdsa_sig = ECDSA_SIG_new();
        if (NULL == ecdsa_sig)
        {
            retval = SGX_ERROR_OUT_OF_MEMORY;
            break;
        }

        // setes the r and s values of ecdsa_sig
        // calling this function transfers the memory management of the values to the ECDSA_SIG object,
        // and therefore the values that have been passed in should not be freed directly after this function has been called
        //
        if (1 != ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s))
        {
            break;
        }

        siglen = i2d_ECDSA_SIG(ecdsa_sig, &sig);
        if(siglen <= 0)
        {
            break;
        }

        // verifies that the signature ecdsa_sig is a valid ECDSA signature using EVP_DigestVerify
        //
        evp_md_ctx = EVP_MD_CTX_new();
        if(NULL == evp_md_ctx) 
        {
            break;
        }
        if(1 != EVP_DigestVerifyInit(evp_md_ctx, NULL, NULL, NULL, evp_pkey))
        {
            break;
        }
        if(1 != EVP_DigestVerifyUpdate(evp_md_ctx, p_data, data_size))
        {
            break;
        }
        valid = EVP_DigestVerifyFinal(evp_md_ctx, sig, siglen);
	if (valid < 0)
        {
            break;
        }

        // sets the p_result based on ECDSA_do_verify result
        //
	if (valid == 1)
        {
            *p_result = SGX_EC_VALID;
        }

        retval = SGX_SUCCESS;
    } while(0);

    if (ecdsa_sig)
    {
        ECDSA_SIG_free(ecdsa_sig);
        bn_r = NULL;
        bn_s = NULL;
    }
    if (bn_r)
        BN_clear_free(bn_r);
    if (bn_s)
        BN_clear_free(bn_s);

    if (evp_pkey)
        EVP_PKEY_free(evp_pkey);
    if (evp_md_ctx)
        EVP_MD_CTX_free(evp_md_ctx);
    if (sig)
        OPENSSL_free(sig);
    return retval;
}

