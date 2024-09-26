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

#include "ipp_wrapper.h"
#include "sgx_fips_internal.h"

const uint32_t sgx_nistp256_r[] = {
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF,
    0x00000000, 0xFFFFFFFF};

/* Computes signature for data based on private key
 * Parameters:
 *   Return: sgx_status_t - SGX_SUCCESS or failure as defined sgx_error.h
 *   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
 *           sgx_ec256_private_t *p_private - Pointer to the private key - LITTLE ENDIAN
 *           sgx_uint8_t *p_data - Pointer to the data to be signed
 *           uint32_t data_size - Size of the data to be signed
 *   Output: sgx_ec256_signature_t *p_signature - Pointer to the signature - LITTLE ENDIAN  */
sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data,
                            uint32_t data_size,
                            const sgx_ec256_private_t *p_private,
                            sgx_ec256_signature_t *p_signature,
                            sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_private == NULL) || (p_signature == NULL) || (p_data == NULL) || (data_size < 1))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    fips_self_test_hash256();
    fips_self_test_ecc();

    IppStatus ipp_ret = ippStsErr;
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    IppsBigNumState *p_ecp_order = NULL;
    IppsBigNumState *p_hash_bn = NULL;
    IppsBigNumState *p_msg_bn = NULL;
    IppsBigNumState *p_eph_priv_bn = NULL;
    IppsGFpECPoint *p_eph_pub = NULL;
    IppsBigNumState *p_reg_priv_bn = NULL;
    IppsBigNumState *p_signx_bn = NULL;
    IppsBigNumState *p_signy_bn = NULL;
    Ipp32u *p_sigx = NULL;
    Ipp32u *p_sigy = NULL;
    int ecp_size = 0;
    IppECResult ec_result = ippECValid;
    const int order_size = sizeof(sgx_nistp256_r);
    uint8_t hash[SGX_SHA256_HASH_SIZE] = {0};
    int scratch_size = 0;
    Ipp8u *scratch_buf = NULL;

    do
    {
        ipp_ret = sgx_ipp_newBN(sgx_nistp256_r, order_size, &p_ecp_order);
        ERROR_BREAK(ipp_ret);

        // Prepare the message used to sign.
        ipp_ret = ippsHashMessage_rmf(p_data, data_size, (Ipp8u *)hash, ippsHashMethod_SHA256_TT());
        ERROR_BREAK(ipp_ret);
        /* Byte swap in creation of Big Number from SHA256 hash output */
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(hash), &p_hash_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsSetOctString_BN((Ipp8u *)hash, sizeof(hash), p_hash_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN(NULL, order_size, &p_msg_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsMod_BN(p_hash_bn, p_ecp_order, p_msg_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN(NULL, order_size, &p_eph_priv_bn);
        ERROR_BREAK(ipp_ret);

        // Set the regular private key.
        ipp_ret = sgx_ipp_newBN((uint32_t *)p_private->r, sizeof(p_private->r), &p_reg_priv_bn);
        ERROR_BREAK(ipp_ret);
        // init eccp point
        ipp_ret = ippsGFpECPointGetSize(p_ec_handle->p_ec_state, &ecp_size);
        ERROR_BREAK(ipp_ret);
        p_eph_pub = (IppsGFpECPoint *)malloc(ecp_size);
        if (!p_eph_pub)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, p_eph_pub, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECScratchBufferSize(1, p_ec_handle->p_ec_state, &scratch_size);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratch_size);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        uint32_t bn_result = 0;
        do
        {
            // Generate ephemeral key pair for signing operation
            ipp_ret = ippsGFpECPrivateKey(p_eph_priv_bn, p_ec_handle->p_ec_state, (IppBitSupplier)sgx_ipp_DRNGen, NULL);
            ERROR_BREAK(ipp_ret);

            ipp_ret = ippsGFpECPublicKey(p_eph_priv_bn, p_eph_pub, p_ec_handle->p_ec_state, scratch_buf);
            ERROR_BREAK(ipp_ret);
            ipp_ret = ippsGFpECTstKeyPair(p_eph_priv_bn, p_eph_pub, &ec_result, p_ec_handle->p_ec_state, scratch_buf);
            ERROR_BREAK(ipp_ret);
            if (ec_result != ippECValid)
            {
                ipp_ret = ippStsErr;
                break;
            }
            // Ensure the generated ephemeral private key is different from the regular private key
            ipp_ret = ippsCmp_BN(p_eph_priv_bn, p_reg_priv_bn, &bn_result);
            ERROR_BREAK(ipp_ret);
        } while (bn_result == 0);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN(NULL, order_size, &p_signx_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN(NULL, order_size, &p_signy_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECSignDSA(p_msg_bn, p_reg_priv_bn, p_eph_priv_bn, p_signx_bn,
                                   p_signy_bn, p_ec_handle->p_ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);
        IppsBigNumSGN sign;
        int length;
        ipp_ret = ippsRef_BN(&sign, &length, (Ipp32u **)&p_sigx, p_signx_bn);
        ERROR_BREAK(ipp_ret);
        memset(p_signature->x, 0, sizeof(p_signature->x));
        ipp_ret = check_copy_size(sizeof(p_signature->x), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_signature->x, p_sigx, ROUND_TO(length, 8) / 8);
        memset_s(p_sigx, sizeof(p_signature->x), 0, ROUND_TO(length, 8) / 8);
        ipp_ret = ippsRef_BN(&sign, &length, (Ipp32u **)&p_sigy, p_signy_bn);
        ERROR_BREAK(ipp_ret);
        memset(p_signature->y, 0, sizeof(p_signature->y));
        ipp_ret = check_copy_size(sizeof(p_signature->y), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_signature->y, p_sigy, ROUND_TO(length, 8) / 8);
        memset_s(p_sigy, sizeof(p_signature->y), 0, ROUND_TO(length, 8) / 8);
    } while (0);

    CLEAR_FREE_MEM(p_eph_pub, ecp_size);
    SAFE_FREE(scratch_buf);
    sgx_ipp_secure_free_BN(p_ecp_order, order_size);
    sgx_ipp_secure_free_BN(p_hash_bn, sizeof(hash));
    sgx_ipp_secure_free_BN(p_msg_bn, order_size);
    sgx_ipp_secure_free_BN(p_eph_priv_bn, order_size);
    sgx_ipp_secure_free_BN(p_reg_priv_bn, sizeof(p_private->r));
    sgx_ipp_secure_free_BN(p_signx_bn, order_size);
    sgx_ipp_secure_free_BN(p_signy_bn, order_size);

    switch (ipp_ret)
    {
    case ippStsNoErr:
        return SGX_SUCCESS;
    case ippStsNoMemErr:
    case ippStsMemAllocErr:
        return SGX_ERROR_OUT_OF_MEMORY;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
    case ippStsOutOfRangeErr:
    case ippStsSizeErr:
    case ippStsBadArgErr:
        return SGX_ERROR_INVALID_PARAMETER;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
}

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
    fips_self_test_hash256();

    uint8_t hash[SGX_SHA256_HASH_SIZE] = {0};

    // Prepare the message used to sign.
    if (ippStsNoErr != ippsHashMessage_rmf(p_data, data_size, (Ipp8u *)hash, ippsHashMethod_SHA256_TT()))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return (sgx_ecdsa_verify_hash(hash, p_public, p_signature, p_result, ecc_handle));
}

sgx_status_t sgx_ecdsa_verify_hash(const uint8_t *hash,
                                   const sgx_ec256_public_t *p_public,
                                   const sgx_ec256_signature_t *p_signature,
                                   uint8_t *p_result,
                                   sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_public == NULL) || (p_signature == NULL) ||
        (hash == NULL) || (p_result == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_ecc();

    IppStatus ipp_ret = ippStsErr;
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    IppECResult result = ippECInvalidSignature;
    *p_result = SGX_EC_INVALID_SIGNATURE;

    IppsBigNumState *p_ecp_order = NULL;
    IppsBigNumState *p_hash_bn = NULL;
    IppsBigNumState *p_msg_bn = NULL;
    IppsBigNumState *p_reg_pubx_bn = NULL;
    IppsBigNumState *p_reg_puby_bn = NULL;
    IppsBigNumState *p_signx_bn = NULL;
    IppsBigNumState *p_signy_bn = NULL;
    IppsGFpECPoint *p_reg_pub = NULL;
    int ecp_size = 0;
    const int order_size = sizeof(sgx_nistp256_r);
    int scratch_size = 0;
    Ipp8u *scratch_buf = NULL;

    do
    {
        ipp_ret = sgx_ipp_newBN(sgx_nistp256_r, order_size, &p_ecp_order);
        ERROR_BREAK(ipp_ret);

        /* Byte swap in creation of Big Number from SHA256 hash output */
        ipp_ret = sgx_ipp_newBN(NULL, SGX_SHA256_HASH_SIZE, &p_hash_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsSetOctString_BN((Ipp8u *)hash, SGX_SHA256_HASH_SIZE, p_hash_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN(NULL, order_size, &p_msg_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsMod_BN(p_hash_bn, p_ecp_order, p_msg_bn);
        ERROR_BREAK(ipp_ret);

        // Init eccp point
        ipp_ret = ippsGFpECPointGetSize(p_ec_handle->p_ec_state, &ecp_size);
        ERROR_BREAK(ipp_ret);
        p_reg_pub = (IppsGFpECPoint *)malloc(ecp_size);
        if (!p_reg_pub)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, p_reg_pub, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECScratchBufferSize(2, p_ec_handle->p_ec_state, &scratch_size);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratch_size);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = sgx_ipp_newBN((const uint32_t *)p_public->gx, sizeof(p_public->gx), &p_reg_pubx_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((const uint32_t *)p_public->gy, sizeof(p_public->gy), &p_reg_puby_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECSetPointRegular(p_reg_pubx_bn, p_reg_puby_bn, p_reg_pub, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN(p_signature->x, order_size, &p_signx_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN(p_signature->y, order_size, &p_signy_bn);
        ERROR_BREAK(ipp_ret);
        // Verify the message
        ipp_ret = ippsGFpECVerifyDSA(p_msg_bn, p_reg_pub, p_signx_bn, p_signy_bn, &result, p_ec_handle->p_ec_state, scratch_buf);
    } while (0);

    // Clear buffer before free
    CLEAR_FREE_MEM(p_reg_pub, ecp_size);
    SAFE_FREE(scratch_buf);
    sgx_ipp_secure_free_BN(p_ecp_order, order_size);
    sgx_ipp_secure_free_BN(p_hash_bn, sizeof(hash));
    sgx_ipp_secure_free_BN(p_msg_bn, order_size);
    sgx_ipp_secure_free_BN(p_reg_pubx_bn, sizeof(p_public->gx));
    sgx_ipp_secure_free_BN(p_reg_puby_bn, sizeof(p_public->gy));
    sgx_ipp_secure_free_BN(p_signx_bn, order_size);
    sgx_ipp_secure_free_BN(p_signy_bn, order_size);

    switch (result)
    {
    case ippECValid:
        *p_result = SGX_EC_VALID;
        break; /* validation pass successfully */
    case ippECInvalidSignature:
        *p_result = SGX_EC_INVALID_SIGNATURE;
        break; /* invalid signature */
    default:
        *p_result = SGX_EC_INVALID_SIGNATURE;
        break;
    }

    switch (ipp_ret)
    {
    case ippStsNoErr:
        return SGX_SUCCESS;
    case ippStsNoMemErr:
    case ippStsMemAllocErr:
        return SGX_ERROR_OUT_OF_MEMORY;
    case ippStsNullPtrErr:
    case ippStsLengthErr:
    case ippStsOutOfRangeErr:
    case ippStsSizeErr:
    case ippStsBadArgErr:
        return SGX_ERROR_INVALID_PARAMETER;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t sgx_calculate_ecdsa_priv_key(const unsigned char *hash_drg, int hash_drg_len,
                                          const unsigned char *sgx_nistp256_r_m1, int sgx_nistp256_r_m1_len,
                                          unsigned char *out_key, int out_key_len)
{

    if (out_key == NULL || hash_drg_len <= 0 || sgx_nistp256_r_m1_len <= 0 ||
        out_key_len <= 0 || hash_drg == NULL || sgx_nistp256_r_m1 == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
    IppStatus ipp_status = ippStsNoErr;
    IppsBigNumState *bn_d = NULL;
    IppsBigNumState *bn_m = NULL;
    IppsBigNumState *bn_o = NULL;
    IppsBigNumState *bn_one = NULL;
    Ipp32u i = 1;

    do
    {

        // allocate and initialize BNs
        //
        ipp_status = sgx_ipp_newBN(reinterpret_cast<const Ipp32u *>(hash_drg), hash_drg_len, &bn_d);
        ERROR_BREAK(ipp_status);

        // generate mod to be n-1 where n is order of ECC Group
        //
        ipp_status = sgx_ipp_newBN(reinterpret_cast<const Ipp32u *>(sgx_nistp256_r_m1), sgx_nistp256_r_m1_len, &bn_m);
        ERROR_BREAK(ipp_status);

        // allocate memory for output BN
        //
        ipp_status = sgx_ipp_newBN(NULL, sgx_nistp256_r_m1_len, &bn_o);
        ERROR_BREAK(ipp_status);

        // create big number with value of 1
        //
        ipp_status = sgx_ipp_newBN(&i, sizeof(Ipp32u), &bn_one);
        ERROR_BREAK(ipp_status);

        // calculate output's BN value
        ipp_status = ippsMod_BN(bn_d, bn_m, bn_o);
        ERROR_BREAK(ipp_status)

        // increase by 1
        //
        ipp_status = ippsAdd_BN(bn_o, bn_one, bn_o);
        ERROR_BREAK(ipp_status);

        /*Unmatched size*/
        if (sgx_nistp256_r_m1_len != sizeof(sgx_ec256_private_t))
        {
            break;
        }

        // convert BN_o into octet string
        ipp_status = ippsGetOctString_BN(reinterpret_cast<Ipp8u *>(out_key), sgx_nistp256_r_m1_len, bn_o); // output data in bigendian order
        ERROR_BREAK(ipp_status);

        ret_code = SGX_SUCCESS;
    } while (0);

    sgx_ipp_secure_free_BN(bn_d, hash_drg_len);
    sgx_ipp_secure_free_BN(bn_m, sgx_nistp256_r_m1_len);
    sgx_ipp_secure_free_BN(bn_o, sgx_nistp256_r_m1_len);
    sgx_ipp_secure_free_BN(bn_one, sizeof(uint32_t));

    if (ipp_status == ippStsMemAllocErr)
        ret_code = SGX_ERROR_OUT_OF_MEMORY;

    if (ret_code != SGX_SUCCESS)
    {
        (void)memset_s(out_key, out_key_len, 0, out_key_len);
    }

    return ret_code;
}
