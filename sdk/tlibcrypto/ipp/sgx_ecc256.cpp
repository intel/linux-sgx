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

#define ECC_FIELD_SIZE 256

void fips_self_test_ecc()
{
    static bool fips_selftest_ecc_flag = false;
    if (g_global_data.fips_on != 0 && fips_selftest_ecc_flag == false)
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
            FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECPrivateKey, p_gfp_buf, p_ec_buf, p_data_buf);
            FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECPublicKey, p_gfp_buf, p_ec_buf, p_data_buf);
            FIPS_SELFTEST_FUNC_3(test_result, fips_selftest_ippsGFpECSharedSecretDH, p_gfp_buf, p_ec_buf, p_data_buf);
            ret = SGX_SUCCESS;
            fips_selftest_ecc_flag = true;
        } while (0);
        SAFE_FREE(p_gfp_buf);
        SAFE_FREE(p_ec_buf);
        SAFE_FREE(p_data_buf);
        ERROR_ABORT(ret);
    }
    return;
}

/*
 * Elliptic Curve Crytpography - Based on GF(p), 256 bits
 */
/* Allocates and initializes ecc context
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
 *   Output: sgx_ecc_state_handle_t *p_ecc_handle - Pointer to the handle of ECC crypto system  */
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t *p_ecc_handle)
{
    if (p_ecc_handle == NULL)
        return SGX_ERROR_INVALID_PARAMETER;

    fips_self_test_ecc();

    IppStatus ipp_ret = ippStsErr;
    ipp_ec_state_handles_t *ipp_state_handle = NULL;
    IppsGFpState *gfp_ctx = NULL;
    IppsGFpECState *ec_state = NULL;
    int gfp_ctx_size = 0;
    int ec_size = 0;
    do
    {
        ipp_ret = ippsGFpGetSize(ECC_FIELD_SIZE, &gfp_ctx_size);
        ERROR_BREAK(ipp_ret);
        gfp_ctx = (IppsGFpState *)malloc(gfp_ctx_size);
        if (!gfp_ctx)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpInit(NULL, ECC_FIELD_SIZE, ippsGFpMethod_p256r1(), gfp_ctx);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsGFpECGetSize(gfp_ctx, &ec_size);
        ERROR_BREAK(ipp_ret);
        ec_state = (IppsGFpECState *)malloc(ec_size);
        if (!ec_state)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECInitStd256r1(gfp_ctx, ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_state_handle = (ipp_ec_state_handles_t *)malloc(sizeof(ipp_ec_state_handles_t));
        if (!ipp_state_handle)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_state_handle->p_gfp_state = gfp_ctx;
        ipp_state_handle->p_ec_state = ec_state;
    } while (0);

    if (ipp_ret != ippStsNoErr)
    {
        CLEAR_FREE_MEM(gfp_ctx, gfp_ctx_size);
        CLEAR_FREE_MEM(ec_state, ec_size);
        SAFE_FREE(ipp_state_handle);
    }
    else
    {
        *p_ecc_handle = ipp_state_handle;
    }
    switch (ipp_ret)
    {
    case ippStsNoErr:
        return SGX_SUCCESS;
    case ippStsNoMemErr:
    case ippStsMemAllocErr:
        return SGX_ERROR_OUT_OF_MEMORY;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
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
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    if (p_ec_handle->p_ec_state)
    {
        int ec_size = 0;
        if (ippsGFpECGetSize(p_ec_handle->p_gfp_state, &ec_size) != ippStsNoErr)
        {
            free(p_ec_handle->p_ec_state);
        }
        else
        {
            CLEAR_FREE_MEM(p_ec_handle->p_ec_state, ec_size);
        }
    }
    if (p_ec_handle->p_gfp_state)
    {
        int gfp_ctx_size = 0;
        if (ippsGFpGetSize(ECC_FIELD_SIZE, &gfp_ctx_size) != ippStsNoErr)
        {
            free(p_ec_handle->p_gfp_state);
        }
        else
        {
            CLEAR_FREE_MEM(p_ec_handle->p_gfp_state, gfp_ctx_size);
        }
    }
    free(p_ec_handle);
    return SGX_SUCCESS;
}

/* Populates private/public key pair - caller code allocates memory
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
 *   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
 *   Outputs: sgx_ec256_private_t *p_private - Pointer to the private key
 *            sgx_ec256_public_t *p_public - Pointer to the public key  */
sgx_status_t sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private,
                                        sgx_ec256_public_t *p_public,
                                        sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_private == NULL) || (p_public == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_ecc();

    IppsBigNumState *dh_priv_bn = NULL;
    IppStatus ipp_ret = ippStsErr;
    IppsBigNumState *pub_gx = NULL;
    IppsBigNumState *pub_gy = NULL;
    IppsGFpECPoint *pub_point = NULL;
    int ec_point_size = 0;
    int scratch_size = 0;
    Ipp8u *scratch_buf = NULL;
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    IppECResult ec_result = ippECValid;
    do
    {
        ipp_ret = sgx_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &dh_priv_bn);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECPrivateKey(dh_priv_bn, p_ec_handle->p_ec_state, (IppBitSupplier)sgx_ipp_DRNGen, NULL);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsGFpECPointGetSize(p_ec_handle->p_ec_state, &ec_point_size);
        ERROR_BREAK(ipp_ret);
        pub_point = (IppsGFpECPoint *)malloc(ec_point_size);
        if (!pub_point)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, pub_point, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECScratchBufferSize(1, p_ec_handle->p_ec_state, &scratch_size);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratch_size);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPublicKey(dh_priv_bn, pub_point, p_ec_handle->p_ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECTstKeyPair(dh_priv_bn, pub_point, &ec_result, p_ec_handle->p_ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);
        if (ec_result != ippECValid)
        {
            ipp_ret = ippStsErr;
            break;
        }
        // convert point_result to oct string
        ipp_ret = sgx_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &pub_gx);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN(NULL, SGX_ECP256_KEY_SIZE, &pub_gy);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECGetPointRegular(pub_point, pub_gx, pub_gy, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);

        IppsBigNumSGN sgn = IppsBigNumPOS;
        Ipp32u *pdata = NULL;
        // ippsRef_BN is in bits not bytes (versus old ippsGet_BN)
        int length = 0;
        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, pub_gx);
        ERROR_BREAK(ipp_ret);
        memset(p_public->gx, 0, sizeof(p_public->gx));
        ipp_ret = check_copy_size(sizeof(p_public->gx), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_public->gx, pdata, ROUND_TO(length, 8) / 8);
        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, pub_gy);
        ERROR_BREAK(ipp_ret);
        memset(p_public->gy, 0, sizeof(p_public->gy));
        ipp_ret = check_copy_size(sizeof(p_public->gy), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_public->gy, pdata, ROUND_TO(length, 8) / 8);
        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, dh_priv_bn);
        ERROR_BREAK(ipp_ret);
        memset(p_private->r, 0, sizeof(p_private->r));
        ipp_ret = check_copy_size(sizeof(p_private->r), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_private->r, pdata, ROUND_TO(length, 8) / 8);
    } while (0);
    // Clear temp buffer before free.
    CLEAR_FREE_MEM(pub_point, ec_point_size);
    SAFE_FREE(scratch_buf);
    sgx_ipp_secure_free_BN(pub_gx, SGX_ECP256_KEY_SIZE);
    sgx_ipp_secure_free_BN(pub_gy, SGX_ECP256_KEY_SIZE);
    sgx_ipp_secure_free_BN(dh_priv_bn, SGX_ECP256_KEY_SIZE);

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

/* Checks whether the input point is a valid point on the given elliptic curve
 * Parameters:
 *   Return: sgx_status_t - SGX_SUCCESS or failure as defined sgx_error.h
 *   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
 *           sgx_ec256_public_t *p_point - Pointer to perform validity check on - LITTLE ENDIAN
 *   Output: int *p_valid - Return 0 if the point is an invalid point on ECC curve */
sgx_status_t sgx_ecc256_check_point(const sgx_ec256_public_t *p_point,
                                    const sgx_ecc_state_handle_t ecc_handle,
                                    int *p_valid)
{
    if ((ecc_handle == NULL) || (p_point == NULL) || (p_valid == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_ecc();

    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    IppsGFpECPoint *point2check = NULL;
    IppStatus ipp_ret = ippStsErr;
    IppECResult ipp_result = ippECValid;
    int ec_point_size = 0;
    IppsBigNumState *bn_gx = NULL;
    IppsBigNumState *bn_gy = NULL;

    // Intialize return to false
    *p_valid = 0;
    do
    {
        ipp_ret = ippsGFpECPointGetSize(p_ec_handle->p_ec_state, &ec_point_size);
        ERROR_BREAK(ipp_ret);
        point2check = (IppsGFpECPoint *)malloc(ec_point_size);
        if (!point2check)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, point2check, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_point->gx, sizeof(p_point->gx), &bn_gx);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_point->gy, sizeof(p_point->gy), &bn_gy);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECSetPointRegular(bn_gx, bn_gy, point2check, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECTstPoint(point2check, &ipp_result, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        if (ipp_result == ippECValid)
        {
            *p_valid = 1;
        }
    } while (0);

    CLEAR_FREE_MEM(point2check, ec_point_size);
    sgx_ipp_secure_free_BN(bn_gx, sizeof(p_point->gx));
    sgx_ipp_secure_free_BN(bn_gy, sizeof(p_point->gy));

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

/* Computes DH shared key based on private B key (local) and remote public Ga Key
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
*           sgx_ec256_private_t *p_private_b - Pointer to the local private key - LITTLE ENDIAN
*           sgx_ec256_public_t *p_public_ga - Pointer to the remote public key - LITTLE ENDIAN
*   Output: sgx_ec256_dh_shared_t *p_shared_key - Pointer to the shared DH key - LITTLE ENDIAN
x-coordinate of (privKeyB - pubKeyA) */
sgx_status_t sgx_ecc256_compute_shared_dhkey(const sgx_ec256_private_t *p_private_b,
                                             const sgx_ec256_public_t *p_public_ga,
                                             sgx_ec256_dh_shared_t *p_shared_key,
                                             sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_private_b == NULL) || (p_public_ga == NULL) || (p_shared_key == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_ecc();

    IppsBigNumState *bn_dh_priv_b = NULL;
    IppsBigNumState *bn_dh_share = NULL;
    IppsBigNumState *pub_a_gx = NULL;
    IppsBigNumState *pub_a_gy = NULL;
    IppsGFpECPoint *point_pub_a = NULL;
    IppStatus ipp_ret = ippStsErr;
    int ec_point_size = 0;
    IppECResult ipp_result = ippECValid;
    int scratchSize = 0;
    Ipp8u *scratch_buf = NULL;
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    do
    {
        ipp_ret = sgx_ipp_newBN((Ipp32u *)p_private_b->r, sizeof(sgx_ec256_private_t), &bn_dh_priv_b);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((uint32_t *)p_public_ga->gx, sizeof(p_public_ga->gx), &pub_a_gx);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((uint32_t *)p_public_ga->gy, sizeof(p_public_ga->gy), &pub_a_gy);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsGFpECPointGetSize(p_ec_handle->p_ec_state, &ec_point_size);
        ERROR_BREAK(ipp_ret);
        point_pub_a = (IppsGFpECPoint *)malloc(ec_point_size);
        if (!point_pub_a)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, point_pub_a, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECSetPointRegular(pub_a_gx, pub_a_gy, point_pub_a, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECTstPoint(point_pub_a, &ipp_result, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        if (ipp_result != ippECValid)
        {
            ipp_ret = ippStsErr;
            break;
        }
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_dh_shared_t), &bn_dh_share);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECScratchBufferSize(1, p_ec_handle->p_ec_state, &scratchSize);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratchSize);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }

        ipp_ret = ippsGFpECSharedSecretDH(bn_dh_priv_b, point_pub_a, bn_dh_share, p_ec_handle->p_ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);
        IppsBigNumSGN sgn = IppsBigNumPOS;
        int length = 0;
        Ipp32u *pdata = NULL;
        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, bn_dh_share);
        ERROR_BREAK(ipp_ret);
        memset(p_shared_key->s, 0, sizeof(p_shared_key->s));
        ipp_ret = check_copy_size(sizeof(p_shared_key->s), ROUND_TO(length, 8) / 8);
        ERROR_BREAK(ipp_ret);
        memcpy(p_shared_key->s, pdata, ROUND_TO(length, 8) / 8);
    } while (0);

    CLEAR_FREE_MEM(point_pub_a, ec_point_size);
    SAFE_FREE(scratch_buf);
    sgx_ipp_secure_free_BN(pub_a_gx, sizeof(p_public_ga->gx));
    sgx_ipp_secure_free_BN(pub_a_gy, sizeof(p_public_ga->gy));
    sgx_ipp_secure_free_BN(bn_dh_priv_b, sizeof(sgx_ec256_private_t));
    sgx_ipp_secure_free_BN(bn_dh_share, sizeof(sgx_ec256_dh_shared_t));

    if (ipp_result != ippECValid)
    {
        return SGX_ERROR_INVALID_PARAMETER;
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

/** Create an ECC public key based on a given ECC private key.
 *
 * Parameters:
 *   Return: sgx_status_t - SGX_SUCCESS or failure as defined in sgx_error.h
 *   Input: p_att_priv_key - Input private key
 *   Output: p_att_pub_key - Output public key - LITTLE ENDIAN
 *
 */
sgx_status_t sgx_ecc256_calculate_pub_from_priv(const sgx_ec256_private_t *p_att_priv_key, sgx_ec256_public_t *p_att_pub_key)
{
    if ((p_att_priv_key == NULL) || (p_att_pub_key == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    fips_self_test_ecc();

    IppStatus ipp_ret = ippStsErr;
    IppsGFpState *gfp_ctx = NULL;
    IppsGFpECState *ec_state = NULL;
    int gfp_ctx_size = 0;
    int ec_size = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int point_size = 0;
    IppsGFpECPoint *public_key = NULL;
    IppsBigNumState *bn_o = NULL;
    IppsBigNumState *bn_x = NULL;
    IppsBigNumState *bn_y = NULL;
    int scratch_size = 0;
    Ipp8u *scratch_buf = NULL;
    sgx_ec256_private_t att_priv_key_be;
    uint8_t *p_temp;
    int size = 0;
    IppsBigNumSGN sgn;
    do
    {
        ipp_ret = ippsGFpGetSize(ECC_FIELD_SIZE, &gfp_ctx_size);
        ERROR_BREAK(ipp_ret);
        gfp_ctx = (IppsGFpState *)malloc(gfp_ctx_size);
        if (!gfp_ctx)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpInit(NULL, ECC_FIELD_SIZE, ippsGFpMethod_p256r1(), gfp_ctx);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECGetSize(gfp_ctx, &ec_size);
        ERROR_BREAK(ipp_ret);
        ec_state = (IppsGFpECState *)malloc(ec_size);
        if (!ec_state)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECInitStd256r1(gfp_ctx, ec_state);
        ERROR_BREAK(ipp_ret);
        // create buffer for point (public key) and init point
        ipp_ret = ippsGFpECPointGetSize(ec_state, &point_size);
        ERROR_BREAK(ipp_ret);
        public_key = (IppsGFpECPoint *)malloc(point_size);
        if (!public_key)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, public_key, ec_state);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsGFpECScratchBufferSize(1, ec_state, &scratch_size);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratch_size);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }

        // allocate bn_o, will be used for private key
        //
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_private_t), &bn_o);
        ERROR_BREAK(ipp_ret);
        // convert private key into big endian
        //
        p_temp = (uint8_t *)p_att_priv_key;
        for (uint32_t i = 0; i < sizeof(att_priv_key_be); i++)
        {
            att_priv_key_be.r[i] = *(p_temp + sizeof(att_priv_key_be) - 1 - i);
        }

        // assign private key into bn_o
        //
        ipp_ret = ippsSetOctString_BN(reinterpret_cast<Ipp8u *>(&att_priv_key_be), sizeof(sgx_ec256_private_t), bn_o);
        ERROR_BREAK(ipp_ret);
        // compute public key from the given private key (bn_o) of the elliptic cryptosystem (p_ecc_state) over GF(p).
        //
        ipp_ret = ippsGFpECPublicKey(bn_o, public_key, ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);

        // allocate BNs
        //
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_private_t), &bn_x);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_private_t), &bn_y);
        ERROR_BREAK(ipp_ret);
        // assign public key into BNs
        //
        ipp_ret = ippsGFpECGetPointRegular(public_key, bn_x, bn_y, ec_state);
        ERROR_BREAK(ipp_ret);
        // output key in little endian order
        //
        // gx value
        ipp_ret = ippsGetSize_BN(bn_x, &size);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGet_BN(&sgn, &size, reinterpret_cast<Ipp32u *>(p_att_pub_key->gx), bn_x);
        ERROR_BREAK(ipp_ret);
        // gy value
        //
        ipp_ret = ippsGetSize_BN(bn_y, &size);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGet_BN(&sgn, &size, reinterpret_cast<Ipp32u *>(p_att_pub_key->gy), bn_y);
        ERROR_BREAK(ipp_ret);
        ret = SGX_SUCCESS;

    } while (0);
    // clear public key in case of failure
    //
    if (ret != SGX_SUCCESS)
    {
        (void)memset_s(p_att_pub_key, sizeof(sgx_ec256_public_t), 0, sizeof(sgx_ec256_public_t));
    }
    SAFE_FREE(scratch_buf);
    CLEAR_FREE_MEM(gfp_ctx, gfp_ctx_size);
    CLEAR_FREE_MEM(ec_state, ec_size);
    CLEAR_FREE_MEM(public_key, point_size);
    sgx_ipp_secure_free_BN(bn_o, sizeof(sgx_ec256_private_t));
    sgx_ipp_secure_free_BN(bn_x, sizeof(sgx_ec256_private_t));
    sgx_ipp_secure_free_BN(bn_y, sizeof(sgx_ec256_private_t));

    return ret;
}
