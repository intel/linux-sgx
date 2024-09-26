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
#include "sgx_ecc256_internal.h"
#include "sgx_fips_internal.h"

/* Computes a point with scalar multiplication based on private B key (local) and remote public Ga Key
 * Parameters:
 *    Return: sgx_status_t - SGX_SUCCESS or failure as defined sgx_error.h
 *    Inputs: sgx_ecc_state_handle_t ecc_handle - Handle to ECC crypto system
 *            sgx_ec256_private_t *p_private_b - Pointer to the local private key - LITTLE ENDIAN
 *            sgx_ec256_public_t *p_public_ga - Pointer to the remote public key - LITTLE ENDIAN
 *    Output: sgx_ec256_shared_point_t *p_shared_key - Pointer to the target shared point - LITTLE ENDIAN
                                                    x-coordinate of (privKeyB - pubKeyA) */
sgx_status_t sgx_ecc256_compute_shared_point(sgx_ec256_private_t *p_private_b,
                                             sgx_ec256_public_t *p_public_ga,
                                             sgx_ec256_shared_point_t *p_shared_key,
                                             sgx_ecc_state_handle_t ecc_handle)
{
    if ((ecc_handle == NULL) || (p_private_b == NULL) || (p_public_ga == NULL) || (p_shared_key == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    fips_self_test_ecc();

    IppsBigNumState *bn_dh_privb = NULL;
    IppsBigNumState *bn_dh_shared_x = NULL;
    IppsBigNumState *bn_dh_shared_y = NULL;
    IppsBigNumState *puba_gx = NULL;
    IppsBigNumState *puba_gy = NULL;
    IppsGFpECPoint *point_pub_a = NULL;
    IppsGFpECPoint *point_r = NULL;
    IppStatus ipp_ret = ippStsErr;
    int ec_point_size = 0;
    IppECResult ipp_result = ippECValid;
    int scratch_size = 0;
    Ipp8u *scratch_buf = NULL;
    ipp_ec_state_handles_t *p_ec_handle = (ipp_ec_state_handles_t *)ecc_handle;
    do
    {
        ipp_ret = sgx_ipp_newBN((Ipp32u *)p_private_b->r, sizeof(sgx_ec256_private_t), &bn_dh_privb);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((uint32_t *)p_public_ga->gx, sizeof(p_public_ga->gx), &puba_gx);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN((uint32_t *)p_public_ga->gy, sizeof(p_public_ga->gy), &puba_gy);
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
        ipp_ret = ippsGFpECSetPointRegular(puba_gx, puba_gy, point_pub_a, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECTstPoint(point_pub_a, &ipp_result, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        if (ipp_result != ippECValid)
        {
            break;
        }

        point_r = (IppsGFpECPoint *)malloc(ec_point_size);
        if (!point_r)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECPointInit(NULL, NULL, point_r, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsGFpECScratchBufferSize(1, p_ec_handle->p_ec_state, &scratch_size);
        ERROR_BREAK(ipp_ret);
        scratch_buf = (Ipp8u *)malloc(scratch_size);
        if (!scratch_buf)
        {
            ipp_ret = ippStsNoMemErr;
            break;
        }
        ipp_ret = ippsGFpECMulPoint(point_pub_a, bn_dh_privb, point_r, p_ec_handle->p_ec_state, scratch_buf);
        ERROR_BREAK(ipp_ret);

        // defense in depth to verify that point_r in ECC group
        // a return value of ippECValid indicates the point is on the elliptic curve
        // and is not the point at infinity
        ipp_ret = ippsGFpECTstPoint(point_r, &ipp_result, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);
        if (ipp_result != ippECValid)
        {
            break;
        }

        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_dh_shared_t), &bn_dh_shared_x);
        ERROR_BREAK(ipp_ret);
        ipp_ret = sgx_ipp_newBN(NULL, sizeof(sgx_ec256_dh_shared_t), &bn_dh_shared_y);
        ERROR_BREAK(ipp_ret);
        ipp_ret = ippsGFpECGetPointRegular(point_r, bn_dh_shared_x, bn_dh_shared_y, p_ec_handle->p_ec_state);
        ERROR_BREAK(ipp_ret);

        IppsBigNumSGN sgn = IppsBigNumPOS;
        int length = 0;
        Ipp32u *pdata = NULL;
        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, bn_dh_shared_x);
        ERROR_BREAK(ipp_ret);
        memset(p_shared_key->x, 0, sizeof(p_shared_key->x));
        memcpy(p_shared_key->x, pdata, ROUND_TO(length, 8) / 8);
        // Clear memory securely
        memset_s(pdata, sizeof(p_shared_key->x), 0, ROUND_TO(length, 8) / 8);

        ipp_ret = ippsRef_BN(&sgn, &length, &pdata, bn_dh_shared_y);
        ERROR_BREAK(ipp_ret);
        memset(p_shared_key->y, 0, sizeof(p_shared_key->y));
        memcpy(p_shared_key->y, pdata, ROUND_TO(length, 8) / 8);
        // Clear memory securely
        memset_s(pdata, sizeof(p_shared_key->x), 0, ROUND_TO(length, 8) / 8);
    } while (0);
    CLEAR_FREE_MEM(point_pub_a, ec_point_size);
    CLEAR_FREE_MEM(point_r, ec_point_size);
    sgx_ipp_secure_free_BN(puba_gx, sizeof(p_public_ga->gx));
    sgx_ipp_secure_free_BN(puba_gy, sizeof(p_public_ga->gy));
    sgx_ipp_secure_free_BN(bn_dh_privb, sizeof(sgx_ec256_private_t));
    sgx_ipp_secure_free_BN(bn_dh_shared_x, sizeof(sgx_ec256_dh_shared_t));
    sgx_ipp_secure_free_BN(bn_dh_shared_y, sizeof(sgx_ec256_dh_shared_t));

    if (ipp_ret == ippStsNoMemErr || ipp_ret == ippStsMemAllocErr)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    else if (ipp_ret != ippStsNoErr)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
