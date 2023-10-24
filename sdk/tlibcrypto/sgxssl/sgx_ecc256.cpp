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

#include "string.h"
#include "se_tcrypto_common.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include "sgx_tcrypto.h"
#include "ssl_wrapper.h"
#define POINT_NOT_ON_CURVE 0x1012606b

EVP_PKEY *get_priv_key_from_bin(const sgx_ec256_private_t *p_private, sgx_ecc_state_handle_t ecc_handle)
{
	EVP_PKEY *evp_key = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	BIGNUM *bn_priv = NULL;
	OSSL_PARAM_BLD *params_build = NULL;
	OSSL_PARAM *params = NULL;
	const char *curvename = NULL;
	int nid = 0;

	do {
		bn_priv = BN_lebin2bn((unsigned char*)p_private->r, sizeof(sgx_ec256_private_t), 0);
		if (bn_priv == NULL) {
			break;
		}
		// build OSSL_PARAM
		nid = EC_GROUP_get_curve_name((EC_GROUP *)ecc_handle);
		if (nid == NID_undef) {
			break;
		}
		curvename = OBJ_nid2sn(nid);
		if (curvename == NULL) {
			break;
		}
		params_build = OSSL_PARAM_BLD_new();
		if ( !params_build) {
			break;
		}
		if ( 1 != OSSL_PARAM_BLD_push_utf8_string(params_build, "group", curvename, 0)) {
			break;
		}
	        if ( 1 != OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) {
        	        break;
		}
		params = OSSL_PARAM_BLD_to_param(params_build);
		if ( NULL == params ) {
			break;
		}

		// get pkey from param
		pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (NULL == pkey_ctx) {
			break;
		}
		if ( 1 != EVP_PKEY_fromdata_init(pkey_ctx) ) {
			break;
		}
		if ( 1 != EVP_PKEY_fromdata(pkey_ctx, &evp_key, EVP_PKEY_KEYPAIR, params) ) {
			EVP_PKEY_free(evp_key);
			evp_key = NULL;
		}
	} while(0);

	BN_clear_free(bn_priv);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(params_build);
	EVP_PKEY_CTX_free(pkey_ctx);

	return evp_key;
}

EVP_PKEY *get_pub_key_from_coords(const sgx_ec256_public_t *p_public, sgx_ecc_state_handle_t ecc_handle)
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

/*
* Elliptic Curve Cryptography - Based on GF(p), 256 bit
*/
/* Allocates and initializes ecc context
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Output: sgx_ecc_state_handle_t *p_ecc_handle - Pointer to the handle of ECC crypto system  */
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle)
{
	if (p_ecc_handle == NULL) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t retval = SGX_SUCCESS;

	/* construct a curve p-256 */
	EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (NULL == ec_group) {
		retval = SGX_ERROR_UNEXPECTED;
	} else {
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
	if (ecc_handle == NULL) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	EC_GROUP_free((EC_GROUP*)ecc_handle);

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
	if ((ecc_handle == NULL) || (p_private == NULL) || (p_public == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	BIGNUM *pub_k_x = NULL;
	BIGNUM *pub_k_y = NULL;
	BIGNUM *private_k = NULL;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	OSSL_PARAM params[2];
	const char *curvename = NULL;
	int nid = 0;

	do {
		// build OSSL_PARAM
		nid = EC_GROUP_get_curve_name((EC_GROUP *)ecc_handle);
		if (nid == NID_undef) {
			break;
		}
		curvename = OBJ_nid2sn(nid);
		if (curvename == NULL) {
			break;
		}

                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)curvename, 0);
                params[1] = OSSL_PARAM_construct_end();

		// generate key
		pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (NULL == pkey_ctx) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
                if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
			break;
		}
                if (!EVP_PKEY_CTX_set_params(pkey_ctx, params)) {
			break;
		}
                if (EVP_PKEY_generate(pkey_ctx, &pkey) <= 0) {
			break;
		}

		// get public and private keys
		if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &private_k)) {
			break;
		}
                if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pub_k_x)) {
			break;
		}
	        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &pub_k_y)) {
			break;
		}

		if (-1 == BN_bn2lebinpad(private_k, (unsigned char*)p_private, SGX_ECP256_KEY_SIZE)) {
			break;
		}
		if (-1 == BN_bn2lebinpad(pub_k_x, (unsigned char*)p_public->gx, SGX_ECP256_KEY_SIZE)) {
			break;
		}
		if (-1 == BN_bn2lebinpad(pub_k_y, (unsigned char*)p_public->gy, SGX_ECP256_KEY_SIZE)) {
			break;
		}

		ret = SGX_SUCCESS;
	} while(0);

	if (SGX_SUCCESS != ret) {
		// in case of error, clear output buffers
		memset_s(p_private, sizeof(p_private), 0, sizeof(p_private));
		memset_s(p_public->gx, sizeof(p_public->gx), 0, sizeof(p_public->gx));
		memset_s(p_public->gy, sizeof(p_public->gy), 0, sizeof(p_public->gy));
	}

	//free temp data
	BN_clear_free(pub_k_x);
	BN_clear_free(pub_k_y);
	BN_clear_free(private_k);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pkey_ctx);

	return ret;
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
	if ((ecc_handle == NULL) || (p_point == NULL) || (p_valid == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	EC_POINT *ec_point = NULL;
	BIGNUM *b_x = NULL;
	BIGNUM *b_y = NULL;
	int ret_point_on_curve = 0;
	unsigned long internal_openssl_error = 0;

	do {
		// converts the x value of the point, represented as positive integer in little-endian into a BIGNUM
		//
		b_x = BN_lebin2bn(p_point->gx, SGX_ECP256_KEY_SIZE, NULL);
		if (NULL == b_x) {
			break;
		}

		// converts the y value of the point, represented as positive integer in little-endian into a BIGNUM
		//
		b_y = BN_lebin2bn(p_point->gy, SGX_ECP256_KEY_SIZE, NULL);
		if (NULL == b_y) {
			break;
		}

		// creates new point and assigned the group object that the point relates to
		//
		ec_point = EC_POINT_new((const EC_GROUP*)ecc_handle);
		if (NULL == ec_point) {
			retval = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// sets point based on x,y coordinates
		//
		if (1 != EC_POINT_set_affine_coordinates((const EC_GROUP*)ecc_handle, ec_point, b_x, b_y, NULL)) {
			internal_openssl_error = ERR_get_error();
			if (internal_openssl_error == POINT_NOT_ON_CURVE) {
				/* fails if point not on curve */
				*p_valid = 0;
				retval = SGX_SUCCESS;
			}
			break;
		}

		// checks if point is on curve
		//
		ret_point_on_curve = EC_POINT_is_on_curve((const EC_GROUP*)ecc_handle, ec_point, NULL);
		if (-1 == ret_point_on_curve) {
			break;
		}

		*p_valid = ret_point_on_curve;

		retval = SGX_SUCCESS;
	} while(0);

	if (ec_point)
		EC_POINT_clear_free(ec_point);
	if (b_x)
		BN_clear_free(b_x);
	if (b_y)
		BN_clear_free(b_y);

	return retval;
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
	if ((ecc_handle == NULL) || (p_private_b == NULL) || (p_public_ga == NULL) || (p_shared_key == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	BIGNUM *tmp = NULL;
	EVP_PKEY *pkey_peer = NULL;
	EVP_PKEY *pkey_local = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	size_t shared_key_len = 0;

	do {
		// get BN from public key and private key
		//
		pkey_peer = get_pub_key_from_coords(p_public_ga, ecc_handle);
		if( !pkey_peer) {
			break;
		}
		pkey_local = get_priv_key_from_bin(p_private_b, ecc_handle);
		if( !pkey_local) {
			break;
		}

		// calculate shared dh key
		//
		pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey_local, NULL);
		if (!pctx) {
            		ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		if (EVP_PKEY_derive_init(pctx) <= 0) {
			break;
		}
		if (EVP_PKEY_derive_set_peer(pctx, pkey_peer) <= 0) {
			break;
		}

		if (EVP_PKEY_derive(pctx, NULL, &shared_key_len) <= 0 
		  || shared_key_len != sizeof(sgx_ec256_dh_shared_t) ) {
			break;
		}

		if (EVP_PKEY_derive(pctx, (unsigned char *)(p_shared_key->s), &shared_key_len) <= 0) {
			break;
		}

		// convert big endian to little endian
		//
		tmp = BN_bin2bn((unsigned char*)&(p_shared_key->s), sizeof(sgx_ec256_dh_shared_t), 0);
		if (tmp == NULL) {
			break;
		}
		if (BN_bn2lebinpad(tmp, p_shared_key->s, sizeof(sgx_ec256_dh_shared_t)) == -1) {
			break;
		}
		ret = SGX_SUCCESS;
	} while(0);

	if (ret != SGX_SUCCESS) {
		memset_s(p_shared_key->s, sizeof(p_shared_key->s), 0, sizeof(p_shared_key->s));
	}

	// clear and free memory
	//
	EVP_PKEY_free(pkey_peer);
	EVP_PKEY_free(pkey_local);
	EVP_PKEY_CTX_free(pctx);
	BN_clear_free(tmp);

	return ret;
}

/** Create an ECC public key based on a given ECC private key.
*
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS or failure as defined in sgx_error.h
*   Input: p_att_priv_key - Input private key
*   Output: p_att_pub_key - Output public key - LITTLE ENDIAN
*
*/
sgx_status_t sgx_ecc256_calculate_pub_from_priv(const sgx_ec256_private_t *p_att_priv_key, sgx_ec256_public_t  *p_att_pub_key)
{
	if ((p_att_priv_key == NULL) || (p_att_pub_key == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	EC_GROUP* ec_group = NULL;
	EC_POINT *pub_ec_point = NULL;
	BIGNUM *bn_o = NULL;
	BIGNUM *bn_x = NULL;
	BIGNUM *bn_y = NULL;
	BN_CTX *tmp = NULL;

	do {
		//create empty BNs
		//
		bn_x = BN_new();
		if (NULL == bn_x) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
		bn_y = BN_new();
		if (NULL == bn_y) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
		tmp = BN_CTX_new();
		if (NULL == tmp) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		//init bn_o with private key value
		//
		bn_o = BN_lebin2bn((const unsigned char*)p_att_priv_key, (int)sizeof(sgx_ec256_private_t), bn_o);
		BN_CHECK_BREAK(bn_o);

		//create a new ecc group and initialize it to NID_X9_62_prime256v1 curve
		//
		ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		if (ec_group == NULL) {
			break;
		}

		//create a new EC point
		//
		pub_ec_point = EC_POINT_new(ec_group);
		if (pub_ec_point == NULL) {
			break;
		}

		//calculate public key (point) based on private key. (pub = priv * curve_griup)
		//
		if (!EC_POINT_mul(ec_group, pub_ec_point, bn_o, NULL, NULL, tmp)) {
			break;
		}

		//retrieve x and y coordinates into BNs
		//
		if (!EC_POINT_get_affine_coordinates(ec_group, pub_ec_point, bn_x, bn_y, tmp)) {
			break;
		}

		//convert the absolute value of BNs into little-endian buffers
		//
		if (!BN_bn2lebinpad(bn_x, p_att_pub_key->gx, BN_num_bytes(bn_x))) {
			break;
		}

		if (!BN_bn2lebinpad(bn_y, p_att_pub_key->gy, BN_num_bytes(bn_y))) {
			break;
		}

		ret = SGX_SUCCESS;
	} while (0);

	//in case of failure clear public key
	//
	if (ret != SGX_SUCCESS) {
		(void)memset_s(p_att_pub_key, sizeof(sgx_ec256_public_t), 0, sizeof(sgx_ec256_public_t));
	}

	BN_clear_free(bn_o);
	BN_clear_free(bn_x);
	BN_clear_free(bn_y);
	BN_CTX_free(tmp);
	EC_GROUP_free(ec_group);
	EC_POINT_clear_free(pub_ec_point);

	return ret;
}
