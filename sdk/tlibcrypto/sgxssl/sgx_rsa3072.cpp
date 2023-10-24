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
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "se_tcrypto_common.h"
#include "sgx_read_rand.h"

sgx_status_t sgx_rsa3072_sign(const uint8_t * p_data,
	uint32_t data_size,
	const sgx_rsa3072_key_t * p_key,
	sgx_rsa3072_signature_t * p_signature)
{
	if ((p_data == NULL) || (data_size < 1) || (p_key == NULL) ||
		(p_signature == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	EVP_PKEY* priv_pkey = NULL;
	EVP_MD_CTX* ctx = NULL;
	const EVP_MD* sha256_md = NULL;
	size_t siglen = SGX_RSA3072_KEY_SIZE;

	do {
		if (SGX_SUCCESS != sgx_create_rsa_priv1_key(sizeof(p_key->mod), sizeof(p_key->e), sizeof(p_key->d), p_key->mod, p_key->e, p_key->d, (void **)&priv_pkey)
		 || NULL == priv_pkey) {
			break;
		}

		// allocates, initializes and returns a digest context
		//
		ctx = EVP_MD_CTX_new();
		if (NULL == ctx) {
			retval = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// return EVP_MD structures for SHA256 digest algorithm */
		//
		sha256_md = EVP_sha256();
		if (sha256_md == NULL) {
			break;
		}

		// sets up signing context ctx to use digest type
		//
		if (EVP_DigestSignInit(ctx, NULL, sha256_md, NULL, priv_pkey) <= 0) {
			break;
		}

		// hashes data_size bytes of data at p_data into the signature context ctx
		//
		if (EVP_DigestSignUpdate(ctx, (const void *)p_data, data_size) <= 0) {
			break;
		}

		// signs the data in ctx places the signature in p_signature.
		//
		if (EVP_DigestSignFinal(ctx, (unsigned char *)p_signature, &siglen) <= 0) { //fails
			break;
		}

		// validates the signature size
		//
		if (SGX_RSA3072_KEY_SIZE != siglen) {
			break;
		}

		retval = SGX_SUCCESS;
	} while (0);

	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (priv_pkey) {
		EVP_PKEY_free(priv_pkey);
	}

	return retval;
}

sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
	uint32_t data_size,
	const sgx_rsa3072_public_key_t *p_public,
	const sgx_rsa3072_signature_t *p_signature,
	sgx_rsa_result_t *p_result)
{
	if ((p_data == NULL) || (data_size < 1) || (p_public == NULL) ||
		(p_signature == NULL) || (p_result == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}
	*p_result = SGX_RSA_INVALID_SIGNATURE;

	sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	int verified = 0;
	EVP_PKEY *pub_pkey = NULL;
	const EVP_MD* sha256_md = NULL;
	EVP_MD_CTX *ctx = NULL;

	do {
		if (SGX_SUCCESS != sgx_create_rsa_pub1_key(sizeof(p_public->mod), sizeof(p_public->exp), p_public->mod, p_public->exp, (void**)&pub_pkey)) {
			break;
		}

		// allocates, initializes and returns a digest context
		//
		ctx = EVP_MD_CTX_new();
		if (ctx == NULL) {
			retval = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		// return EVP_MD structures for SHA256 digest algorithm 
		//
		sha256_md = EVP_sha256();
		if (sha256_md == NULL) {
			break;
		}

		// sets up verification context ctx to use digest type
		//
		if (EVP_DigestVerifyInit(ctx, NULL, sha256_md, NULL, pub_pkey) <= 0) {
			break;
		}

		// hashes data_size bytes of data at p_data into the verification context ctx.
		// this function can be called several times on the same ctx to hash additional data
		//
		if (EVP_DigestVerifyUpdate(ctx, (const void *)p_data, data_size) <= 0) {
			break;
		}

		// verifies the data in ctx against the signature in p_signature of length SGX_RSA3072_KEY_SIZE
		//
		verified = EVP_DigestVerifyFinal(ctx, (const unsigned char *)p_signature, SGX_RSA3072_KEY_SIZE);
		if (verified) {
			*p_result = SGX_RSA_VALID;
		}
		else if (verified != 0) {
			break;
		}

		retval = SGX_SUCCESS;
	} while (0);

	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pub_pkey) {
		EVP_PKEY_free(pub_pkey);
	}

	return retval;
}

sgx_status_t sgx_rsa3072_sign_ex(const uint8_t * p_data,
	uint32_t data_size,
	const sgx_rsa3072_key_t * p_key,
	const sgx_rsa3072_public_key_t *p_public,
	sgx_rsa3072_signature_t * p_signature)
{
	sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	sgx_rsa_result_t result = SGX_RSA_INVALID_SIGNATURE;

	if (p_public == NULL)
		return sgx_rsa3072_sign(p_data, data_size, p_key, p_signature);

	retval = sgx_rsa3072_sign(p_data, data_size, p_key, p_signature);
	if (retval != SGX_SUCCESS)
		return retval;
	retval = sgx_rsa3072_verify(p_data, data_size, p_public, p_signature, &result);
	if (retval != SGX_SUCCESS || result != SGX_RSA_VALID) {
		if(SGX_SUCCESS != sgx_read_rand((unsigned char*)p_signature, sizeof(sgx_rsa3072_signature_t)))
			(void)memset_s(p_signature, sizeof(sgx_rsa3072_signature_t), 0, sizeof(sgx_rsa3072_signature_t));
		return retval == SGX_ERROR_OUT_OF_MEMORY ? SGX_ERROR_OUT_OF_MEMORY : SGX_ERROR_INVALID_PARAMETER;
	}
	return retval;
}

