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

#include "stdlib.h"
#include "string.h"
#include "sgx_tcrypto.h"
#include "se_tcrypto_common.h"
#include "openssl/cmac.h"
#include "openssl/err.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/* Message Authentication - Rijndael 128 CMAC
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: sgx_cmac_128bit_key_t *p_key - Pointer to key used in encryption/decryption operation
*           uint8_t *p_src - Pointer to input stream to be MACed
*           uint32_t src_len - Length of input stream to be MACed
*   Output: sgx_cmac_gcm_128bit_tag_t *p_mac - Pointer to resultant MAC */
sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src,
                                      uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac)
{
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *mctx = NULL;
	OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
	char cipher_name[] = "AES-128-CBC";
	size_t mac_len = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;


	if ((p_key == NULL) || (p_src == NULL) || (p_mac == NULL))  {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	do {
		if ((lib_ctx = OSSL_LIB_CTX_new()) == NULL)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
		if ((mac = EVP_MAC_fetch(lib_ctx, "CMAC", NULL)) == NULL)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		if ((mctx = EVP_MAC_CTX_new(mac)) == NULL) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,  cipher_name, sizeof(cipher_name));
		if(!EVP_MAC_CTX_set_params(mctx, params)) {
			break;
		}

		if ((!EVP_MAC_init(mctx, (const uint8_t *)p_key, sizeof(sgx_key_128bit_t), params))) {
			break;
		}
		if (!EVP_MAC_update(mctx, p_src, src_len)) {
			break;
		}
		if (!EVP_MAC_final(mctx, (uint8_t *)p_mac, &mac_len, sizeof(sgx_mac_t))) {
			break;
		}
 
		//validate mac size
		//
		if (mac_len != SGX_CMAC_MAC_SIZE) {
                    break;
		}

		ret = SGX_SUCCESS;
	} while (0);

	// we're done, clear and free CMAC ctx
	//
	EVP_MAC_CTX_free(mctx);
	EVP_MAC_free(mac);
	OSSL_LIB_CTX_free(lib_ctx);

	return ret;
}

/* Allocates and initializes CMAC state
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*   Inputs: sgx_cmac_128bit_key_t *p_key - Pointer to the key used in encryption/decryption operation
*   Output: sgx_cmac_state_handle_t *p_cmac_handle - Pointer to the handle of the EVP_MAC_CTX state  */
sgx_status_t sgx_cmac128_init(const sgx_cmac_128bit_key_t *p_key, sgx_cmac_state_handle_t* p_cmac_handle)
{
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *mctx = NULL;
	OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
	char cipher_name[] = "AES-128-CBC";
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;


	if ((p_key == NULL) || (p_cmac_handle == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	do {
		if ((lib_ctx = OSSL_LIB_CTX_new()) == NULL)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
		if ((mac = EVP_MAC_fetch(lib_ctx, "CMAC", NULL)) == NULL)
		{
			break;
		}

		if ((mctx = EVP_MAC_CTX_new(mac)) == NULL) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,  cipher_name, sizeof(cipher_name));

		if(!EVP_MAC_CTX_set_params(mctx, params)) {
			break;
		}
		if ((!EVP_MAC_init(mctx, (const uint8_t *)p_key, sizeof(sgx_key_128bit_t), params))) {
			break;
		}

		*p_cmac_handle = mctx;
		ret = SGX_SUCCESS;
	} while (0);

	EVP_MAC_free(mac);
	OSSL_LIB_CTX_free(lib_ctx);
	if (ret != SGX_SUCCESS) {
		EVP_MAC_CTX_free(mctx);
	}
	return ret;
}

/* Updates CMAC has calculation based on the input message
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.
*	Input:  sgx_cmac_state_handle_t cmac_handle - Handle to the EVP_MAC_CTX state
*	        uint8_t *p_src - Pointer to the input stream to be hashed
*          uint32_t src_len - Length of the input stream to be hashed  */
sgx_status_t sgx_cmac128_update(const uint8_t *p_src, uint32_t src_len, sgx_cmac_state_handle_t cmac_handle)

{
	if ((p_src == NULL) || (cmac_handle == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (!EVP_MAC_update((EVP_MAC_CTX *)cmac_handle, p_src, src_len)) {
		return SGX_ERROR_UNEXPECTED;
	}
	return SGX_SUCCESS;
}

/* Returns Hash calculation
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*	Input:  sgx_cmac_state_handle_t cmac_handle - Handle to the EVP_MAC_CTX state
*   Output: sgx_cmac_128bit_tag_t *p_hash - Resultant hash from operation  */
sgx_status_t sgx_cmac128_final(sgx_cmac_state_handle_t cmac_handle, sgx_cmac_128bit_tag_t *p_hash)

{
	if ((cmac_handle == NULL) || (p_hash == NULL))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	size_t mactlen;

	if (!EVP_MAC_final((EVP_MAC_CTX*)cmac_handle, (unsigned char*)p_hash, &mactlen, sizeof(sgx_mac_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	return SGX_SUCCESS;
}


/* Clean up the CMAC state
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*   Input:  sgx_cmac_state_handle_t cmac_handle  - Handle to the EVP_MAC_CTX state  */
sgx_status_t sgx_cmac128_close(sgx_cmac_state_handle_t cmac_handle)
{
	if (cmac_handle == NULL) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	EVP_MAC_CTX* pState = (EVP_MAC_CTX*)cmac_handle;
	EVP_MAC_CTX_free(pState);
	cmac_handle = NULL;
	return SGX_SUCCESS;
}
