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
#include "openssl/hmac.h"
#include "openssl/err.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>

 /* Message Authentication - HMAC 256
 * Parameters:
 *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
 *   Inputs: const unsigned char *p_src - Pointer to input stream to be MACed
 *           int src_len - Source length
 *           const unsigned char *p_key - Pointer to key used in message authentication operation
 *           int key_len - Key length
 *           int mac_len - Expected output MAC length
 *   Output: unsigned char *p_mac - Pointer to resultant MAC
 */
sgx_status_t sgx_hmac_sha256_msg(const unsigned char *p_src, int src_len, const unsigned char *p_key, int key_len,
    unsigned char *p_mac, int mac_len)
{
	if ((p_src == NULL) || (p_key == NULL) || (p_mac == NULL) || (src_len <= 0) || (key_len <= 0) || (mac_len <= 0)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	unsigned char *ret_mac = NULL;
	unsigned int md_len = 0;
	do {
		ret_mac = HMAC(EVP_sha256(), (const void *)p_key, key_len, p_src, src_len, p_mac, &md_len);
		if (ret_mac == NULL || md_len != (size_t)mac_len) {
			break;
		}

		ret = SGX_SUCCESS;
	} while (0);
	
	md_len = 0;
	if (ret != SGX_SUCCESS) {
		memset_s(p_mac, mac_len, 0, mac_len);
	}
	
	return ret;
}


/* Allocates and initializes HMAC state
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*   Inputs: const unsigned char *p_key - Pointer to the key used in message authentication operation
*           int key_len - Key length
*   Output: sgx_hmac_state_handle_t *p_hmac_handle - Pointer to the initialized EVP_MAC_CTX state handle
*/
sgx_status_t sgx_hmac256_init(const unsigned char *p_key, int key_len, sgx_hmac_state_handle_t *p_hmac_handle)
{
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *mctx = NULL;
	OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
	char digest_name[] = "SHA256";
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	if ((p_key == NULL) || (key_len <= 0) || (p_hmac_handle == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	do {
		if ((lib_ctx = OSSL_LIB_CTX_new()) == NULL)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}
		if ((mac = EVP_MAC_fetch(lib_ctx, "HMAC", NULL)) == NULL)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		if ((mctx = EVP_MAC_CTX_new(mac)) == NULL) {
			ret = SGX_ERROR_OUT_OF_MEMORY;
			break;
		}

		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,  digest_name, sizeof(digest_name));

		if ((!EVP_MAC_init(mctx, (const uint8_t *)p_key, sizeof(sgx_key_128bit_t), params))) {
			break;
		}

		*p_hmac_handle = mctx;
		ret = SGX_SUCCESS;
	} while (0);


	EVP_MAC_free(mac);
	OSSL_LIB_CTX_free(lib_ctx);
	if (ret != SGX_SUCCESS) {
		EVP_MAC_CTX_free(mctx);
	}

	return ret;
}

/* Updates HMAC hash calculation based on the input message
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.
*	Input:  uint8_t *p_src - Pointer to the input stream to be hashed
*	        int src_len - Length of input stream to be hashed
*	        sgx_hmac_state_handle_t hmac_handle - Handle to the EVP_MAC_CTX state
*/
sgx_status_t sgx_hmac256_update(const uint8_t *p_src, int src_len, sgx_hmac_state_handle_t hmac_handle)
{
	if ((p_src == NULL) || (src_len <= 0) || (hmac_handle == NULL)) {
        	return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	do {
		if (!EVP_MAC_update((EVP_MAC_CTX *)hmac_handle, p_src, src_len)) {
			break;
		}
		
		ret = SGX_SUCCESS;
	} while (0);
	
	return ret;
}

/* Returns calculated hash
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
*	Input:  sgx_hmac_state_handle_t hmac_handle - Handle to the EVP_MAC_CTX state
*	        int hash_len - Expected MAC length
*   Output: unsigned char *p_hash - Resultant hash from HMAC operation
*/
sgx_status_t sgx_hmac256_final(unsigned char *p_hash, int hash_len, sgx_hmac_state_handle_t hmac_handle)
{
	if ((p_hash == NULL) || (hash_len <= 0) || (hmac_handle == NULL)) {
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	size_t mactlen;

	do {
	        if (!EVP_MAC_final((EVP_MAC_CTX*)hmac_handle, (unsigned char*)p_hash, &mactlen, hash_len)) {
			break;
		}
		if (mactlen != (size_t)hash_len) {
			break;
		}
		
		ret = SGX_SUCCESS;
	} while (0);
	
	if (ret != SGX_SUCCESS) {
		mactlen = 0;
		memset_s(p_hash, hash_len, 0, hash_len);
	}
	
	return ret;
}

/* Clean up and free the HMAC state
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS
*   Input:  sgx_hmac_state_handle_t hmac_handle  - Handle to the EVP_MAC_CTX state
* */
sgx_status_t sgx_hmac256_close(sgx_hmac_state_handle_t hmac_handle)
{
	if (hmac_handle != NULL) {
		EVP_MAC_CTX* pState = (EVP_MAC_CTX*)hmac_handle;
		EVP_MAC_CTX_free(pState);
		hmac_handle = NULL;
	}
	
	return SGX_SUCCESS;
}
