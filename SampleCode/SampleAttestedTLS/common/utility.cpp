/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "utility.h"

//
// Generate_Key_Pair function:
// type1: RSA
// type2: EC-P384
// currently all hardware independant
//
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_trts.h"


int get_pkey_by_rsa(EVP_PKEY *pk)
{
    int res = -1;
    RSA* rsa = nullptr;
    BIGNUM* e = nullptr;


    e = BN_new();
    if (!e) {
        PRINT("BN_new failed\n");
        return res;
    }

    res = BN_set_word(e, (BN_ULONG)RSA_F4);
    if (!res) {
        PRINT("BN_set_word failed (%d)\n", res);
		return res;
    }

    rsa = RSA_new();
    if (!rsa) {
        PRINT("RSA_new failed\n");
        res = -1;
		return res;
    }

    res = RSA_generate_key_ex(
        rsa,
        RSA_3072_PRIVATE_KEY_SIZE,   /* number of bits for the key value */
        e,      /* exponent - RSA_F4 is defined as 0x10001L */
        nullptr /* callback argument - not needed in this case */
    );

    if (!res)
    {
        PRINT("RSA_generate_key failed (%d)\n", res);
		return res;
    }

    // Assign RSA key to EVP_PKEY structure
    EVP_PKEY_assign_RSA(pk, rsa);

    return res;
}

int get_pkey_by_ec(EVP_PKEY *pk)
{
	int res = -1;
	EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL)
        return res;
    res = EVP_PKEY_keygen_init(ctx);
    if (res <= 0)
    {
        PRINT("EC_generate_key failed (%d)\n", res);
        return res;
    }

    res = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1);
    if (res <= 0)
    {
        PRINT("EC_generate_key failed (%d)\n", res);
        return res;
    }

    /* Generate key */
    res = EVP_PKEY_keygen(ctx, &pk);
    if (res <= 0)
    {
        PRINT("EC_generate_key failed (%d)\n", res);
        return res;
    }

    return res;
}


// actually is generating RSA pair
// hardare independant
sgx_status_t generate_key_pair(
    int type,
	uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    uint8_t* local_public_key = nullptr;
    uint8_t* local_private_key = nullptr;
    int res = -1;
    EVP_PKEY* pkey = nullptr;
    BIO* bio = nullptr;

    pkey = EVP_PKEY_new();
    if (!pkey)
    {
        PRINT("EVP_PKEY_new failed\n");
        result = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    if (type != RSA_TYPE && type != EC_TYPE)
    {
        type = RSA_TYPE; // by default, we use RSA_TYPE
    }

    switch(type)
    {
        case RSA_TYPE:
            res = get_pkey_by_rsa(pkey);
            break;
        case EC_TYPE:
            res = get_pkey_by_ec(pkey);
            break;
    }

    if (res <= 0)
    {
        PRINT("get_pkey failed (%d)\n", res);
		result = SGX_ERROR_UNEXPECTED;
		goto done;
    }

    // Allocate memory
    local_public_key = (uint8_t*)malloc(RSA_3072_PUBLIC_KEY_SIZE);
    if (!local_public_key)
    {
        PRINT("out-of-memory:calloc(local_public_key failed\n");
        result = SGX_ERROR_OUT_OF_EPC;
        goto done;
    }
    memset(local_public_key, 0x00, RSA_3072_PUBLIC_KEY_SIZE);

    local_private_key = (uint8_t*)malloc(RSA_3072_PRIVATE_KEY_SIZE);
    if (!local_private_key)
    {
        PRINT("out-of-memory: calloc(local_private_key) failed\n");
        result = SGX_ERROR_OUT_OF_EPC;
        goto done;
    }
    memset(local_private_key, 0x00, RSA_3072_PRIVATE_KEY_SIZE);

    // Write out the public/private key in PEM format for exchange with
    // other enclaves.
    bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        PRINT("BIO_new for local_public_key failed\n");
		goto done;
    }

    res = PEM_write_bio_PUBKEY(bio, pkey);
    if (!res)
    {
        PRINT("PEM_write_bio_PUBKEY failed (%d)\n", res);
        goto done;
    }

    res = BIO_read(bio, local_public_key, RSA_3072_PUBLIC_KEY_SIZE);
    if (!res)
    {
        PRINT("BIO_read public key failed (%d)\n", res);
        goto done;
    }
    BIO_free(bio);
    bio = nullptr;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        PRINT("BIO_new for local_public_key failed\n");
        goto done;
    }

    res = PEM_write_bio_PrivateKey(
        bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    if (!res)
    {
        PRINT("PEM_write_bio_PrivateKey failed (%d)\n", res);
        goto done;
    }

    res = BIO_read(bio, local_private_key, RSA_3072_PRIVATE_KEY_SIZE);
    if (!res)
    {
        PRINT("BIO_read private key failed (%d)\n", res);
        goto done;
    }

    BIO_free(bio);
    bio = nullptr;

    *public_key = local_public_key;
    *private_key = local_private_key;

    *public_key_size = strlen(reinterpret_cast<const char *>(local_public_key)) + 1;
    *private_key_size = strlen(reinterpret_cast<const char *>(local_private_key)) + 1;

    PRINT("public_key_size %d, private_key_size %d\n", *public_key_size, *private_key_size);
    result = SGX_SUCCESS;

done:
    if (bio)
        BIO_free(bio);
    if (pkey)
        EVP_PKEY_free(pkey); // When this is called, rsa is also freed
    if (result != SGX_SUCCESS)
	{
        if (local_public_key)
            free(local_public_key);
        if (local_private_key)
            free(local_private_key);
    }
    return result;
}
