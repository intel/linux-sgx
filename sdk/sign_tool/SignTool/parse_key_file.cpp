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

/**
* File:
*     parse_key_file.cpp
* Description:
*     Parse the RSA key file that user inputs
* to get the key type and RSA structure.
*/

#include "parse_key_file.h"
#include "se_trace.h"
#include "util_st.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

bool rsa_get_bn(EVP_PKEY *pkey, BIGNUM **n, BIGNUM **e, BIGNUM **d)
{
    if (n)
    {
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n) == 0)
        {
            return false;
        }
    }
    if (e)
    {
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e) == 0)
        {
            return false;
        }
    }
    if (d)
    {
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, d) == 0)
        {
            return false;
        }
    }
    return true;
}

void rsa_free_bn(BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if(n)
        BN_free(n);
    if(e)
        BN_free(e);
    if(d)
        BN_free(d);
}

//parse_key_file():
//       parse the RSA key file
//Return Value:
//      true: success
//      false: fail
bool parse_key_file(int mode, const char *key_path, EVP_PKEY **pkey, int *pkey_type)
{
    assert(pkey != NULL && pkey_type != NULL);

    if(key_path == NULL)
    {
        *pkey_type = NO_KEY;
        return false;
    }
    BIO* rsa_bio = BIO_new_file(key_path, "r");
    if(rsa_bio == NULL)
    {
        se_trace(SE_TRACE_ERROR, OPEN_FILE_ERROR, key_path);
        return false;       
    }

    EVP_PKEY *key = NULL; 
    int key_type = UNIDENTIFIABLE_KEY;

    if(mode == SIGN)
    {
        key = PEM_read_bio_PrivateKey(rsa_bio, NULL, NULL, NULL);
        BIO_free(rsa_bio);
        if(!key)
        {
            se_trace(SE_TRACE_ERROR, KEY_FORMAT_ERROR);
            return false;
        }
        key_type = PRIVATE_KEY;
    }
    else if(mode == CATSIG)
    {
        key = PEM_read_bio_PUBKEY(rsa_bio, NULL, NULL, NULL);
        BIO_free(rsa_bio);
        if(!key)
        {
            se_trace(SE_TRACE_ERROR, KEY_FORMAT_ERROR);
            return false;
        }
        key_type = PUBLIC_KEY;
    }
    else
    {
        se_trace(SE_TRACE_ERROR, "ERROR: Invalid command\n %s", USAGE_STRING);
        BIO_free(rsa_bio);
        return false;
    }

    // Check the key size and exponent
    BIGNUM *n = NULL, *e = NULL;
    if(rsa_get_bn(key, &n, &e, NULL) == false)
    {
        EVP_PKEY_free(key);
        return false;        
    }
    if(BN_num_bytes(n) != N_SIZE_IN_BYTES)
    {
        se_trace(SE_TRACE_ERROR, INVALID_KEYSIZE_ERROR);
        EVP_PKEY_free(key);
        rsa_free_bn(n, e, NULL);
        return false;
    }
    char *p = BN_bn2dec(e);
    if(memcmp(p, "3", 2))
    {
        se_trace(SE_TRACE_ERROR, INVALID_EXPONENT_ERROR);
        OPENSSL_free(p);
        EVP_PKEY_free(key);
        rsa_free_bn(n, e, NULL);
        return false;
    }
    rsa_free_bn(n, e, NULL);
    OPENSSL_free(p);
    *pkey = key;
    *pkey_type = key_type;
    return true;
}
