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

/* definitions of common functions in trusted environment
 * for both server and client
 */

#include <stdio.h>
#include <string.h>

#include "common.h"

#include "sgx_trts.h"

#define RSA_PUBLIC_KEY_SIZE 512
#define RSA_PRIVATE_KEY_SIZE 2048

#define RSA_3072_PUBLIC_KEY_SIZE 650
#define RSA_3072_PRIVATE_KEY_SIZE 3072

#define RSA_TYPE 0
#define EC_TYPE 1 // EC-P384

const unsigned char certificate_subject_name[] =
    "CN=Intel SGX Enclave, O=Intel Corporation,C=US";

sgx_status_t generate_key_pair(
    int type,
	uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size);

void p_sgx_tls_qv_err_msg(sgx_ql_qv_result_t error_code);

void p_sgx_tls_qe_err_msg(quote3_error_t error_code);

