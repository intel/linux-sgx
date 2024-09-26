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


#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t
{
	sgx_status_t err;
	const char *msg;
	const char *sug;
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
	{
		SGX_ERROR_MEMORY_MAP_FAILURE,
		"Failed to reserve memory for the enclave.",
		NULL
	},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++)
	{
		if (ret == sgx_errlist[idx].err)
		{
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
				ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	/* Call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		print_error_message(ret);
		return -1;
	}

	return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow. 
	 */
	printf("%s", str);
}

/* ECall functions */
/* GM SM2 sign and verify functions */
int ecall_sm2_sign_verify_functions()
{
	int rev = -1;
	ecall_sm2_sign_verify(global_eid, &rev);
	return rev;
}

/* GM SM2 key exchange functions */
int ecall_sm2_key_exchange_functions()
{
	int rev = -1;
	ecall_sm2_key_exchange(global_eid, &rev);
	return rev;
}

/* GM SM2 encrypt and decrypt functions(GM version) */
int ecall_sm2_encrypt_decrypt_gm_functions()
{
	int rev = -1;
	ecall_sm2_encrypt_decrypt_gm(global_eid, &rev);
	return rev;
}

/* GM SM3 functions */
int ecall_sm3_functions()
{
	int rev = -1;
	ecall_sm3(global_eid, &rev);
	return rev;
}

/* GM SM4 CBC functions */
int ecall_sm4_cbc_functions()
{
	int rev = -1;
	ecall_sm4_cbc(global_eid, &rev);
	return rev;
}

/* GM SM4 CTR functions */
int ecall_sm4_ctr_functions()
{
	int rev = -1;
	ecall_sm4_ctr(global_eid, &rev);
	return rev;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);

	/* Initialize the enclave */
	if (initialize_enclave() < 0)
	{
		printf("Enter a character before exit ...\n");
		getchar();
		return -1;
	}

	/* GM SMx functions test */
	/* SM2 */
	if (ecall_sm2_sign_verify_functions() == 0)
		printf("GM SM2 - sign and verify: PASS\n");
	else
		printf("GM SM2 - sign and verify: FAIL\n");

	if (ecall_sm2_key_exchange_functions() == 0)
		printf("GM SM2 - key exchange: PASS\n");
	else
		printf("GM SM2 - key exchange: FAIL\n");

	if (ecall_sm2_encrypt_decrypt_gm_functions() == 0)
		printf("GM SM2 - encrypt and decrypt(GM version): PASS\n");
	else
		printf("GM SM2 - encrypt and decrypt(GM version): FAIL\n");

	/* SM3 */
	if (ecall_sm3_functions() == 0)
		printf("GM SM3 - compute digest of message: PASS\n");
	else
		printf("GM SM3 - compute digest of message: FAIL\n");

	/* SM4 */
	if (ecall_sm4_cbc_functions() == 0)
		printf("GM SM4 - cbc encrypt and decrypt: PASS\n");
	else
		printf("GM SM4 - cbc encrypt and decrypt: FAIL\n");

	if (ecall_sm4_ctr_functions () == 0)
		printf("GM SM4 - ctr encrypt and decrypt: PASS\n");
	else
		printf("GM SM4 - ctr encrypt and decrypt: FAIL\n");

	/* Destroy the enclave */
	sgx_destroy_enclave(global_eid);

	printf("Info: SampleEnclaveGMIPP successfully returned.\n");

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
