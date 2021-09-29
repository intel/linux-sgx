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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <ippcp.h> /* ipp library */

#ifndef SAFE_FREE
#define SAFE_FREE(ptr, size) do {if (NULL != (ptr)) {memset_s(ptr, size, 0, size); free(ptr); (ptr)=NULL;}} while(0);
#endif

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
	return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/* Define EC over GF(p) context for SM2 */
static IppsECCPState* new_ECC_sm2(void)
{
	int ctxSize = 0;
	IppsECCPState* pSM2 = NULL;
	IppStatus status = ippStsNoErr;

	// Get the size of ECC context for SM2
	status = ippsECCPGetSizeStdSM2(&ctxSize);
	if (status != ippStsNoErr) {
		printf("Error: fail to get size of ECCP\n");
		return NULL;
	}

	// Allocate the ECC context for SM2
	pSM2 = (IppsECCPState*)(malloc(ctxSize));
	if (pSM2 == NULL) {
		printf("Error: fail to allocate memory for ECCP\n");
		return NULL;
	}

	// Initialize the ECC context for SM2
	status = ippsECCPInitStdSM2(pSM2);
	if (status != ippStsNoErr) {
		printf("Error: fail to initialize ECCP\n");
		SAFE_FREE(pSM2, ctxSize);
		return NULL;
	}

	// Set up a recommended set of domain parameters for ECC context for SM2
	status = ippsECCPSetStdSM2(pSM2);
	if (status != ippStsNoErr) {
		printf("Error: fail to set up recommended set of domain parameters for ECCP\n");
		SAFE_FREE(pSM2, ctxSize);
		return NULL;
	}

	return pSM2;
}

/* Define EC over GF(p) Point context */
static IppsECCPPointState* new_ECC_Point(void)
{
	int ctxSize = 0;
	IppsECCPPointState* pPoint = NULL;
	IppStatus status = ippStsNoErr;

	status = ippsECCPPointGetSize(256, &ctxSize);
	if (status != ippStsNoErr) {
		printf("Error: fail to get size of ECCPPoint\n");
		return NULL;
	}

	pPoint = (IppsECCPPointState*)(malloc(ctxSize));
	if (pPoint == NULL) {
		printf("Error: fail to allocate memory for ECCPPoint\n");
		return NULL;
	}

	status = ippsECCPPointInit(256, pPoint);
	if (status != ippStsNoErr) {
		printf("Error: fail to initialize ECCPPoint\n");
		SAFE_FREE(pPoint, ctxSize);
		return NULL;
	}

	return pPoint;
}

/* Define Big Number context */
static IppsBigNumState* new_BN(int len, const unsigned int* pData)
{
	int ctxSize = 0;
	IppsBigNumState* pBN = NULL;
	IppStatus status = ippStsNoErr;

	status = ippsBigNumGetSize(len, &ctxSize);
	if (status != ippStsNoErr) {
		printf("Error: fail to get size of BigNum\n");
		return NULL;
	}

	pBN = (IppsBigNumState*)(malloc(ctxSize));
	if (pBN == NULL) {
		printf("Error: fail to allocate memory for BigNum\n");
		return NULL;
	}

	status = ippsBigNumInit(len, pBN);
	if (status != ippStsNoErr) {
		printf("Error: fail to initialize BigNum\n");
		SAFE_FREE(pBN, ctxSize);
		return NULL;
	}

	if (pData)
		ippsSet_BN(IppsBigNumPOS, len, pData, pBN);

	return pBN;
}

/* Define Pseudo-random generation context */
static IppsPRNGState* new_PRNG(void)
{
	int ctxSize = 0;
	IppsPRNGState* pPRNG = NULL;
	IppStatus status = ippStsNoErr;

	status = ippsPRNGGetSize(&ctxSize);
	if (status != ippStsNoErr) {
		printf("Error: fail to get size of PRNG\n");
		return NULL;
	}

	pPRNG = (IppsPRNGState*)(malloc(ctxSize));
	if (pPRNG == NULL) {
		printf("Error: fail to allocate memory for PRNG\n");
		return NULL;
	}

	status = ippsPRNGInit(256, pPRNG);
	if (status != ippStsNoErr) {
		printf("Error: fail to initialize PRNG\n");
		SAFE_FREE(pPRNG, ctxSize);
		return NULL;
	}

	return pPRNG;
}

/* Signing and verification using ECC context for SM2 */
int ecall_sm2(void)
{
	IppsECCPState *pECCPS = NULL;
	IppsBigNumState *pBNS = NULL;
	IppsPRNGState *pPRNGS = NULL;
	IppsBigNumState *pRandMsg = NULL;
	IppsBigNumState *pMsg = NULL;
	IppsBigNumState *regPrivateKey = NULL, *ephPrivateKey = NULL;
	IppsECCPPointState *regPublicKey = NULL, *ephPublicKey = NULL;
	IppsBigNumState *signX = NULL, *signY = NULL;

	IppStatus status = ippStsNoErr;
	IppECResult eccResult = ippECValid;
	int ret = 0;

	const unsigned int order[] = {0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE};
	const int ordSize = sizeof(order) / sizeof(unsigned int);
	unsigned int tmpData[ordSize];

	do {
		// 1. Create ECC context for SM2
		pECCPS = new_ECC_sm2();
		if (pECCPS == NULL) {
			printf("Error: fail to create ecc context for sm2\n");
			ret = -1;
			break;
		}

		// 2. Get order of ECC context for SM2
		pBNS = new_BN(ordSize, order);
		if (pBNS == NULL) {
			printf("Error: fail to get order of ecc context for sm2\n");
			ret = -2;
			break;
		}

		// 3. Create a random message to be signed
		pPRNGS = new_PRNG();
		if (pPRNGS == NULL) {
			printf("Error: fail to create pseudo-random generation context\n");
			ret = -3;
			break;
		}
		status = ippsPRNGen(tmpData, 256, pPRNGS);
		if (status != ippStsNoErr) {
			printf("Error: fail to generate a pseudorandom bit sequence\n");
			ret = -4;
			break;
		}
		pRandMsg = new_BN(ordSize, tmpData);
		if (pRandMsg == NULL) {
			printf("Error: fail to create a random message\n");
			ret = -5;
			break;
		}
		pMsg = new_BN(ordSize, 0);
		if (pMsg == NULL) {
			printf("Error: fail to create a message to be signed\n");
			ret = -6;
			break;
		}
		status = ippsMod_BN(pRandMsg, pBNS, pMsg);
		if (status != ippStsNoErr) {
			printf("Error: fail to compute modular reduction for input big number\n");
			ret = -7;
			break;
		}

		// 4. Create regular and ephemeral private key and public key
		regPrivateKey = new_BN(ordSize, 0);
		if (regPrivateKey == NULL) {
			printf("Error: fail to create regular private key\n");
			ret = -8;
			break;
		}
		ephPrivateKey = new_BN(ordSize, 0);
		if (ephPrivateKey == NULL) {
			printf("Error: fail to create ephemeral private key\n");
			ret = -9;
			break;
		}
		regPublicKey = new_ECC_Point();
		if (regPublicKey == NULL) {
			printf("Error: fail to create regular public key\n");
			ret = -10;
			break;
		}		
		ephPublicKey = new_ECC_Point();
		if (ephPublicKey == NULL) {
			printf("Error: fail to create ephemeral public key\n");
			ret = -11;
			break;
		}

		// 5. Generate regular and ephemeral key pairs
		status = ippsECCPGenKeyPair(regPrivateKey, regPublicKey, pECCPS, ippsPRNGen, pPRNGS);
		if (status != ippStsNoErr) {
			printf("Error: fail to generate regular key pairs\n");
			ret = -12;
			break;
		}
		status = ippsECCPGenKeyPair(ephPrivateKey, ephPublicKey, pECCPS, ippsPRNGen, pPRNGS);
		if (status != ippStsNoErr) {
			printf("Error: fail to generate ephemeral key pairs\n");
			ret = -13;
			break;
		}

		// 6. Sign using ECC context for SM2
		status = ippsECCPSetKeyPair(ephPrivateKey, ephPublicKey, ippFalse, pECCPS);
		if (status != ippStsNoErr) {
			printf("Error: fail to set ephemeral key pairs\n");
			ret = -14;
			break;
		}
		signX = new_BN(ordSize, 0);
		if (signX == NULL) {
			printf("Error: fail to create signX\n");
			ret = -15;
			break;
		}		
		signY = new_BN(ordSize, 0);
		if (signY == NULL) {
			printf("Error: fail to create signY\n");
			ret = -16;
			break;
		}
		status = ippsECCPSignSM2(pMsg, regPrivateKey, ephPrivateKey, signX, signY, pECCPS);
		if (status != ippStsNoErr) {
			printf("Error: fail to compute signature\n");
			ret = -17;
			break;
		}

		// 7. Verify using ECC context for SM2
		status = ippsECCPSetKeyPair(NULL, regPublicKey, ippTrue, pECCPS);
		if (status != ippStsNoErr) {
			printf("Error: fail to set regular public key\n");
			ret = -18;
			break;
		}
		status = ippsECCPVerifySM2(pMsg, regPublicKey, signX, signY, &eccResult, pECCPS);
		if((status != ippStsNoErr) || (eccResult != ippECValid)) {
			printf("Error: fail to verify signature\n");
			ret = -19;
			break;
		}
	} while(0);

	// 8. Final, remove secret and release resources
	SAFE_FREE(signX, sizeof(signX));
	SAFE_FREE(signY, sizeof(signY));
	SAFE_FREE(ephPublicKey, sizeof(ephPublicKey));
	SAFE_FREE(ephPrivateKey, sizeof(ephPrivateKey));
	SAFE_FREE(regPublicKey, sizeof(regPublicKey));
	SAFE_FREE(regPrivateKey, sizeof(regPrivateKey));
	SAFE_FREE(pRandMsg, sizeof(pRandMsg));
	SAFE_FREE(pMsg, sizeof(pMsg));
	SAFE_FREE(pPRNGS, sizeof(pPRNGS));
	SAFE_FREE(pBNS, sizeof(pBNS));
	SAFE_FREE(pECCPS, sizeof(pECCPS));

	return ret;
}

/* Compute a SM3 digest of a message. */
int ecall_sm3(void)
{
	int ctxSize = 0;
	IppsSM3State* pSM3 = NULL;
	IppStatus status = ippStsNoErr;
	unsigned char msg[] = "this is a test message";
	unsigned char digest[32] = "";
	unsigned char tag[32] = "";
	int ret = 0;

	do {
		// 1. Init
		// Get size of the SM3 context
		status = ippsSM3GetSize(&ctxSize);
		if (status != ippStsNoErr) {
			printf("Error: fail to get size of SM3 context\n");
			ret = -1;
			break;
		}

		// Allocate the SM3 context
		pSM3 = (IppsSM3State*)(malloc(ctxSize));
		if (pSM3 == NULL) {
			printf("Error: fail to allocate memory for SM3 context\n");
			ret = -2;
			break;
		}

		// Initialize the SM3 context
		status = ippsSM3Init(pSM3);
		if (status != ippStsNoErr) {
			printf("Error: fail to initialize SM3 context\n");
			ret = -3;
			break;
		}

		// 2. Update
		// Digest the message of specified length
		status = ippsSM3Update(msg, strlen((char*)msg), pSM3);
		if (status != ippStsNoErr) {
			printf("Error: fail to digest the message of specified length\n");
			ret = -4;
			break;
		}

		// 3. GetTag
		// Compute current SM3 digest value of the processed part of the message
		status = ippsSM3GetTag(tag, sizeof(tag), pSM3);
		if (status != ippStsNoErr) {
			printf("Error: fail to compute current SM3 digest value of the processed part of the message\n");
			ret = -5;
			break;
		}

		// 4. Final
		// Complete computation of the SM3 digest value
		status = ippsSM3Final(digest, pSM3);
		if (status != ippStsNoErr) {
			printf("Error: fail to complete computation of the SM3 digest value\n");
			ret = -6;
			break;
		}		
	} while(0);

	//Remove secret and release resources
	SAFE_FREE(pSM3, ctxSize);

	return ret;
}

/* SM4 block cipher mode(CBC) of operation. */
int ecall_sm4_cbc()
{
	// Plain text
	unsigned char plainText[16] = {
		0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,
		0xCC,0xCC,0xCC,0xCC,0xDD,0xDD,0xDD,0xDD
	};
	// Secret key
	unsigned char key[16] = {
		0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
		0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
	};
	// Initialization vector
	unsigned char iv[16] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
	};
	unsigned char encryptedText[16] = {};
	unsigned char decryptedText[16] = {};

	int ctxSize = 0;
	IppsSMS4Spec* pSM4 = 0;
	IppStatus status = ippStsNoErr, status1 = ippStsNoErr, status2 = ippStsNoErr;
	int ret = 0;

	do {
		// 1. Get size needed for SM4 context structure
		status = ippsSMS4GetSize(&ctxSize);
		if (status != ippStsNoErr) {
			printf("Error: fail to get size of SM4 context\n");
			ret = -1;
			break;
		}

		// 2. Allocate memory for SM4 context structure
		pSM4 = (IppsSMS4Spec*)malloc(ctxSize);
		if (pSM4 == NULL) {
			printf("Error: fail to allocate memory for SM4 context\n");
			ret = -2;
			break;
		}

		// 3. Initialize SM4 context
		status = ippsSMS4Init(key, sizeof(key), pSM4, ctxSize);
		if (status != ippStsNoErr) {
			printf("Error: fail to initialize SM4 context\n");
			ret = -3;
			break;
		}

		// 4. CBC Encryption and decryption
		status1 = ippsSMS4EncryptCBC(plainText, encryptedText, sizeof(plainText), pSM4, iv);
		if (status1 != ippStsNoErr) {
			printf("Error: fail to encrypt the plaintext\n");
			ret = -4;
			break;
		}
		status2 = ippsSMS4DecryptCBC(encryptedText, decryptedText, sizeof(encryptedText), pSM4, iv);
		if (status2 != ippStsNoErr) {
			printf("Error: fail to decrypt the ciphertext\n");
			ret = -5;
			break;
		}

		// 5. Compare original and decrypted text
		if (memcmp(plainText, decryptedText, sizeof(plainText)) != 0) {
			printf("Error: decrypted text is different from plaintext\n");
			ret = -6;
			break;
		}
	} while (0);

	// 6. Remove secret and release resources
	SAFE_FREE(pSM4, ctxSize);

	return ret;
}

/* SM4 counter mode(CTR) of operation. */
int ecall_sm4_ctr()
{
	// message to be encrypted
	unsigned char msg[] = "the message to be encrypted";
	// secret key
	unsigned char key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15";
	// initial counter
	unsigned char ctr0[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";
	// counter
	unsigned char ctr[16];

	unsigned char etext[sizeof(msg)];
	unsigned char dtext[sizeof(etext)];

	int ctxSize = 0;
	IppsSMS4Spec* pSM4 = 0;
	IppStatus status = ippStsNoErr, status1 = ippStsNoErr, status2 = ippStsNoErr;
	int ret = 0;

	do {
		// 1. Get size needed for SM4 context structure
		status = ippsSMS4GetSize(&ctxSize);
		if (status != ippStsNoErr) {
			printf("Error: fail to get size of SM4 context\n");
			ret = -1;
			break;
		}

		// 2. Allocate memory for SM4 context structure
		pSM4 = (IppsSMS4Spec*)malloc(ctxSize);
		if (pSM4 == NULL) {
			printf("Error: fail to allocate memory for SM4 context\n");
			ret = -2;
			break;
		}

		// 3. Initialize SM4 context
		status = ippsSMS4Init(key, sizeof(key), pSM4, ctxSize);
		if (status != ippStsNoErr) {
			printf("Error: fail to initialize SM4 context\n");
			ret = -3;
			break;
		}

		// 4. Encryption and decryption
		// Initialize counter before encryption
		memcpy(ctr, ctr0, sizeof(ctr));
		// Encrypt message
		status1 = ippsSMS4EncryptCTR(msg, etext, sizeof(msg), pSM4, ctr, 64);	
		if (status1 != ippStsNoErr) {
			printf("Erro: fail to encrypt the plaintext\n");
			ret = -4;
			break;
		}		
		// Initialize counter before decryption
		memcpy(ctr, ctr0, sizeof(ctr));
		// Decrypt message
		status2 = ippsSMS4DecryptCTR(etext, dtext, sizeof(etext), pSM4, ctr, 64);
		if (status2 != ippStsNoErr) {
			printf("Error: fail to decrypt the ciphertext\n");
			ret = -5;
			break;
		}

		// 5. Compare original message and decrypted text 
		if (memcmp(msg, dtext, sizeof(msg)) != 0) {
			printf("Error: decrypted text is different from plaintext\n");
			ret = -6;
			break;
		}
	} while (0);

	// 6. Remove secret and release resources
	SAFE_FREE(pSM4, ctxSize);

	return ret;
}
