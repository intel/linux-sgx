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
#include "sgx_trts.h"

#include <ippcp.h> /* ipp library */

#ifndef SAFE_FREE
#define SAFE_FREE(ptr, size) do {if (NULL != (ptr)) {memset_s(ptr, size, 0, size); free(ptr); (ptr)=NULL;}} while(0);
#endif

const unsigned int order[] = {0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE};
const int ordSize = sizeof(order) / sizeof(unsigned int);

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

/* Convert bit size into 32-bit word size */
static int Bitsize2Wordsize(int nBits)
{
	return (nBits+31)>>5;
}

/* Set up an array of 32-bit items with random number */
static int rand(void)
{
	int num = 0;
	sgx_read_rand((unsigned char*)&num, sizeof(int));
	return num;
}
static unsigned int* rand32(unsigned int* pX, int size)
{
	for(int n = 0; n < size; n++)
		pX[n] = rand();
	return pX;
}

/* Define Pseudo-random generation context */
static IppsPRNGState* new_PRNG(void)
{
	int size = 0;
	IppsPRNGState* pPRNG = NULL;
	IppsBigNumState* pBN = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	int seedBitsize = 160;
	int seedSize = Bitsize2Wordsize(seedBitsize);
	unsigned int* seed = NULL;
	unsigned int* augm = NULL;

	ipp_ret = ippsPRNGGetSize(&size);
	if (ipp_ret != ippStsNoErr) {
		printf("Error: fail to get size of PRNG\n");
		return NULL;
	}

	pPRNG = (IppsPRNGState*)malloc(size);
	if (pPRNG == NULL) {
		printf("Error: fail to allocate memory for PRNG\n");
		return NULL;
	}

	ipp_ret = ippsPRNGInit(seedBitsize, pPRNG);
	if (ipp_ret != ippStsNoErr) {
		printf("Error: fail to initialize PRNG\n");
		SAFE_FREE(pPRNG, size);
		return NULL;
	}

	seed = (unsigned int*)malloc(seedSize);
	augm = (unsigned int*)malloc(seedSize);
	ipp_ret = ippsPRNGSetSeed(pBN=new_BN(seedSize, rand32(seed, seedSize)), pPRNG);
	if (ipp_ret != ippStsNoErr) {
		printf("Error: fail to set the seed value of PRNG\n");
		SAFE_FREE(pPRNG, size);
		SAFE_FREE(pBN, sizeof(pBN));
		SAFE_FREE(pBN, sizeof(augm));
		SAFE_FREE(pBN, sizeof(seed));
		return NULL;
	}
	SAFE_FREE(pBN, sizeof(pBN));
	ipp_ret = ippsPRNGSetAugment(pBN=new_BN(seedSize, rand32(augm, seedSize)), pPRNG);
	if (ipp_ret != ippStsNoErr) {
		printf("Error: fail to set the entropy augmentation of PRNG\n");
		SAFE_FREE(pPRNG, size);
		SAFE_FREE(pBN, sizeof(pBN));
		SAFE_FREE(pBN, sizeof(augm));
		SAFE_FREE(pBN, sizeof(seed));
		return NULL;
	}

	return pPRNG;
}

/* Calculate ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA) */
static int hash_digest_z(const IppsHashMethod *hash_method, const char *id, const int id_len, const IppsBigNumState *pubX, const IppsBigNumState *pubY, unsigned char *z_digest)
{
	int ctx_size = 0;
	IppsHashState_rmf* hash_handle = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	int ret = 0;

	int id_bit_len = id_len * 8;
	unsigned char entl[2] = {0};
	entl[0] = (id_bit_len & 0xff00) >> 8;
	entl[1] = id_bit_len & 0xff;
	unsigned char a[32] = {
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
	unsigned char b[32] = {
		0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
		0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
		0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
		0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};
	unsigned char xG[32] = {
		0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
		0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
		0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
		0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};
	unsigned char yG[32] = {
		0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
		0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
		0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
		0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};
	unsigned char xA[32] = {0};
	unsigned char yA[32] = {0};

	do {
		ipp_ret = ippsGetOctString_BN(xA, 32, pubX);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to Convert BN value pubX into octet string xA\n");
			ret = -1;
			break;
		}
		ipp_ret = ippsGetOctString_BN(yA, 32, pubY);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to Convert BN value pubY into octet string yA\n");
			ret = -2;
			break;
		}

		ipp_ret = ippsHashGetSize_rmf(&ctx_size);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to get size of ippsHashGetSize_rmf\n");
			ret = -3;
			break;
		}

		hash_handle = (IppsHashState_rmf*)(malloc(ctx_size));
		if (!hash_handle)
		{
			printf("Error: fail to allocate memory for ippsHashGetSize_rmf\n");
			ret = -4;
			break;
		}

		// Set Hash 256 handler:
		// SM3 - ippsHashMethod_SM3()
		// SHA256 - ippsHashMethod_SHA256_TT()
		ipp_ret = ippsHashInit_rmf(hash_handle, hash_method);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to set hash 256 handler\n");
			ret = -5;
			break;
		}

		// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
		ipp_ret = ippsHashUpdate_rmf(entl, sizeof(entl), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of ENTLA\n");
			ret = -6;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf((unsigned char*)id, id_len, hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of IDA\n");
			ret = -7;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(a, sizeof(a), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of a\n");
			ret = -8;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(b, sizeof(b), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of b\n");
			ret = -9;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(xG, sizeof(xG), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of xG\n");
			ret = -10;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(yG, sizeof(yG), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of yG\n");
			ret = -11;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(xA, sizeof(xA), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of xA\n");
			ret = -12;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf(yA, sizeof(yA), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of yA\n");
			ret = -13;
			break;
		}
		ipp_ret = ippsHashFinal_rmf(z_digest, hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to complete message digesting and return digest\n");
			ret = -14;
			break;
		}
	} while(0);

	SAFE_FREE(hash_handle, sizeof(hash_handle));

	return ret;
}

/* Calculate ZA = H256(Z||M) */
static int hash_digest_with_preprocess(const IppsHashMethod *hash_method, const char *msg, const int msg_len, const char *id, const int id_len, const IppsBigNumState* pubX, const IppsBigNumState* pubY, unsigned char *digest)
{
	int ctx_size = 0;
	IppsHashState_rmf* hash_handle = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	int ret = 0;
	unsigned char z_digest[32] = {0};

	do {
		ret = hash_digest_z(hash_method, id, id_len, pubX, pubY, z_digest);
		if (ret != 0)
		{
			printf("Error: fail to complete SM3 digest of leading data Z\n");
			return -1;
			break;
		}

		ipp_ret = ippsHashGetSize_rmf(&ctx_size);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to get size of IppsHashState_rmf\n");
			ret = -2;
			break;
		}

		hash_handle = (IppsHashState_rmf*)(malloc(ctx_size));
		if (!hash_handle)
		{
			printf("Error: fail to allocate memory for IppsHashState_rmf\n");
			ret = -3;
			break;
		}

		// Set Hash 256 handler:
		// SM3 - ippsHashMethod_SM3()
		// SHA256 - ippsHashMethod_SHA256_TT()
		ipp_ret = ippsHashInit_rmf(hash_handle, hash_method);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to initialize IppsHashState_rmf\n");
			ret = -4;
			break;
		}

		// ZA = H256(Z||M)
		ipp_ret = ippsHashUpdate_rmf(z_digest, sizeof(z_digest), hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of Z\n");
			ret = -5;
			break;
		}
		ipp_ret = ippsHashUpdate_rmf((unsigned char *)msg, msg_len, hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to update hash value of M\n");
			ret = -6;
			break;
		}
		ipp_ret = ippsHashFinal_rmf(digest, hash_handle);
		if (ipp_ret != ippStsNoErr)
		{
			printf("Error: fail to complete message digesting and return digest\n");
			ret = -7;
			break;
		}
	} while(0);

	SAFE_FREE(hash_handle, sizeof(hash_handle));

	return ret;
}

/* SM2 sign */
static int sm2_do_sign(const IppsBigNumState *regPrivateKey, const IppsHashMethod *hash_method, const char *id, const int id_len, const char *msg, const int msg_len, IppsBigNumState* signX, IppsBigNumState* signY)
{
	IppsECCPState *pECCPS = NULL;
	IppsPRNGState *pPRNGS = NULL;
	IppsBigNumState *ephPrivateKey = NULL;
	IppsECCPPointState *regPublicKey = NULL, *ephPublicKey = NULL;
	IppsBigNumState *pMsg = NULL;
	IppsBigNumState *pX = NULL, *pY = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	int ret = 0;
	unsigned char hash[32] = {0};

	do {
		// 1. Create ECC context for SM2
		pECCPS = new_ECC_sm2();
		if (pECCPS == NULL) {
			printf("Error: fail to create pECCPS\n");
			ret = -1;
			break;
		}

		// 2. Create ephemeral private key and public key, regular public key
		ephPrivateKey = new_BN(ordSize, 0);
		if (ephPrivateKey == NULL) {
			printf("Error: fail to create ephemeral private key\n");
			ret = -2;
			break;
		}
		ephPublicKey = new_ECC_Point();
		if (ephPublicKey == NULL) {
			printf("Error: fail to create ephemeral public key\n");
			ret = -3;
			break;
		}
		regPublicKey = new_ECC_Point();
		if (regPublicKey == NULL) {
			printf("Error: fail to create regular public key\n");
			ret = -4;
			break;
		}
		ipp_ret = ippsECCPPublicKey(regPrivateKey, regPublicKey, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to calculate regular public key\n");
			ret = -5;
			break;
		}

		// 3. Generate ephemeral key pairs
		pPRNGS = new_PRNG();
		if (pPRNGS == NULL) {
			printf("Error: fail to create pPRNGS\n");
			ret = -6;
			break;
		}

		ipp_ret = ippsECCPGenKeyPair(ephPrivateKey, ephPublicKey, pECCPS, ippsPRNGen, pPRNGS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to generate ephemeral key pairs\n");
			ret = -7;
			break;
		}

		// 4. Create pX and pY
		pX = new_BN(ordSize, 0);
		if (pX == NULL){
			printf("Error: fail to create pX\n");
			ret = -8;
			break;			
		}
		pY = new_BN(ordSize, 0);
		if (pY == NULL){
			printf("Error: fail to create pY\n");
			ret = -9;
			break;			
		}
		ipp_ret = ippsECCPGetPoint(pX, pY, regPublicKey, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to convert internal presentation EC point into regular affine coordinates EC point\n");
			ret = -10;
			break;	
		}

		// 5. Do user message digest
		ret = hash_digest_with_preprocess(hash_method, msg, msg_len, id, id_len, pX, pY, hash);
		if (ret != 0) {
			printf("Error: fail to do hash digest with preprocess\n");
			ret = -11;
			break;
		}
		pMsg = new_BN(ordSize, 0);
		if (pMsg == NULL) {
			printf("Error: fail to create BN\n");
			ret = -12;
			break;			
		}
		ipp_ret = ippsSetOctString_BN(hash, sizeof(hash), pMsg);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to convert octet string into BN value\n");
			ret = -13;
			break;
		}

		// 6. Sign using ECC context for SM2
		ipp_ret = ippsECCPSetKeyPair(ephPrivateKey, ephPublicKey, ippFalse, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to set ephemeral key pairs\n");
			ret = -14;
			break;
		}
		ipp_ret = ippsECCPSignSM2(pMsg, regPrivateKey, ephPrivateKey, signX, signY, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to compute signature\n");
			ret = -15;
			break;
		}
	} while(0);

	// 7. Final, remove secret and release resources
	SAFE_FREE(pY, sizeof(pY));
	SAFE_FREE(pX, sizeof(pX));
	SAFE_FREE(pMsg, sizeof(pMsg));
	SAFE_FREE(regPublicKey, sizeof(regPublicKey));
	SAFE_FREE(ephPublicKey, sizeof(ephPublicKey));
	SAFE_FREE(ephPrivateKey, sizeof(ephPrivateKey));
	SAFE_FREE(pPRNGS, sizeof(pPRNGS));
	SAFE_FREE(pECCPS, sizeof(pECCPS));

	return ret;
}

/* SM2 verify */
static int sm2_do_verify(const IppsECCPPointState *regPublicKey, const IppsHashMethod *hash_method, const char *id, const int id_len, const char *msg, const int msg_len, IppsBigNumState* signX, IppsBigNumState* signY)
{
	IppsECCPState *pECCPS = NULL;
	IppsBigNumState* pMsg = NULL;
	IppsBigNumState *pX = NULL, *pY = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	IppECResult eccResult = ippECValid;
	int ret = 0;
	unsigned char hash[32] = {0};

	do {
		// 1. Create ECC context for SM2
		pECCPS = new_ECC_sm2();
		if (pECCPS == NULL) {
			printf("Error: fail to create pECCPS\n");
			ret = -1;
			break;
		}

		// 2. Create pX and pY
		pX = new_BN(ordSize, 0);
		if (pX == NULL){
			printf("Error: fail to create pX\n");
			ret = -2;
			break;			
		}
		pY = new_BN(ordSize, 0);
		if (pY == NULL){
			printf("Error: fail to create pY\n");
			ret = -3;
			break;			
		}
		ipp_ret = ippsECCPGetPoint(pX, pY, regPublicKey, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to convert internal presentation EC point into regular affine coordinates EC point\n");
			ret = -4;
			break;	
		}

		// 3. Do user message digest
		ret = hash_digest_with_preprocess(hash_method, msg, msg_len, id, id_len, pX, pY, hash);
		if (ret != 0) {
			printf("Error: fail to do hash digest with preprocess\n");
			ret = -5;
			break;
		}
		pMsg = new_BN(ordSize, 0);
		if (pMsg == NULL) {
			printf("Error: fail to create BN\n");
			ret = -6;
			break;
		}
		ipp_ret = ippsSetOctString_BN(hash, sizeof(hash), pMsg);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to convert octet string into BN value\n");
			ret = -7;
			break;
		}

		// 4. Verify using ECC context for SM2	
		ipp_ret = ippsECCPSetKeyPair(NULL, regPublicKey, ippTrue, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to set regular public key\n");
			ret = -8;
			break;
		}
		ipp_ret = ippsECCPVerifySM2(pMsg, regPublicKey, signX, signY, &eccResult, pECCPS);
		if((ipp_ret != ippStsNoErr) || (eccResult != ippECValid)) {
			printf("Error: fail to verify signature\n");
			ret = -9;
			break;
		}
	} while(0);

	// 5. Final, remove secret and release resources
	SAFE_FREE(pY, sizeof(pY));
	SAFE_FREE(pX, sizeof(pX));
	SAFE_FREE(pMsg, sizeof(pMsg));
	SAFE_FREE(pECCPS, sizeof(pECCPS));

	return ret;
}

/* Signing and verification using ECC context for SM2 */
int ecall_sm2(void)
{
	IppsECCPState *pECCPS = NULL;
	IppsBigNumState *regPrivateKey = NULL;
	IppsECCPPointState *regPublicKey = NULL;
	IppsBigNumState *signX = NULL, *signY = NULL;
	IppStatus ipp_ret = ippStsNoErr;
	int ret = 0;

	char *message = "context need to be signed";
	char *user_id = "1234567812345678";
	unsigned char priKey[] = "\xd0\x91\x56\x73\x30\x17\xbd\xad\x80\x9f\xd9\xbb\xd8\xc6\x93\xf6\x02\x30\x59\x31\x69\xb6\xf9\x4a\xaf\x1c\x8e\xe1\x38\xcc\x99\xb5";

	do {
		// 1. Create ECC context for SM2
		pECCPS = new_ECC_sm2();
		if (pECCPS == NULL) {
			printf("Error: fail to create ecc context for sm2\n");
			ret = -1;
			break;
		}

		// 2. Create regular private key and public key
		regPrivateKey = new_BN(ordSize, 0);
		if (regPrivateKey == NULL) {
			printf("Error: fail to create regular private key\n");
			ret = -2;
			break;
		}
		regPublicKey = new_ECC_Point();
		if (regPublicKey == NULL) {
			printf("Error: fail to create regular public key\n");
			ret = -3;
			break;
		}

		// 3. Create regular private and public key pairs
		ipp_ret = ippsSetOctString_BN(priKey, sizeof(priKey)-1, regPrivateKey);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to convert octet string into BN value\n");
			ret = -4;
			break;
		}
		ipp_ret = ippsECCPPublicKey(regPrivateKey, regPublicKey, pECCPS);
		if (ipp_ret != ippStsNoErr) {
			printf("Error: fail to calculate regular public key\n");
			ret = -5;
			break;
		}

		// 4. Create signX and signY
		signX = new_BN(ordSize, 0);
		if (signX == NULL) {
			printf("Error: fail to create signX\n");
			ret = -6;
			break;
		}		
		signY = new_BN(ordSize, 0);
		if (signY == NULL) {
			printf("Error: fail to create signY\n");
			ret = -7;
			break;
		}		

		// 5. Sign using ECC context for SM2
		ret = sm2_do_sign(regPrivateKey, ippsHashMethod_SM3(), user_id, strlen(user_id), message, strlen(message), signX, signY);
		if(ret != 0)
		{
			printf("Error: fail to sign\n");
			ret = -8;
			break;
		}

		// 6. Verify using ECC context for SM2
		ret = sm2_do_verify(regPublicKey, ippsHashMethod_SM3(), user_id, strlen(user_id), message, strlen(message), signX, signY);
		if (ret != 0)
		{
			printf("Error: fail to verify\n");
			ret = -9;
			break;
		}
	} while(0);

	// 7. Final, remove secret and release resources
	SAFE_FREE(signY, sizeof(signY));
	SAFE_FREE(signX, sizeof(signX));
	SAFE_FREE(regPublicKey, sizeof(regPublicKey));
	SAFE_FREE(regPrivateKey, sizeof(regPrivateKey));
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
