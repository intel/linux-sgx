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

#include "ippcp.h"

#ifndef IPP_CALL
#define IPP_CALL IPP_STDCALL
#endif
#define IPPFUN(type,name,arg) extern type IPP_CALL name arg

#ifndef NULL
#ifdef  __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#if defined (_M_AMD64) || defined (__x86_64__)

#define AVX3I_FEATURES ( ippCPUID_SHA|ippCPUID_AVX512VBMI|ippCPUID_AVX512VBMI2|ippCPUID_AVX512IFMA|ippCPUID_AVX512GFNI|ippCPUID_AVX512VAES|ippCPUID_AVX512VCLMUL )
#define AVX3X_FEATURES ( ippCPUID_AVX512F|ippCPUID_AVX512CD|ippCPUID_AVX512VL|ippCPUID_AVX512BW|ippCPUID_AVX512DQ )
#define AVX3M_FEATURES ( ippCPUID_AVX512F|ippCPUID_AVX512CD|ippCPUID_AVX512PF|ippCPUID_AVX512ER )

#ifdef __cplusplus
extern "C" {
#endif

IPPAPI(IppStatus, k1_ippsLMSPublicKeyStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))
IPPAPI(IppStatus, l9_ippsLMSPublicKeyStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))
IPPAPI(IppStatus, y8_ippsLMSPublicKeyStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))

IPPFUN(IppStatus, sgx_disp_ippsLMSPublicKeyStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))
{
    Ipp64u _features;
    _features = ippcpGetEnabledCpuFeatures();

    if( AVX3I_FEATURES  == ( _features & AVX3I_FEATURES  )) {
        return k1_ippsLMSPublicKeyStateGetSize( pSize, lmsType );
    } else 
    if( ippCPUID_AVX2  == ( _features & ippCPUID_AVX2  )) {
        return l9_ippsLMSPublicKeyStateGetSize( pSize, lmsType );
    } else 
    if( ippCPUID_SSE42  == ( _features & ippCPUID_SSE42  )) {
        return y8_ippsLMSPublicKeyStateGetSize( pSize, lmsType );
    } else 
        return ippStsCpuNotSupportedErr;
}

#ifdef __cplusplus
}
#endif

#endif
