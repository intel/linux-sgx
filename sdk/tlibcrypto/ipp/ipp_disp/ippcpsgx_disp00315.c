#include "ippcp.h"

#define IPPFUN(type,name,arg) extern type IPP_STDCALL name arg

#ifndef NULL
#ifdef  __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#if defined (_M_AMD64) || defined (__x86_64__)

#define AVX3X_FEATURES ( ippCPUID_AVX512F|ippCPUID_AVX512CD|ippCPUID_AVX512VL|ippCPUID_AVX512BW|ippCPUID_AVX512DQ )
#define AVX3M_FEATURES ( ippCPUID_AVX512F|ippCPUID_AVX512CD|ippCPUID_AVX512PF|ippCPUID_AVX512ER )


IPPAPI(IppStatus, y8_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))
IPPAPI(IppStatus, l9_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))

IPPFUN(IppStatus,sgx_disp_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))
{
  Ipp64u features;
  ippcpGetCpuFeatures( &features );

      if( ippCPUID_AVX2  == ( features & ippCPUID_AVX2  )) { /* HasweLl ia32=H9, x64=L9 */
        return l9_ippsDLPSharedSecretDH( pPrvKeyA, pPubKeyB, pShare, pCtx );
      } else 
      if( ippCPUID_SSE42 == ( features & ippCPUID_SSE42 )) { /* Nehalem or Westmer = PenrYn + SSE42 + ?CLMUL + ?AES + ?SHA */
        return y8_ippsDLPSharedSecretDH( pPrvKeyA, pPubKeyB, pShare, pCtx );
      } else 
        return ippStsCpuNotSupportedErr;
}
#else


IPPAPI(IppStatus, p8_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))
IPPAPI(IppStatus, h9_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))

IPPFUN(IppStatus,sgx_disp_ippsDLPSharedSecretDH,(const IppsBigNumState* pPrvKeyA, const IppsBigNumState* pPubKeyB, IppsBigNumState* pShare, IppsDLPState* pCtx))
{
  Ipp64u features;
  ippcpGetCpuFeatures( &features );

      if( ippCPUID_AVX2  == ( features & ippCPUID_AVX2  )) { /* HasweLl ia32=H9, x64=L9 */
        return h9_ippsDLPSharedSecretDH( pPrvKeyA, pPubKeyB, pShare, pCtx );
      } else 
      if( ippCPUID_SSE42 == ( features & ippCPUID_SSE42 )) { /* Nehalem or Westmer = PenrYn + SSE42 + ?CLMUL + ?AES + ?SHA */
        return p8_ippsDLPSharedSecretDH( pPrvKeyA, pPubKeyB, pShare, pCtx );
      } else 
        return ippStsCpuNotSupportedErr;
}
#endif
