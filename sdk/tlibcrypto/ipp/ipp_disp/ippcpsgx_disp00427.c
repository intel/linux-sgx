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


IPPAPI(IppStatus, y8_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))
IPPAPI(IppStatus, l9_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))

IPPFUN(IppStatus,sgx_disp_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))
{
  Ipp64u features;
  ippcpGetCpuFeatures( &features );

      if( ippCPUID_AVX2  == ( features & ippCPUID_AVX2  )) { /* HasweLl ia32=H9, x64=L9 */
        return l9_ippsGFpAdd_PE( pA, pParentB, pR, pGFp );
      } else 
      if( ippCPUID_SSE42 == ( features & ippCPUID_SSE42 )) { /* Nehalem or Westmer = PenrYn + SSE42 + ?CLMUL + ?AES + ?SHA */
        return y8_ippsGFpAdd_PE( pA, pParentB, pR, pGFp );
      } else 
        return ippStsCpuNotSupportedErr;
}
#else


IPPAPI(IppStatus, p8_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))
IPPAPI(IppStatus, h9_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))

IPPFUN(IppStatus,sgx_disp_ippsGFpAdd_PE,(const IppsGFpElement* pA, const IppsGFpElement* pParentB, IppsGFpElement* pR, IppsGFpState* pGFp))
{
  Ipp64u features;
  ippcpGetCpuFeatures( &features );

      if( ippCPUID_AVX2  == ( features & ippCPUID_AVX2  )) { /* HasweLl ia32=H9, x64=L9 */
        return h9_ippsGFpAdd_PE( pA, pParentB, pR, pGFp );
      } else 
      if( ippCPUID_SSE42 == ( features & ippCPUID_SSE42 )) { /* Nehalem or Westmer = PenrYn + SSE42 + ?CLMUL + ?AES + ?SHA */
        return p8_ippsGFpAdd_PE( pA, pParentB, pR, pGFp );
      } else 
        return ippStsCpuNotSupportedErr;
}
#endif
