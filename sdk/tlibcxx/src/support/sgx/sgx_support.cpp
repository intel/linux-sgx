#include <support/sgx/__sgx_support>

/* NOTE: Reason for the <__sgx_support> header and sgx_support.cpp file is: 
    The declarations of intrinsecs below was copy-pasted from tlibc's malloc.c source. PRC team recommended
    to keep these decl inside sources so we would not confuse customers to be tempted to use them. They are
    for internal usage only. Because we want to keep them hidden in a source file we had to move definition
    of the _builtin_ctz family functions in the same source file so we had to also remove the implicit
    __force_inline attribute. Except of this change the bodies of these functions have not been changed
*/

#if defined(_LIBCPP_MSVC)

/* Declarations for bit scanning on win32 */
#if defined(_MSC_VER) && _MSC_VER>=1400
#ifndef BitScanForward /* Try to avoid pulling in WinNT.h */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    unsigned char _BitScanForward(unsigned long *index, unsigned long mask);
    unsigned char _BitScanReverse(unsigned long *index, unsigned long mask);
    unsigned char _BitScanForward64(unsigned long *index, unsigned long long mask);
    unsigned char _BitScanReverse64(unsigned long *index, unsigned long long mask);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#define BitScanForward64 _BitScanForward64
#define BitScanReverse64 _BitScanReverse64
#ifndef __ICL
#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward64)
#pragma intrinsic(_BitScanReverse64)
#endif /* __ICL */
#endif /* BitScanForward */
#endif /* defined(_MSC_VER) && _MSC_VER>=1300 */


// Returns the number of trailing 0-bits in x, starting at the least significant
// bit position. If x is 0, the result is undefined.
int __builtin_ctzll(unsigned long long mask)
{
  unsigned long where;
  // Search from LSB to MSB for first set bit.
  // Returns zero if no set bit is found.
#if defined(_WIN64)
  if (_BitScanForward64(&where, mask))
    return static_cast<int>(where);
#elif defined(_WIN32)
  // Win32 doesn't have _BitScanForward64 so emulate it with two 32 bit calls.
  // Scan the Low Word.
  if (_BitScanForward(&where, static_cast<unsigned long>(mask)))
    return static_cast<int>(where);
  // Scan the High Word.
  if (_BitScanForward(&where, static_cast<unsigned long>(mask >> 32)))
    return static_cast<int>(where + 32); // Create a bit offset from the LSB.
#else
#error "Implementation of __builtin_ctzll required"
#endif
  return 64;
}

int __builtin_ctzl(unsigned long mask)
{
  unsigned long where;
  // Search from LSB to MSB for first set bit.
  // Returns zero if no set bit is found.
  if (_BitScanForward(&where, mask))
    return static_cast<int>(where);
  return 32;
}

int __builtin_ctz(unsigned int mask)
{
  // Win32 and Win64 expectations.
  static_assert(sizeof(mask) == 4, "");
  static_assert(sizeof(unsigned long) == 4, "");
  return __builtin_ctzl(static_cast<unsigned long>(mask));
}

// Returns the number of leading 0-bits in x, starting at the most significant
// bit position. If x is 0, the result is undefined.
int __builtin_clzll(unsigned long long mask)
{
  unsigned long where;
  // BitScanReverse scans from MSB to LSB for first set bit.
  // Returns 0 if no set bit is found.
#if defined(_WIN64)
  if (_BitScanReverse64(&where, mask))
    return static_cast<int>(63 - where);
#elif defined(_WIN32)
  // Scan the high 32 bits.
  if (_BitScanReverse(&where, static_cast<unsigned long>(mask >> 32)))
    return static_cast<int>(63 -
      (where + 32)); // Create a bit offset from the MSB.
                     // Scan the low 32 bits.
  if (_BitScanReverse(&where, static_cast<unsigned long>(mask)))
    return static_cast<int>(63 - where);
#else
#error "Implementation of __builtin_clzll required"
#endif
  return 64; // Undefined Behavior.
}

int __builtin_clzl(unsigned long mask)
{
  unsigned long where;
  // Search from MSB to LSB for first set bit.
  // Returns zero if no set bit is found.
  if (_BitScanReverse(&where, mask))
    return static_cast<int>(31 - where);
  return 32; // Undefined Behavior.
}

int __builtin_clz(unsigned int mask)
{
  // Win32 and Win64 expectations.
  static_assert(sizeof(mask) == 4, "");
  static_assert(sizeof(unsigned long) == 4, "");
  return __builtin_clzl(static_cast<unsigned long>(mask));
}

#endif  // defined(_LIBCPP_MSVC)
