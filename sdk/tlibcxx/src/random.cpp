//===-------------------------- random.cpp --------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <__config>

#if defined(_LIBCPP_USING_WIN32_RANDOM)
// Must be defined before including stdlib.h to enable rand_s().
#define _CRT_RAND_S
#endif // defined(_LIBCPP_USING_WIN32_RANDOM)

#include "random"
#include "system_error"

#if defined(__sun__)
#define rename solaris_headers_are_broken
#endif // defined(__sun__)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sgx_trts.h>

_LIBCPP_BEGIN_NAMESPACE_STD

random_device::random_device(const string& __token)
{
    (void)__token;
}

random_device::~random_device()
{
}

unsigned
random_device::operator()()
{
    unsigned result;
    
    sgx_read_rand(reinterpret_cast<unsigned char*>(&result), sizeof(result));
    return result;
}

double
random_device::entropy() const _NOEXCEPT
{
    return 0;
}

_LIBCPP_END_NAMESPACE_STD
