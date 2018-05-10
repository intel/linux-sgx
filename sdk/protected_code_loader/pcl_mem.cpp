/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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
 
#include <stdint.h>
#include <stdlib.h>
#include <global_data.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <pcl_common.h>
#include <pcl_internal.h>

/*
 * @func pcl_memcpy implements memcpy that can run before runtime initiazliation
 * @param OUT void* dst, output destination buffer
 * @param IN void* src, input source buffer
 * @param size_t size, buffer size in bytes
 */
void pcl_memcpy(OUT void* dst, IN void* src, size_t size)
{
    if(NULL == dst || NULL == src)abort();
    for(size_t i=0;i<size;i++)
    {
        CASTU8P(dst)[i]=CASTU8P(src)[i];
    }
}

/*
 * @func pcl_memset implements memset that can run before runtime initiazliation
 * @param OUT void* dst, output destination buffer
 * @param uint8_t val, value to set buffer
 * @param size_t size, buffer size in bytes
 */
void pcl_memset(OUT void* dst, uint8_t val, size_t size)
{
    if(NULL == dst)abort();
    for(size_t i=0;i<size;i++)
    {
        CASTU8P(dst)[i]=val;
    }
}


/*
 * @func pcl_volatile_memset implements memset that will not be optimized by compiler
 * and can run before runtime initiazliation 
 * @param OUT volatile void* dst, output volatile destination buffer
 * @param uint8_t val, value to set buffer
 * @param size_t size, buffer size in bytes
 */
void pcl_volatile_memset(OUT volatile void* dst, uint8_t val, size_t size)
{
    if(NULL == dst)abort();
    for(size_t i=0;i<size;i++)
    {
        CAST_VOLATILE_U8P(dst)[i]=val;
    }
}

/* 
 * @func pcl_consttime_memequal compares two buffers content in constant time
 * Code is taken from consttime_memequal. C runtime is unavailable during PCL execution
 * @par IN const void *b1 - pointer to buffer 1
 * @par IN const void *b2 - pointer to buffer 2
 * @par size_t len - number of bytes to compare
 * @return uint32_t
 * 0 - if no match
 * 1 - if match
 */
uint32_t pcl_consttime_memequal(IN const void *b1, IN const void *b2, size_t len) 
{
    if(NULL == b1 || NULL == b2)abort();
    const unsigned char *c1 = (const unsigned char *)b1, *c2 = (const unsigned char *)b2;
    uint32_t res = 0;

    while (len--)
        res |= *c1++ ^ *c2++;

    /*
    * Map 0 to 1 and [1, 256) to 0 using only constant-time
    * arithmetic.
    *
    * This is not simply `!res' because although many CPUs support
    * branchless conditional moves and many compilers will take
    * advantage of them, certain compilers generate branches on
    * certain CPUs for `!res'.
    */
    return (1 & ((res - 1) >> 8));
}

/* 
 * g_pcl_imagebase is set by PCL at runtime to ELF base address. 
 * It is used by functions pcl_is_outside_enclave and pcl_is_within_enclave
 */
extern uintptr_t g_pcl_imagebase;

/* 
 * @func pcl_is_outside_enclave checks if buffer is completely outside the enclave
 * @par IN const void* addr - the start address of the buffer
 * @par size_t size - buffer size in bytes
 * @return int
 * 1 - the buffer is strictly outside the enclave
 * 0 - the whole buffer or part of the buffer is not outside the enclave,
 *     or the buffer is wrap around
 */
int pcl_is_outside_enclave(IN const void *addr, size_t size)
{
    size_t start = (size_t)addr;
    size_t end = 0;
    size_t enclave_start = (size_t)g_pcl_imagebase;
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    {
        end = start + size - 1;
    }
    else
    {
        end = start;
    }
	
    if( (start <= end) && ((end < enclave_start) || (start > enclave_end)) )
    {
        return 1;
    }
    return 0;
}

/* 
 * @func pcl_is_outside_enclave checks if buffer is completely inside the enclave
 * @par IN const void* addr - the start address of the buffer
 * @par size_t size - buffer size in bytes
 * @return int
 * 1 - the buffer is strictly within the enclave
 * 0 - the whole buffer or part of the buffer is not within the enclave,
 *     or the buffer is wrap around
 */
int pcl_is_within_enclave(const void *addr, size_t size)
{
    size_t start = (size_t)addr;
    size_t end = 0;
    size_t enclave_start = (size_t)g_pcl_imagebase;
    size_t enclave_end = enclave_start + g_global_data.enclave_size - 1;
    // g_global_data.enclave_end = enclave_base + enclave_size - 1;
    // so the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    {
        end = start + size - 1;
    }
    else
    {
        end = start;
    }
    if( (start <= end) && (start >= enclave_start) && (end <= enclave_end) )
    {
        return 1;
    }
    return 0;
}

