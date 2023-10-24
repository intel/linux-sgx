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
#include <sgx_trts_exception.h>
#include <sgx_trts_aex.h>
#include <sgx_trts.h>

#include "powers_of_two.h"

void count_powers_of_two(uint64_t low, uint64_t high, uint32_t* count)
{
   if(!count) return;
   const uint32_t local_count = count_powers_of_two(low,high);
   *count = local_count;
}

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

uint64_t g_aex_count = 0;

static void my_aex_notify_handler(const sgx_exception_info_t *info, const void * args)
{
   // This sample will not perform any additional mitigations beyond what the trts
   // does. It will do some simple counting.
   (void)info;
   (void)args;
   g_aex_count++;
}

//  Count the number of powers of two between [low, high].
//  Also count the number of times our AEX-Notify handler was called.
//  If the function runs long enough, normal OS preemptive multitasking 
//  should generate an AEX. 
//  You can use additional threads and thread affinity to change the OS
//  behavior and induce more async enclave exits as needed.
void count_powers_of_two_with_aex(uint64_t low, uint64_t high, uint32_t* count, uint64_t* aex_count)
{
    if(!count) return;
    if(!aex_count) return;

    g_aex_count = 0;
   
    const char* args = NULL; 
    sgx_aex_mitigation_node_t node;
    
    sgx_register_aex_handler(&node, my_aex_notify_handler, (const void*)args);

   const uint32_t local_count = count_powers_of_two(low,high);
   *count = local_count;

   sgx_unregister_aex_handler(my_aex_notify_handler);
   
   *aex_count = g_aex_count;
}


