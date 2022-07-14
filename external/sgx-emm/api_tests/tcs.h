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

#ifndef TCS_H_
#define TCS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _tcs_t
{
    uint64_t            reserved0;       /* (0) */
    uint64_t            flags;           /* (8)bit 0: DBGOPTION */
    uint64_t            ossa;            /* (16)State Save Area */
    uint32_t            cssa;            /* (24)Current SSA slot */
    uint32_t            nssa;            /* (28)Number of SSA slots */
    uint64_t            oentry;          /* (32)Offset in enclave to which control is transferred on EENTER if enclave INACTIVE state */
    uint64_t            reserved1;       /* (40) */
    uint64_t            ofs_base;        /* (48)When added to the base address of the enclave, produces the base address FS segment inside the enclave */
    uint64_t            ogs_base;        /* (56)When added to the base address of the enclave, produces the base address GS segment inside the enclave */
    uint32_t            ofs_limit;       /* (64)Size to become the new FS limit in 32-bit mode */
    uint32_t            ogs_limit;       /* (68)Size to become the new GS limit in 32-bit mode */
#define TCS_RESERVED_LENGTH 4024
    uint8_t             reserved[TCS_RESERVED_LENGTH];  /* (72) */
}tcs_t;

#ifdef __cplusplus
}
#endif


#endif
