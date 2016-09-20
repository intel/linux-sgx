/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
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


#include "arch.h"
#include "xsave.h"
#include "trts_inst.h"
#include "util.h"
#include "se_cpu_feature_defs.h"

// 'SYNTHETIC_STATE' buffer size is (512 + 64 + 256) bytes
//   512 for fxsave buffer,
//   64 for xsave header,
//   256 for YMM State (16 * 16 bytes of each YMMH-register)
// and the buffer should be 64 byte aligned.
#define SYNTHETIC_STATE_SIZE   (512 + 64 + 256)

se_static_assert(SYNTHETIC_STATE_SIZE <= SE_PAGE_SIZE);

static SE_DECLSPEC_ALIGN(4096) const uint16_t
SYNTHETIC_STATE[SYNTHETIC_STATE_SIZE/sizeof(uint16_t)] = {
    0x037F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1F80, 0, 0xFFFF, 0
};

static int g_xsave_enabled;             // flag to indicate whether xsave is enabled or not

// init_xfeature_state()
//      init g_xsave_enabled based on secs.attr.xfrm.  EENTER will set xcr0 with secs.attr.xfrm,
// Parameters:
//      xfrm - secs.attr.xfrm value
// Return Value:
//      none
void init_xfeature_state(uint64_t xfrm)
{
    g_xsave_enabled = XFEATURE_ENABLED_AVX(xfrm) ? 1 : 0;
}

// save_and_clean_xfeature_regs()
//      do fwait, fxsave, and then clean the extended feature registers
// Parameters:
//      buffer - If the pointer is not NULL, save the CPU state to the memory
// Return Value:
//      none
void save_and_clean_xfeature_regs(uint8_t *buffer)
{
    do_fwait();

    if(buffer != 0)
    {
        uint8_t *buf = (uint8_t*)ROUND_TO((size_t)buffer, FXSAVE_ALIGN_SIZE);
        do_fxsave(buf);
    }

    if(g_xsave_enabled)
    {
        do_xrstor(SYNTHETIC_STATE);
    }
    else
    {
        do_fxrstor(SYNTHETIC_STATE);
    }
}
// restore_xfeature_regs()
//      restore the extended feature registers
//
void restore_xfeature_regs(const uint8_t *buffer)
{
    if(buffer != 0)
    {
        uint8_t *buf = (uint8_t*)ROUND_TO((size_t)buffer, FXSAVE_ALIGN_SIZE);
        do_fxrstor(buf);
    }
}
