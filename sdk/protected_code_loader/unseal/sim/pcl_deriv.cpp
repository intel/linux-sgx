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

/* Content from sdk/simulation/tinst/deriv.cpp */

#include "t_instructions.h"    /* for `g_global_data_sim' */
#include "deriv.h"
#include <sgx_tseal.h>
#include <pcl_common.h>
#include <pcl_unseal_internal.h>

extern global_data_sim_t g_global_data_sim;

int pcl_cmac(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src,
    uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac);

// The built-in seal key in simulation mode
static const uint8_t PCL_BASE_SEAL_KEY[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t* pcl_get_base_key(uint16_t key_name)
{
    // Shouldn't use switch else requires relocation
/* PCL UNUSED START *
    switch (key_name) {
    case SGX_KEYSELECT_SEAL:
        return BASE_SEAL_KEY;
    case SGX_KEYSELECT_REPORT:
        return BASE_REPORT_KEY;
    case SGX_KEYSELECT_EINITTOKEN:
        return BASE_EINITTOKEN_KEY;
    case SGX_KEYSELECT_PROVISION:
        return BASE_PROVISION_KEY;
    case SGX_KEYSELECT_PROVISION_SEAL:
        return BASE_PROV_SEAL_KEY;
    }
/* PCL UNUSED END   */
    if (key_name == SGX_KEYSELECT_SEAL) return PCL_BASE_SEAL_KEY;    
	
    // Should not come here - error should have been reported
    // when the key name is not supported in the caller.
    return (uint8_t*)0;
}

// Compute the CMAC of derivation data with corresponding base key
// and save it to `okey'.
void pcl_derive_key(const derivation_data_t* dd, sgx_key_128bit_t okey)
{
    const uint8_t* base_key = pcl_get_base_key(dd->key_name);
    pcl_cmac((const sgx_cmac_128bit_key_t*)base_key,dd->ddbuf, dd->size, (sgx_cmac_128bit_tag_t*)okey);
}

