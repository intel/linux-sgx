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

/* Content from sdk/simulation/tinst/t_instructions.cpp */

#include "t_instructions.h"    /* for `g_global_data_sim' */
#include "deriv.h"
#include <sgx_tseal.h>
#include "pcl_common.h"
#include "pcl_internal.h"
#include "pcl_unseal_internal.h"

////////////////////////////////////////////////////////////////////////
// Simulation for EGETKEY
////////////////////////////////////////////////////////////////////////

// The hard-coded OwnerEpoch.
static const se_owner_epoch_t SIMU_OWNER_EPOCH_MSR = {
    0x54, 0x48, 0x49, 0x53, 0x49, 0x53, 0x4f, 0x57,
    0x4e, 0x45, 0x52, 0x45, 0x50, 0x4f, 0x43, 0x48,
};

static const sgx_cpu_svn_t PCL_DEFAULT_CPUSVN = {
    {
        0x48, 0x20, 0xf3, 0x37, 0x6a, 0xe6, 0xb2, 0xf2,
        0x03, 0x4d, 0x3b, 0x7a, 0x4b, 0x48, 0xa7, 0x78
    }
};

static const sgx_cpu_svn_t PCL_UPGRADED_CPUSVN = {
    {
        0x53, 0x39, 0xae, 0x8c, 0x93, 0xae, 0x8f, 0x3c,
        0xe4, 0x32, 0xdb, 0x92, 0x4d, 0x0f, 0x07, 0x33
    }
};

static const sgx_cpu_svn_t PCL_DOWNGRADED_CPUSVN = {
    {
        0x64, 0xea, 0x4f, 0x3f, 0xa0, 0x03, 0x0c, 0x36,
        0x38, 0x3c, 0x32, 0x2d, 0x4f, 0x3a, 0x8d, 0x4f
    }
};

egetkey_status_t pcl_check_cpu_svn(sgx_key_request_t* kr)
{
    if(!pcl_consttime_memequal(&kr->cpu_svn, (void*)&PCL_UPGRADED_CPUSVN, sizeof(PCL_UPGRADED_CPUSVN)) &&                        
       !pcl_consttime_memequal(&kr->cpu_svn, (void*)&PCL_DEFAULT_CPUSVN, sizeof(PCL_DEFAULT_CPUSVN)) &&                            
       !pcl_consttime_memequal(&kr->cpu_svn, (void*)&PCL_DOWNGRADED_CPUSVN, sizeof(PCL_DOWNGRADED_CPUSVN))){                        
        return EGETKEY_INVALID_CPUSVN;                                                          
    }                                                                                           
    if ( (pcl_consttime_memequal(&g_global_data_sim.cpusvn_sim, (void*)&PCL_DEFAULT_CPUSVN, sizeof(PCL_DEFAULT_CPUSVN)) &&     
          pcl_consttime_memequal(&kr->cpu_svn, (void*)&PCL_UPGRADED_CPUSVN, sizeof(PCL_UPGRADED_CPUSVN))) ||                         
         (pcl_consttime_memequal(&g_global_data_sim.cpusvn_sim, (void*)&PCL_DOWNGRADED_CPUSVN, sizeof(PCL_DOWNGRADED_CPUSVN)) &&    
           !pcl_consttime_memequal(&kr->cpu_svn, (void*)&PCL_DOWNGRADED_CPUSVN, sizeof(PCL_DOWNGRADED_CPUSVN)))){                       
        return EGETKEY_INVALID_CPUSVN;                                                          
    }        
    return EGETKEY_SUCCESS;                                                                                   
}


#define check_attr_flag(secs, flag) do {        \
    if ((secs->attributes.flags & flag) == 0) { \
        return EGETKEY_INVALID_ATTRIBUTE;       \
    }                                           \
} while(0)


// The hardware EGETKEY instruction will set ZF on failure.
//
// In simulation mode, we can not guarentee that the ZF is always set
// between _EGETKEY ending its life and tRTS testing ZF.  Since there
// are additional assembly code in between.
//
// In simulation mode, we check return code instead of ZF.
// c.f. do_egetkey() in trts/linux/trts_pic.S
#  define GP() return ((egetkey_status_t)-1)
#define GP_ON(cond) do { if (unlikely(cond)) GP(); } while (0)

egetkey_status_t pcl_check_isv_svn(sgx_key_request_t* kr, secs_t* secs) 
{
    if (kr->isv_svn > secs->isv_svn) {  
        return EGETKEY_INVALID_ISVSVN;  
    }    
    return EGETKEY_SUCCESS;
}

egetkey_status_t pcl_egetkey(sgx_key_request_t* kr, sgx_key_128bit_t okey)
{
    // check alignment of KEYREQUEST
    GP_ON(((size_t)kr & (KEY_REQUEST_ALIGN_SIZE - 1)) != 0);

    // check to see if KEYREQEUST is inside the current enclave
    ////GP_ON(!sgx_is_within_enclave(kr, sizeof(sgx_key_request_t)));

    // check alignment of OUTPUTDATA
    GP_ON(((size_t)okey & (KEY_ALIGN_SIZE - 1)) != 0);

    // check to see if OUTPUTDATA is inside the current enclave
    ////GP_ON(!sgx_is_within_enclave(okey, sizeof(sgx_key_128bit_t)));

    // check reserved bits are not set
    GP_ON((kr->key_policy & ~(SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)) != 0);

    // check to see if reserved space in KEYREQUEST are valid
    const uint8_t* u8ptr = (uint8_t *)(&(kr->reserved1));
    for (unsigned i = 0; i < sizeof(kr->reserved1); ++i)
        GP_ON(u8ptr[i] != (uint8_t)0);

    u8ptr = (uint8_t *)(&(kr->reserved2));
    for (unsigned i = 0; i < sizeof(kr->reserved2); ++i)
        GP_ON(u8ptr[i] != (uint8_t)0);

    secs_t*             cur_secs = g_global_data_sim.secs_ptr;
    sgx_attributes_t    tmp_attr;
    derivation_data_t   dd;

    pcl_memset(&dd, 0, sizeof(dd));
    dd.key_name = kr->key_name;

    // Determine which enclave attributes that must be included in the key.
    // Attributes that must always be included INIT & DEBUG.
    pcl_memset(&tmp_attr, 0, sizeof(tmp_attr));
    tmp_attr.flags = kr->attribute_mask.flags | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    tmp_attr.flags &= cur_secs->attributes.flags;
    tmp_attr.xfrm = kr->attribute_mask.xfrm & cur_secs->attributes.xfrm;
    // HW supports CPUSVN to be set as 0. 
    // To be consistent with HW behaviour, we replace the cpusvn as DEFAULT_CPUSVN if the input cpusvn is 0.
    if(pcl_consttime_memequal(&kr->cpu_svn, &dd.ddpk.cpu_svn, sizeof(sgx_cpu_svn_t)))
    {
        pcl_memcpy(&kr->cpu_svn, (void*)&DEFAULT_CPUSVN, sizeof(sgx_cpu_svn_t));
    }

    // Must not use swich else relocations
    /* PCL UNUSED START *
    switch (kr->key_name) {
    case SGX_KEYSELECT_SEAL:
    /* PCL UNUSED END   */
        egetkey_status_t esa = pcl_check_isv_svn(kr, cur_secs);
        if(EGETKEY_SUCCESS != esa)return esa;
        esa = pcl_check_cpu_svn(kr);
        if(EGETKEY_SUCCESS != esa)return esa;
        // assemble derivation data
        dd.size = sizeof(dd_seal_key_t);
        if (kr->key_policy & SGX_KEYPOLICY_MRENCLAVE) {
            pcl_memcpy(&dd.ddsk.mrenclave, &cur_secs->mr_enclave, sizeof(sgx_measurement_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_MRSIGNER) {
            pcl_memcpy(&dd.ddsk.mrsigner, (void*)&cur_secs->mr_signer, sizeof(sgx_measurement_t));
        }

        pcl_memcpy(&dd.ddsk.tmp_attr, &tmp_attr, sizeof(sgx_attributes_t));
        pcl_memcpy(&dd.ddsk.attribute_mask, &kr->attribute_mask, sizeof(sgx_attributes_t));
        pcl_memcpy(dd.ddsk.csr_owner_epoch, (void*)SIMU_OWNER_EPOCH_MSR, sizeof(se_owner_epoch_t));
        pcl_memcpy(&dd.ddsk.cpu_svn,&kr->cpu_svn,sizeof(sgx_cpu_svn_t));
        dd.ddsk.isv_svn = kr->isv_svn;
        dd.ddsk.isv_prod_id = cur_secs->isv_prod_id;
        pcl_memcpy(&dd.ddsk.key_id, &kr->key_id, sizeof(sgx_key_id_t));


/* PCL UNUSED START *
    default:
        return EGETKEY_INVALID_KEYNAME;
    }
/* PCL UNUSED END   */
    pcl_derive_key(&dd, okey);
    return EGETKEY_SUCCESS;
}
