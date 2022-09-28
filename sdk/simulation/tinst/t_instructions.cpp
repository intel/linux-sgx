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


// t_instructions.cpp -- It simulates Enclave instructions.
#include <string.h>
#include <stdlib.h>

#include "arch.h"
#include "util.h"
#include "lowlib.h"
#include "sgx_trts.h"
#include "trts_inst.h"

#include "deriv.h"
#include "t_instructions.h"
#include "td_mngr.h"

////////////////////////////////////////////////////////////////////////
global_data_sim_t g_global_data_sim = {NULL, {{0}}, 0};

#define GP() abort()
#define GP_ON(cond) do { if (unlikely(cond)) GP(); } while (0)

////////////////////////////////////////////////////////////////////////
// Simulation for EGETKEY
////////////////////////////////////////////////////////////////////////

// The hard-coded OwnerEpoch.
static const se_owner_epoch_t SIMU_OWNER_EPOCH_MSR = {
    0x54, 0x48, 0x49, 0x53, 0x49, 0x53, 0x4f, 0x57,
    0x4e, 0x45, 0x52, 0x45, 0x50, 0x4f, 0x43, 0x48,
};


#define check_cpu_svn(kr) do {                                                                  \
    if(memcmp(&kr->cpu_svn, &UPGRADED_CPUSVN, sizeof(UPGRADED_CPUSVN)) &&                        \
    memcmp(&kr->cpu_svn, &DEFAULT_CPUSVN, sizeof(DEFAULT_CPUSVN)) &&                            \
    memcmp(&kr->cpu_svn, &DOWNGRADED_CPUSVN, sizeof(DOWNGRADED_CPUSVN))){                        \
        return EGETKEY_INVALID_CPUSVN;                                                          \
    }                                                                                           \
    if ( (!memcmp(&g_global_data_sim.cpusvn_sim, &DEFAULT_CPUSVN, sizeof(DEFAULT_CPUSVN)) &&     \
    !memcmp(&kr->cpu_svn, &UPGRADED_CPUSVN, sizeof(UPGRADED_CPUSVN))) ||                         \
    (!memcmp(&g_global_data_sim.cpusvn_sim, &DOWNGRADED_CPUSVN, sizeof(DOWNGRADED_CPUSVN)) &&    \
    memcmp(&kr->cpu_svn, &DOWNGRADED_CPUSVN, sizeof(DOWNGRADED_CPUSVN)))){                       \
        return EGETKEY_INVALID_CPUSVN;                                                          \
    }                                                                                           \
    } while(0)

#define check_isv_svn(kr, secs) do {    \
    if (kr->isv_svn > secs->isv_svn) {  \
        return EGETKEY_INVALID_ISVSVN;  \
    }                                   \
} while(0)

#define check_attr_flag(secs, flag) do {        \
    if ((secs->attributes.flags & flag) == 0) { \
        return EGETKEY_INVALID_ATTRIBUTE;       \
    }                                           \
} while(0)

#define check_config_svn(kr, secs) do {    \
    if (kr->config_svn > secs->config_svn) {  \
        return EGETKEY_INVALID_ISVSVN;  \
    }                                   \
} while(0)

#define KEY_POLICY_KSS (SGX_KEYPOLICY_CONFIGID | SGX_KEYPOLICY_ISVFAMILYID | SGX_KEYPOLICY_ISVEXTPRODID)

// The hardware EGETKEY instruction will set ZF on failure.
//
// In simulation mode, we can not guarentee that the ZF is always set
// between _EGETKEY ending its life and tRTS testing ZF.  Since there
// are additional assembly code in between.
//
// In simulation mode, we check return code instead of ZF.
// c.f. do_egetkey() in trts/linux/trts_pic.S

static int _EGETKEY(sgx_key_request_t* kr, sgx_key_128bit_t okey)
{
    // check alignment of KEYREQUEST
    GP_ON(((size_t)kr & (KEY_REQUEST_ALIGN_SIZE - 1)) != 0);

    // check to see if KEYREQEUST is inside the current enclave
    GP_ON(!sgx_is_within_enclave(kr, sizeof(sgx_key_request_t)));

    // check alignment of OUTPUTDATA
    GP_ON(((size_t)okey & (KEY_ALIGN_SIZE - 1)) != 0);

    // check to see if OUTPUTDATA is inside the current enclave
    GP_ON(!sgx_is_within_enclave(okey, sizeof(sgx_key_128bit_t)));

    // check reserved bits are not set
    GP_ON((kr->key_policy & ~(SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER | KEY_POLICY_KSS | SGX_KEYPOLICY_NOISVPRODID)) != 0);

    // check to see if reserved space in KEYREQUEST are valid
    const uint8_t* u8ptr = (uint8_t *)(&(kr->reserved1));
    for (unsigned i = 0; i < sizeof(kr->reserved1); ++i)
        GP_ON(u8ptr[i] != (uint8_t)0);

    u8ptr = (uint8_t *)(&(kr->reserved2));
    for (unsigned i = 0; i < sizeof(kr->reserved2); ++i)
        GP_ON(u8ptr[i] != (uint8_t)0);

    secs_t*             cur_secs = g_global_data_sim.secs_ptr;
    isv_ext_id_t*       isv_ext_id = reinterpret_cast<isv_ext_id_t *>(cur_secs->reserved4);

    GP_ON(!(cur_secs->attributes.flags & SGX_FLAGS_KSS) &&
        ((kr->key_policy & (KEY_POLICY_KSS | SGX_KEYPOLICY_NOISVPRODID)) ||kr->config_svn > 0));

    sgx_attributes_t    tmp_attr;
    sgx_misc_select_t   tmp_misc;
    derivation_data_t   dd;

    memset(&dd, 0, sizeof(dd));
    dd.key_name = kr->key_name;

    // Determine which enclave attributes that must be included in the key.
    // Attributes that must always be included INIT & DEBUG.
    memset(&tmp_attr, 0, sizeof(tmp_attr));
    tmp_attr.flags = kr->attribute_mask.flags | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    tmp_attr.flags &= cur_secs->attributes.flags;
    tmp_attr.xfrm = kr->attribute_mask.xfrm & cur_secs->attributes.xfrm;
    // Compute MISCSELECT fields to be included in the key.
    tmp_misc = kr->misc_mask & cur_secs->misc_select;
    // HW supports CPUSVN to be set as 0. 
    // To be consistent with HW behaviour, we replace the cpusvn as DEFAULT_CPUSVN if the input cpusvn is 0.
    if(!memcmp(&kr->cpu_svn, &dd.ddpk.cpu_svn, sizeof(sgx_cpu_svn_t)))
    {
        memcpy(&kr->cpu_svn, &DEFAULT_CPUSVN, sizeof(sgx_cpu_svn_t));
    }

    switch (kr->key_name) {
    case SGX_KEYSELECT_SEAL:
        check_isv_svn(kr, cur_secs);
        check_config_svn(kr, cur_secs);
        check_cpu_svn(kr);

        // assemble derivation data
        dd.size = sizeof(dd_seal_key_t);
        dd.ddsk.key_policy = kr->key_policy;
        if (kr->key_policy & SGX_KEYPOLICY_MRENCLAVE) {
            memcpy(&dd.ddsk.mrenclave, &cur_secs->mr_enclave, sizeof(sgx_measurement_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_MRSIGNER) {
            memcpy(&dd.ddsk.mrsigner, &cur_secs->mr_signer, sizeof(sgx_measurement_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_ISVFAMILYID) {
            memcpy(&dd.ddsk.isv_family_id, &isv_ext_id->isv_family_id, sizeof(sgx_isvfamily_id_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_ISVEXTPRODID) {
            memcpy(&dd.ddsk.isv_ext_prod_id, &isv_ext_id->isv_ext_prod_id, sizeof(sgx_isvext_prod_id_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_CONFIGID) {
            dd.ddsk.config_svn = kr->config_svn;
            memcpy(&dd.ddsk.config_id, &cur_secs->config_id, sizeof(sgx_config_id_t));
        }

        memcpy(&dd.ddsk.tmp_attr, &tmp_attr, sizeof(sgx_attributes_t));
        memcpy(&dd.ddsk.attribute_mask, &kr->attribute_mask, sizeof(sgx_attributes_t));
        dd.ddsk.tmp_misc = tmp_misc;
        dd.ddsk.misc_mask = ~kr->misc_mask;
        memcpy(dd.ddsk.csr_owner_epoch, SIMU_OWNER_EPOCH_MSR, sizeof(se_owner_epoch_t));
        memcpy(&dd.ddsk.cpu_svn,&kr->cpu_svn,sizeof(sgx_cpu_svn_t));
        dd.ddsk.isv_svn = kr->isv_svn;
        if (!(kr->key_policy & SGX_KEYPOLICY_NOISVPRODID)) {
             dd.ddsk.isv_prod_id = cur_secs->isv_prod_id;
        }
        memcpy(&dd.ddsk.key_id, &kr->key_id, sizeof(sgx_key_id_t));
        break;

    case SGX_KEYSELECT_REPORT:
        // assemble derivation data
        dd.size = sizeof(dd_report_key_t);
        memcpy(&dd.ddrk.attributes, &cur_secs->attributes, sizeof(sgx_attributes_t));
        dd.ddrk.misc_select = cur_secs->misc_select;
        memcpy(dd.ddrk.csr_owner_epoch, SIMU_OWNER_EPOCH_MSR, sizeof(se_owner_epoch_t));
        memcpy(&dd.ddrk.cpu_svn,&(g_global_data_sim.cpusvn_sim),sizeof(sgx_cpu_svn_t));
        memcpy(&dd.ddrk.mrenclave, &cur_secs->mr_enclave, sizeof(sgx_measurement_t));
        dd.ddrk.config_svn = cur_secs->config_svn;
        memcpy(&dd.ddrk.config_id, &cur_secs->config_id, sizeof(sgx_config_id_t));
        memcpy(&dd.ddrk.key_id, &kr->key_id, sizeof(sgx_key_id_t));
        break;

    case SGX_KEYSELECT_EINITTOKEN:
        check_attr_flag(cur_secs, SGX_FLAGS_EINITTOKEN_KEY);
        check_isv_svn(kr, cur_secs);
        check_cpu_svn(kr);

        // assemble derivation data
        dd.size = sizeof(dd_license_key_t);
        memcpy(&dd.ddlk.tmp_attr, &tmp_attr, sizeof(sgx_attributes_t));
        dd.ddlk.tmp_misc = tmp_misc;
        memcpy(dd.ddlk.csr_owner_epoch, SIMU_OWNER_EPOCH_MSR, sizeof(se_owner_epoch_t));
        memcpy(&dd.ddlk.cpu_svn,&kr->cpu_svn,sizeof(sgx_cpu_svn_t));
        dd.ddlk.isv_svn = kr->isv_svn;
        dd.ddlk.isv_prod_id = cur_secs->isv_prod_id;
        memcpy(&dd.ddlk.mrsigner, &cur_secs->mr_signer, sizeof(sgx_measurement_t));
        memcpy(&dd.ddlk.key_id, &kr->key_id, sizeof(sgx_key_id_t));
        break;

    case SGX_KEYSELECT_PROVISION:
        check_attr_flag(cur_secs, SGX_FLAGS_PROVISION_KEY);
        check_isv_svn(kr, cur_secs);
        check_cpu_svn(kr);

        // assemble derivation data
        dd.size = sizeof(dd_provision_key_t);
        memcpy(&dd.ddpk.tmp_attr, &tmp_attr, sizeof(sgx_attributes_t));
        memcpy(&dd.ddpk.attribute_mask, &kr->attribute_mask, sizeof(sgx_attributes_t));
        dd.ddpk.tmp_misc = tmp_misc;
        dd.ddpk.misc_mask = ~kr->misc_mask;
        memcpy(&dd.ddpk.cpu_svn,&kr->cpu_svn,sizeof(sgx_cpu_svn_t));
        dd.ddpk.isv_svn = kr->isv_svn;
        dd.ddpk.isv_prod_id = cur_secs->isv_prod_id;
        memcpy(&dd.ddpk.mrsigner, &cur_secs->mr_signer, sizeof(sgx_measurement_t));
        break;
    case SGX_KEYSELECT_PROVISION_SEAL:
        check_attr_flag(cur_secs, SGX_FLAGS_PROVISION_KEY);
        check_isv_svn(kr, cur_secs);
        check_config_svn(kr, cur_secs);
        check_cpu_svn(kr);

        // assemble derivation data
        dd.size = sizeof(dd_provision_seal_key_t);
        dd.ddpsk.key_policy = kr->key_policy;
        if (kr->key_policy & SGX_KEYPOLICY_ISVFAMILYID) {
            memcpy(&dd.ddpsk.isv_family_id, &isv_ext_id->isv_family_id, sizeof(sgx_isvfamily_id_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_ISVEXTPRODID) {
            memcpy(&dd.ddpsk.isv_ext_prod_id, &isv_ext_id->isv_ext_prod_id, sizeof(sgx_isvext_prod_id_t));
        }

        if (kr->key_policy & SGX_KEYPOLICY_CONFIGID) {
            dd.ddpsk.config_svn = kr->config_svn;
            memcpy(&dd.ddpsk.config_id, &cur_secs->config_id, sizeof(sgx_config_id_t));
        }

        memcpy(&dd.ddpsk.tmp_attr, &tmp_attr, sizeof(sgx_attributes_t));
        memcpy(&dd.ddpsk.attribute_mask, &kr->attribute_mask, sizeof(sgx_attributes_t));
        dd.ddpsk.tmp_misc = tmp_misc;
        dd.ddpsk.misc_mask = ~kr->misc_mask;
        memcpy(&dd.ddpsk.cpu_svn,&kr->cpu_svn,sizeof(sgx_cpu_svn_t));
        dd.ddpsk.isv_svn = kr->isv_svn;
        if (!(kr->key_policy & SGX_KEYPOLICY_NOISVPRODID)) {
             dd.ddpsk.isv_prod_id = cur_secs->isv_prod_id;
        }
        memcpy(&dd.ddpsk.mrsigner, &cur_secs->mr_signer, sizeof(sgx_measurement_t));
        break;

    default:
        return EGETKEY_INVALID_KEYNAME;
    }

    derive_key(&dd, okey);
    return 0;
}

////////////////////////////////////////////////////////////////////////
// Simulation for EREPORT
////////////////////////////////////////////////////////////////////////

static void _EREPORT(const sgx_target_info_t* ti, const sgx_report_data_t* rd, sgx_report_t* report)
{
    // check alignment of TARGETINFO
    GP_ON(((size_t)ti & (TARGET_INFO_ALIGN_SIZE - 1)) != 0);

    // check to see if TARGETINFO is inside the current enclave
    GP_ON(!sgx_is_within_enclave(ti, sizeof(sgx_target_info_t)));

    // check alignment of REPORTDATA
    GP_ON(((size_t)rd & (REPORT_DATA_ALIGN_SIZE - 1)) != 0);

    // check to see if REPORTDATA is inside the current enclave
    GP_ON(!sgx_is_within_enclave(rd, sizeof(sgx_report_data_t)));

    // check alignment of OUTPUTDATA
    GP_ON(((size_t)report & (REPORT_ALIGN_SIZE - 1)) != 0);

    // check to see if OUTPUTDATA is inside the current enclave
    GP_ON(!sgx_is_within_enclave(report, sizeof(sgx_report_t)));

    secs_t*     cur_secs = g_global_data_sim.secs_ptr;
    isv_ext_id_t* isv_ext_id = reinterpret_cast<isv_ext_id_t *>(cur_secs->reserved4);
    SE_DECLSPEC_ALIGN(REPORT_ALIGN_SIZE) sgx_report_t tmp_report;

    // assemble REPORT Data
    memset(&tmp_report, 0, sizeof(tmp_report));
    memcpy(&tmp_report.body.cpu_svn,&(g_global_data_sim.cpusvn_sim),sizeof(sgx_cpu_svn_t));
    tmp_report.body.misc_select = cur_secs->misc_select;
    tmp_report.body.isv_prod_id = cur_secs->isv_prod_id;
    tmp_report.body.isv_svn = cur_secs->isv_svn;
    tmp_report.body.config_svn = cur_secs->config_svn;
    memcpy(&tmp_report.body.isv_family_id, &isv_ext_id->isv_family_id, sizeof(sgx_isvfamily_id_t));
    memcpy(&tmp_report.body.isv_ext_prod_id, &isv_ext_id->isv_ext_prod_id, sizeof(sgx_isvext_prod_id_t));
    memcpy(&tmp_report.body.config_id, &cur_secs->config_id, sizeof(sgx_config_id_t));
    memcpy(&tmp_report.body.attributes, &cur_secs->attributes, sizeof(sgx_attributes_t));
    memcpy(&tmp_report.body.report_data, rd, sizeof(sgx_report_data_t));
    memcpy(&tmp_report.body.mr_enclave, &cur_secs->mr_enclave, sizeof(sgx_measurement_t));
    memcpy(&tmp_report.body.mr_signer, &cur_secs->mr_signer, sizeof(sgx_measurement_t));
    memcpy(&tmp_report.key_id, get_base_key(SGX_KEYSELECT_REPORT), sizeof(sgx_key_id_t)/2);

    // derive the report key
    derivation_data_t   dd;
    memset(&dd, 0, sizeof(dd));
    dd.size = sizeof(dd_report_key_t);

    dd.key_name = SGX_KEYSELECT_REPORT;
    memcpy(&dd.ddrk.mrenclave, &ti->mr_enclave, sizeof(sgx_measurement_t));
    memcpy(&dd.ddrk.attributes, &ti->attributes, sizeof(sgx_attributes_t));
    memcpy(dd.ddrk.csr_owner_epoch, SIMU_OWNER_EPOCH_MSR, sizeof(se_owner_epoch_t));
    memcpy(&dd.ddrk.cpu_svn,&(g_global_data_sim.cpusvn_sim),sizeof(sgx_cpu_svn_t));
    memcpy(&dd.ddrk.key_id, &tmp_report.key_id, sizeof(sgx_key_id_t));
    memcpy(&dd.ddrk.config_id, &ti->config_id, sizeof(sgx_config_id_t));
    dd.ddrk.config_svn = ti->config_svn;
    dd.ddrk.misc_select = ti->misc_select;

    // calculate the derived key
    sgx_key_128bit_t tmp_report_key;
    memset(tmp_report_key, 0, sizeof(tmp_report_key));

    derive_key(&dd, tmp_report_key);

    // call cryptographic CMAC function
    // CMAC data are *NOT* including MAC and KEYID
    cmac(&tmp_report_key, reinterpret_cast<uint8_t*>(&tmp_report.body),
        sizeof(tmp_report.body), &tmp_report.mac);

    memcpy(report, &tmp_report, sizeof(sgx_report_t));
}

////////////////////////////////////////////////////////////////////////

static void
_EEXIT(uintptr_t dest, uintptr_t xcx, uintptr_t xdx, uintptr_t xsi, uintptr_t xdi) __attribute__((section(".nipx")));

// The call to load_regs assumes the existence of a frame pointer.
LOAD_REGS_ATTRIBUTES
static void
_EEXIT(uintptr_t dest, uintptr_t xcx, uintptr_t xdx, uintptr_t xsi, uintptr_t xdi)
{
    // By simulator convention, XDX contains XBP and XCX contains XSP.

    enclu_regs_t regs;
    regs.xsp = xcx;   // xcx = xsp = ssa.rsp_u
    regs.xbp = xdx;   // xdx = xbp = ssa.rbp_u
    regs.xip = dest;  // dest= xbx = xcx on EENTER = return address
    // For the value of ssa.rsp_u, ssa.rbp_u, and return address, see _EENTER in u_instruction.cpp

    tcs_t *tcs = GET_TCS_PTR(xdx);
    GP_ON(tcs == NULL);

    // restore the used _tls_array
    GP_ON(td_mngr_restore_td(tcs) == false);

    // check thread is in use or not
    tcs_sim_t *tcs_sim = reinterpret_cast<tcs_sim_t *>(tcs->reserved);

    size_t tcs_target_state = TCS_STATE_INACTIVE;
    size_t tcs_current_state = TCS_STATE_INACTIVE;
    __atomic_exchange(&tcs_sim->tcs_state, &tcs_target_state, &tcs_current_state, __ATOMIC_RELAXED);
    GP_ON(tcs_current_state!= TCS_STATE_ACTIVE);

    regs.xax = 0;
    regs.xbx = dest;
    regs.xcx = tcs_sim->saved_aep;
    regs.xsi = xsi;
    regs.xdi = xdi;

    load_regs(&regs);

    // jump back to the instruction after the call to _SE3
    // common/inc/internal/linux/linux-regs.h:
    //    call    _SE3
    //  ---------------------------> jump here
    // #   ifdef LINUX32
    //     add     $(SE_WORDSIZE * 6), %esp
    // #   endif

    // Never returns.....
}


// Master entry functions

uintptr_t _SE3(uintptr_t xax, uintptr_t xbx, uintptr_t xcx,
               uintptr_t xdx, uintptr_t xsi, uintptr_t xdi)
{
    switch (xax)
    {
    case SE_EEXIT:
        _EEXIT(xbx, xcx, xdx, xsi, xdi);
        // never reach here
        return 0;

    case SE_EGETKEY:
        return _EGETKEY(reinterpret_cast<sgx_key_request_t *>(xbx),
                        reinterpret_cast<uint8_t *>(xcx));

    case SE_EREPORT:
        _EREPORT(reinterpret_cast<sgx_target_info_t*>(xbx),
                 reinterpret_cast<sgx_report_data_t*>(xcx),
                 reinterpret_cast<sgx_report_t*>(xdx));
    return 0;
    }

    GP();
    return (uintptr_t)-1;
}
