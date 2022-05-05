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


#include "enclave_creator_sim.h"
#include "enclave_mngr.h"
#include "se_detect.h"
#include "driver_api.h"
#include "enclave.h"
#include "rts.h"
#include "routine.h"
#include "cpu_features.h"
#include "se_error_internal.h"
#include "util.h"
#include "cpusvn_util.h"
#include "rts_sim.h"
#include <assert.h>
#include <time.h>
#include "sgx_enclave_common.h"
#include <map>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

__attribute__((constructor))
static void init_openssl(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(0, NULL);
#endif
}

__attribute__((destructor))
static void cleanup_openssl(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
#endif
}


static Mutex s_enclave_info_mutex;
static std::map<void *, enclave_elrange_t>s_enclave_elrange_map;


extern "C" bool get_elrange_start_address(void* base_address, uint64_t &elrange_start_address)
{
    LockGuard lock(&s_enclave_info_mutex);
    bool ret = false;
    if(s_enclave_elrange_map.count(base_address) != 0)
    {
        elrange_start_address = s_enclave_elrange_map[base_address].elrange_start_address;
        ret = true;
    }
    return ret;  
}



EnclaveCreator* g_enclave_creator = new EnclaveCreatorSim();

EnclaveCreatorSim::EnclaveCreatorSim():
    m_sig_registered(false)
{
}

int EnclaveCreatorSim::create_enclave(secs_t *secs, sgx_enclave_id_t *enclave_id, void **start_addr, const uint32_t ex_features, const void* ex_features_p[32])
{
    if(ex_features == ENCLAVE_CREATE_EX_EL_RANGE && ex_features_p[ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX] != NULL)
    {
        enclave_elrange_t *tmp_enclave_elrange =  reinterpret_cast<enclave_elrange_t *>(const_cast<void *>(ex_features_p[ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX]));
        void *base_address = reinterpret_cast<void*>(tmp_enclave_elrange->enclave_image_address);
        LockGuard lock(&s_enclave_info_mutex);
        if (s_enclave_elrange_map.count(base_address) != 0)
        {
            enclave_elrange_t enclave_elrange = s_enclave_elrange_map[base_address];

            if (memcpy_s(&enclave_elrange, sizeof(enclave_elrange_t), tmp_enclave_elrange, sizeof(enclave_elrange_t)))
            {
                return SGX_ERROR_UNEXPECTED;
            }
        }
        else
        {
            enclave_elrange_t enclave_elrange;
            memset(&enclave_elrange, 0, sizeof(enclave_elrange_t));
            if (memcpy_s(&enclave_elrange, sizeof(enclave_elrange_t), tmp_enclave_elrange, sizeof(enclave_elrange_t)))
            {
                return SGX_ERROR_UNEXPECTED;
            }
            s_enclave_elrange_map[base_address] = enclave_elrange;
        }
    }
    return ::create_enclave(secs, enclave_id, start_addr);
}
int EnclaveCreatorSim::add_enclave_page(sgx_enclave_id_t enclave_id, void *src, uint64_t offset, const sec_info_t &sinfo, uint32_t attr)
{
    void* source = src;
    uint8_t color_page[SE_PAGE_SIZE];
    if(!source)
    {
        memset(color_page, 0, SE_PAGE_SIZE);
        source = reinterpret_cast<void*>(&color_page);
    }
    return ::add_enclave_page(enclave_id, source, (size_t)offset, sinfo, attr);
}

void reg_sig_handler();
void reg_sig_handler_sim();
int EnclaveCreatorSim::init_enclave(sgx_enclave_id_t enclave_id, enclave_css_t *enclave_css, SGXLaunchToken *lc, le_prd_css_file_t *prd_css_file)
{
    UNUSED(prd_css_file);
    sgx_launch_token_t token;
    memset(token, 0, sizeof(sgx_launch_token_t));

    if(false == m_sig_registered)
    {
        reg_sig_handler();
        reg_sig_handler_sim();
        m_sig_registered = true;
    }

    int ret = lc->update_launch_token(false);
    if(ret != SGX_SUCCESS)
        return ret;

    ret = lc->get_launch_token(&token);
    if(ret != SGX_SUCCESS)
        return ret;

    return ::init_enclave(enclave_id, enclave_css, reinterpret_cast<token_t *>(token));
}

int EnclaveCreatorSim::get_misc_attr(sgx_misc_attribute_t *sgx_misc_attr, metadata_t *metadata, SGXLaunchToken * const lc, uint32_t debug_flag)
{
    UNUSED(lc);
    sgx_attributes_t *required_attr;
    enclave_css_t *enclave_css;
    sgx_attributes_t *secs_attr;
    uint64_t xcr0 = 0;

    assert(sgx_misc_attr != NULL);
    assert(metadata != NULL);

    required_attr = &metadata->attributes;
    enclave_css   = &metadata->enclave_css;
    secs_attr     = &sgx_misc_attr->secs_attr;

    // Make sure that FP/SSE is set.
    if (SGX_XFRM_LEGACY != (required_attr->xfrm & SGX_XFRM_LEGACY))
    {
        SE_TRACE(SE_TRACE_WARNING, "FP/SSE are must-have attributes\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    if (debug_flag)
    {
        //If enclave is signed as product enclave, but is launched as debug enclave, we need report specific error code.
        if((enclave_css->body.attribute_mask.flags & SGX_FLAGS_DEBUG)
                && !(enclave_css->body.attributes.flags & SGX_FLAGS_DEBUG)
          )
        {
            return SGX_ERROR_NDEBUG_ENCLAVE;
        }
        required_attr->flags |= SGX_FLAGS_DEBUG;
    }
    else
        required_attr->flags &= (~SGX_FLAGS_DEBUG);

    secs_attr->flags = required_attr->flags;
    if (! try_read_xcr0(&xcr0))
    {
        // read_xcr0() failed
        secs_attr->xfrm = SGX_XFRM_LEGACY;
    }
    else
    {
        secs_attr->xfrm = xcr0 & required_attr->xfrm;
    }

    // Check the signature structure xfrm attribute restrictions.
    if((enclave_css->body.attribute_mask.xfrm & secs_attr->xfrm)
            != (enclave_css->body.attribute_mask.xfrm & enclave_css->body.attributes.xfrm))
    {
        SE_TRACE(SE_TRACE_WARNING, "secs attributes.xfrm does NOT match signature attributes.xfrm\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    // Check the signature structure flags attribute restrictions.
    if((enclave_css->body.attribute_mask.flags & secs_attr->flags)
            != (enclave_css->body.attribute_mask.flags & enclave_css->body.attributes.flags))
    {
        SE_TRACE(SE_TRACE_WARNING, "secs attributes.flag does NOT match signature attributes.flag\n");
        return SGX_ERROR_INVALID_ATTRIBUTE;
    }

    return SGX_SUCCESS;
}

int EnclaveCreatorSim::destroy_enclave(sgx_enclave_id_t enclave_id, uint64_t enclave_size)
{
    UNUSED(enclave_size);
    CEnclave *enclave = CEnclavePool::instance()->get_enclave(enclave_id);

    if(enclave == NULL)
        return SGX_ERROR_INVALID_ENCLAVE_ID;
    return ::destroy_enclave(enclave_id);
}

int EnclaveCreatorSim::initialize(sgx_enclave_id_t enclave_id)
{
    CEnclave *enclave = CEnclavePool::instance()->get_enclave(enclave_id);

    if(enclave == NULL)
    {
        SE_TRACE(SE_TRACE_WARNING, "enclave (id = %llu) not found.\n", enclave_id);
        return SGX_ERROR_INVALID_ENCLAVE_ID;
    }

    // Save the SECS address (EGETKEY/EREPORT needs to know SECS).
    CEnclaveMngr *mngr = CEnclaveMngr::get_instance();
    CEnclaveSim  *ce = mngr->get_enclave(enclave_id);
    if (ce == NULL)
    {
        SE_TRACE(SE_TRACE_WARNING, "enclave (id = %llu) not found.\n", enclave_id);
        return SGX_ERROR_INVALID_ENCLAVE_ID;
    }

    global_data_sim_t *global_data_sim_ptr = (global_data_sim_t *)enclave->get_global_data_sim_ptr();
    //We have check the symbol of "g_global_data_sim" in urts_com.h::_create_enclave(), so here global_data_sim_ptr won't be NULL. 
    assert(global_data_sim_ptr != NULL);

    // Initialize the `seed' to `g_global_data_sim'.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    global_data_sim_ptr->seed = (uint64_t)ts.tv_sec * 1000000000ULL  + (uint64_t)ts.tv_nsec; 
    global_data_sim_ptr->secs_ptr = ce->get_secs();
    sgx_cpu_svn_t temp_cpusvn = {{0}};

    int status = get_cpusvn(&temp_cpusvn);
    assert(status == SGX_SUCCESS);

    memcpy_s(&(global_data_sim_ptr->cpusvn_sim),sizeof(global_data_sim_ptr->cpusvn_sim), &temp_cpusvn, sizeof(temp_cpusvn));


    //Since CPUID instruction is NOT supported within enclave, we emuerate the cpu features here and send to tRTS.
    system_features_t info;
    memset(&info, 0, sizeof(system_features_t));
    get_cpu_features(&info.cpu_features);
    get_cpu_features_ext(&info.cpu_features_ext);
    init_cpuinfo((uint32_t *)info.cpuinfo_table);
    info.system_feature_set[0] |= (1ULL << SYS_FEATURE_EXTEND);
    info.size = sizeof(system_features_t);
    info.version = SDK_VERSION_1_5;
    info.sealed_key = enclave->get_sealed_key();
    status = enclave->ecall(ECMD_INIT_ENCLAVE, NULL, reinterpret_cast<void *>(&info));
    //free the tcs used by initialization;
    enclave->get_thread_pool()->reset();
    if(SGX_SUCCESS == status)
    {
        return SGX_SUCCESS;
    }
    else
    {
        SE_TRACE(SE_TRACE_WARNING, "initialize enclave failed: 0x%0x\n", status);
        return SGX_ERROR_UNEXPECTED;
    }
}

bool EnclaveCreatorSim::use_se_hw() const
{
    return false;
}

bool EnclaveCreatorSim::is_EDMM_supported(sgx_enclave_id_t enclave_id)
{
    UNUSED(enclave_id);
    return false;
}

bool EnclaveCreatorSim::is_driver_compatible()
{
    return true;
}

bool EnclaveCreatorSim::get_plat_cap(sgx_misc_attribute_t *se_attr)
{
    UNUSED(se_attr);
    return false;
}

int EnclaveCreatorSim::emodpr(uint64_t addr, uint64_t size, uint64_t flag)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(flag);

    return SGX_SUCCESS;
}

int EnclaveCreatorSim::mktcs(uint64_t tcs_addr)
{
    UNUSED(tcs_addr);

    return SGX_SUCCESS;
}

int EnclaveCreatorSim::trim_range(uint64_t fromaddr, uint64_t toaddr)
{
    UNUSED(fromaddr);
    UNUSED(toaddr);

    return SGX_SUCCESS;

}

int EnclaveCreatorSim::trim_accept(uint64_t addr)
{
    UNUSED(addr);

    return SGX_SUCCESS;
}

int EnclaveCreatorSim::remove_range(uint64_t fromaddr, uint64_t numpages)
{
    UNUSED(fromaddr);
    UNUSED(numpages);

    return SGX_SUCCESS;
}


