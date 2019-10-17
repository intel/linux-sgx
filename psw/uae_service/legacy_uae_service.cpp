/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#include <dlfcn.h>
#include "sgx_uae_service.h"
#include "uae_service_internal.h"

template<class T>
class Singleton
{
public:
    static T& instance()
    {
        if (0 == _instance)
        {
            _instance = new T();
            atexit(destroy);
        }
        return *_instance;
    }

    virtual ~Singleton()
    {
        _instance = NULL;
    }

protected:
    Singleton(){}
private:
    Singleton(const Singleton&);
    Singleton& operator=(const Singleton&);
    static void destroy()
    {
        if ( _instance != 0 )
        {
            delete _instance;
            _instance = 0;
        }
    }
    static T * volatile _instance;
};


template<class T>
T * volatile Singleton<T>::_instance = 0;

template<class T>
class SharedLibProxy: public Singleton<T>
{
private:
    void* handle;

protected:	
    virtual const char* GetLibraryPath(void) const = 0;

public:
    SharedLibProxy(void):handle(NULL){};
	virtual ~SharedLibProxy(void)
	{
		unload();
	};

    void load()
	{
		handle = dlopen(GetLibraryPath(), RTLD_LAZY);
		if (!isLoaded())
			dlerror();
	};
    void unload()
	{
		if (isLoaded())
		{
			dlclose(handle);
			handle = 0;
		}
	};
    bool isLoaded() const { return handle != 0; };
	bool findSymbol(const char* name, void** function)
	{
		if (!isLoaded())
		{
			load();
		}
		if (isLoaded())
		{
			*function = dlsym(handle, name);
			return *function != NULL;
		}
		return false;
	};
};

#define _CONCAT(x, y) x/**/y

#define MAJOR_VER "1"

const static char EPID_LIB[] = _CONCAT("libsgx_epid.so.", MAJOR_VER);

class EPIDLib:public SharedLibProxy<EPIDLib>
{
protected:	
    const char* GetLibraryPath(void) const
	{
		return EPID_LIB;
	};
};

const static char LAUNCH_LIB[] = _CONCAT("libsgx_launch.so.", MAJOR_VER);

class LaunchLib:public SharedLibProxy<LaunchLib>
{
protected:	
    const char* GetLibraryPath(void) const
	{
		return LAUNCH_LIB;
	};
};

const static char PLATFORM_LIB[] = _CONCAT("libsgx_platform.so.", MAJOR_VER);

class PlatformLib:public SharedLibProxy<PlatformLib>
{
protected:	
    const char* GetLibraryPath(void) const
	{
		return PLATFORM_LIB;
	};
};

const static char QUOTE_EX_LIB[] = _CONCAT("libsgx_quote_ex.so.", MAJOR_VER);

class QuoteExLib:public SharedLibProxy<QuoteExLib>
{
protected:	
    const char* GetLibraryPath(void) const
	{
		return QUOTE_EX_LIB;
	};
};

extern "C" {

sgx_status_t get_launch_token(
    const enclave_css_t*        signature,
    const sgx_attributes_t*     attribute,
    sgx_launch_token_t*         launch_token)
{
	sgx_status_t (*p_get_launch_token)(
		const enclave_css_t*        signature,
		const sgx_attributes_t*     attribute,
		sgx_launch_token_t*         launch_token) = NULL;
    if (LaunchLib::instance().findSymbol(__FUNCTION__, (void**)&p_get_launch_token))
    {
        return p_get_launch_token(signature, attribute, launch_token);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_init_quote(
    sgx_target_info_t       *p_target_info,
    sgx_epid_group_id_t     *p_gid)
{
	sgx_status_t (*p_sgx_init_quote)(
		sgx_target_info_t       *p_target_info,
		sgx_epid_group_id_t     *p_gid) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_init_quote))
    {
        return p_sgx_init_quote(p_target_info, p_gid);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_calc_quote_size(
    const uint8_t *p_sig_rl,
    uint32_t sig_rl_size,
    uint32_t* p_quote_size)
{
	sgx_status_t (*p_sgx_calc_quote_size)(
		const uint8_t *p_sig_rl,
		uint32_t sig_rl_size,
		uint32_t* p_quote_size) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_calc_quote_size))
    {
        return p_sgx_calc_quote_size(p_sig_rl, sig_rl_size, p_quote_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_get_quote_size(
    const uint8_t *p_sig_rl,
    uint32_t* p_quote_size)
{
	sgx_status_t (*p_sgx_get_quote_size)(
		const uint8_t *p_sig_rl,
		uint32_t* p_quote_size) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_quote_size))
    {
        return p_sgx_get_quote_size(p_sig_rl, p_quote_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_get_quote(
    const sgx_report_t      *p_report,
    sgx_quote_sign_type_t   quote_type,
    const sgx_spid_t        *p_spid,
    const sgx_quote_nonce_t *p_nonce,
    const uint8_t           *p_sig_rl,
    uint32_t                sig_rl_size,
    sgx_report_t            *p_qe_report,
    sgx_quote_t             *p_quote,
    uint32_t                quote_size)
{

	sgx_status_t (*p_sgx_get_quote)(
		const sgx_report_t      *p_report,
		sgx_quote_sign_type_t   quote_type,
		const sgx_spid_t        *p_spid,
		const sgx_quote_nonce_t *p_nonce,
		const uint8_t           *p_sig_rl,
		uint32_t                sig_rl_size,
		sgx_report_t            *p_qe_report,
		sgx_quote_t             *p_quote,
		uint32_t                quote_size) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_quote))
    {
        return p_sgx_get_quote(p_report, quote_type, p_spid, p_nonce, p_sig_rl, sig_rl_size, p_qe_report,
                                            p_quote, quote_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_get_ps_cap(sgx_ps_cap_t* p_sgx_ps_cap)
{
    sgx_status_t (*p_sgx_get_ps_cap)(sgx_ps_cap_t* p_sgx_ps_cap) = NULL;
    if (PlatformLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_ps_cap))
    {
        return p_sgx_get_ps_cap(p_sgx_ps_cap);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_report_attestation_status(
    const sgx_platform_info_t*  p_platform_info,
    int                         attestation_status,
    sgx_update_info_bit_t*          p_update_info)
{
	sgx_status_t (*p_sgx_report_attestation_status)(
		const sgx_platform_info_t*  p_platform_info,
		int                         attestation_status,
		sgx_update_info_bit_t*          p_update_info) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_report_attestation_status))
    {
        return p_sgx_report_attestation_status(p_platform_info, attestation_status, p_update_info);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t SGXAPI sgx_check_update_status(
    const sgx_platform_info_t* p_platform_info,
    sgx_update_info_bit_t* p_update_info,
    uint32_t config,
    uint32_t* p_status)
{
	sgx_status_t (*p_sgx_check_update_status)(
		const sgx_platform_info_t* p_platform_info,
		sgx_update_info_bit_t* p_update_info,
		uint32_t config,
		uint32_t* p_status) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_check_update_status))
    {
        return p_sgx_check_update_status(p_platform_info, p_update_info, config, p_status);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t create_session_ocall(
    uint32_t        *session_id,
    uint8_t         *se_dh_msg1,
    uint32_t        dh_msg1_size,
    uint32_t timeout)
{
	sgx_status_t (*p_create_session_ocall)(
		uint32_t        *session_id,
		uint8_t         *se_dh_msg1,
		uint32_t        dh_msg1_size,
		uint32_t timeout) = NULL;
    if (PlatformLib::instance().findSymbol(__FUNCTION__, (void**)&p_create_session_ocall))
    {
        return p_create_session_ocall(session_id, se_dh_msg1, dh_msg1_size, timeout);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t exchange_report_ocall(
    uint32_t        session_id,
    const uint8_t   *se_dh_msg2,
    uint32_t        dh_msg2_size,
    uint8_t         *se_dh_msg3,
    uint32_t        dh_msg3_size,
    uint32_t        timeout)
{
	sgx_status_t (*p_exchange_report_ocall)(
		uint32_t        session_id,
		const uint8_t   *se_dh_msg2,
		uint32_t        dh_msg2_size,
		uint8_t         *se_dh_msg3,
		uint32_t        dh_msg3_size,
		uint32_t        timeout) = NULL;
    if (PlatformLib::instance().findSymbol(__FUNCTION__, (void**)&p_exchange_report_ocall))
    {
        return p_exchange_report_ocall(session_id, se_dh_msg2, dh_msg2_size, se_dh_msg3, dh_msg3_size, timeout);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t close_session_ocall(
    uint32_t        session_id,
    uint32_t        timeout)
{
	sgx_status_t (*p_close_session_ocall)(
		uint32_t        session_id,
		uint32_t        timeout) = NULL;
    if (PlatformLib::instance().findSymbol(__FUNCTION__, (void**)&p_close_session_ocall))
    {
        return p_close_session_ocall(session_id, timeout);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t invoke_service_ocall(
    const uint8_t   *pse_message_req,
    uint32_t        pse_message_req_size,
    uint8_t         *pse_message_resp,
    uint32_t        pse_message_resp_size,
    uint32_t        timeout)
{
	sgx_status_t (*p_invoke_service_ocall)(
		const uint8_t   *pse_message_req,
		uint32_t        pse_message_req_size,
		uint8_t         *pse_message_resp,
		uint32_t        pse_message_resp_size,
		uint32_t        timeout) = NULL;
    if (PlatformLib::instance().findSymbol(__FUNCTION__, (void**)&p_invoke_service_ocall))
    {
        return p_invoke_service_ocall(pse_message_req, pse_message_req_size, pse_message_resp, pse_message_resp_size, timeout);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}


sgx_status_t sgx_get_whitelist_size(
    uint32_t* p_whitelist_size)
{
	sgx_status_t (*p_sgx_get_whitelist_size)(
		uint32_t* p_whitelist_size) = NULL;
    if (LaunchLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_whitelist_size))
    {
        return p_sgx_get_whitelist_size(p_whitelist_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}


sgx_status_t sgx_get_whitelist(
    uint8_t* p_whitelist,
    uint32_t whitelist_size)
{
	sgx_status_t (*p_sgx_get_whitelist)(
		uint8_t* p_whitelist,
		uint32_t whitelist_size) = NULL;
    if (LaunchLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_whitelist))
    {
        return p_sgx_get_whitelist(p_whitelist, whitelist_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_get_extended_epid_group_id(
    uint32_t* p_extended_epid_group_id)
{
	sgx_status_t (*p_sgx_get_extended_epid_group_id)(
		uint32_t* p_extended_epid_group_id) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_extended_epid_group_id))
    {
        return p_sgx_get_extended_epid_group_id(p_extended_epid_group_id);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_switch_extended_epid_group(uint32_t extended_epid_group_id)
{
	sgx_status_t (*p_sgx_switch_extended_epid_group)(uint32_t extended_epid_group_id) = NULL;
    if (EPIDLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_switch_extended_epid_group))
    {
        return p_sgx_switch_extended_epid_group(extended_epid_group_id);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_register_wl_cert_chain(uint8_t* p_wl_cert_chain, uint32_t wl_cert_chain_size)
{
	sgx_status_t (*p_sgx_register_wl_cert_chain)(uint8_t* p_wl_cert_chain, uint32_t wl_cert_chain_size) = NULL;
    if (LaunchLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_register_wl_cert_chain))
    {
        return p_sgx_register_wl_cert_chain(p_wl_cert_chain, wl_cert_chain_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t sgx_select_att_key_id(const uint8_t *p_att_key_id_list, uint32_t att_key_id_list_size,
                                   sgx_att_key_id_t *p_selected_key_id)
{
	sgx_status_t (*p_sgx_select_att_key_id)(const uint8_t *p_att_key_id_list, uint32_t att_key_id_list_size,
                                   sgx_att_key_id_t *p_selected_key_id) = NULL;
    if (QuoteExLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_select_att_key_id))
    {
        return p_sgx_select_att_key_id(p_att_key_id_list, att_key_id_list_size, p_selected_key_id);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
 }

sgx_status_t sgx_init_quote_ex(const sgx_att_key_id_t* p_att_key_id,
                                            sgx_target_info_t *p_qe_target_info,
                                            size_t* p_pub_key_id_size,
                                            uint8_t* p_pub_key_id)
{
	sgx_status_t (*p_sgx_init_quote_ex)(const sgx_att_key_id_t* p_att_key_id,
                                            sgx_target_info_t *p_qe_target_info,
                                            size_t* p_pub_key_id_size,
                                            uint8_t* p_pub_key_id) = NULL;
    if (QuoteExLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_init_quote_ex))
    {
        return p_sgx_init_quote_ex(p_att_key_id, p_qe_target_info, p_pub_key_id_size, p_pub_key_id);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t SGXAPI sgx_get_quote_size_ex(const sgx_att_key_id_t *p_att_key_id,
                                                uint32_t* p_quote_size)
{
	sgx_status_t (*p_sgx_get_quote_size_ex)(const sgx_att_key_id_t *p_att_key_id,
                                                uint32_t* p_quote_size) = NULL;
    if (QuoteExLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_quote_size_ex))
    {
        return p_sgx_get_quote_size_ex(p_att_key_id, p_quote_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

sgx_status_t SGXAPI  sgx_get_quote_ex(const sgx_report_t *p_app_report,
                                           const sgx_att_key_id_t *p_att_key_id,
                                           sgx_qe_report_info_t *p_qe_report_info,
                                           uint8_t *p_quote,
                                           uint32_t quote_size)
{
	sgx_status_t (*p_sgx_get_quote_ex)(const sgx_report_t *p_app_report,
                                           const sgx_att_key_id_t *p_att_key_id,
                                           sgx_qe_report_info_t *p_qe_report_info,
                                           uint8_t *p_quote,
                                           uint32_t quote_size) = NULL;
    if (QuoteExLib::instance().findSymbol(__FUNCTION__, (void**)&p_sgx_get_quote_ex))
    {
        return p_sgx_get_quote_ex(p_app_report, p_att_key_id, p_qe_report_info, p_quote, quote_size);
    }
    return SGX_ERROR_SERVICE_UNAVAILABLE;
}

} /* extern "C" */
