#include <pseop_service.h>
#include <epid_quote_service.h>
#include <psepr_service.h>

#include <cppmicroservices/BundleActivator.h>
#include "cppmicroservices/BundleContext.h"
#include <cppmicroservices/GetBundleContext.h>
#include "cppmicroservices_util.h"

#include <iostream>
#include "util.h"
#include "aesm_logic.h"
#include "aesm_long_lived_thread.h"
#include "pse_op_logic.h"
#include "PSEClass.h"
#include "PSDAService.h"
#include "platform_info_logic.h"
#include "interface_psda.h"


using namespace cppmicroservices;
std::shared_ptr<IEpidQuoteService> g_epid_service;
std::shared_ptr<IPseprService> g_psepr_service;


extern ThreadStatus long_term_paring_thread;
static AESMLogicMutex _pse_mutex;

bool query_pse_thread_status(void)
{
    return long_term_paring_thread.query_status_and_reset_clock();
}

#define CHECK_LONG_TERM_PAIRING_STATUS \
    if(!query_pse_thread_status()){\
        return AESM_BUSY; \
    }

static ae_error_t thread_to_init_pse(aesm_thread_arg_type_t arg)
{
    UNUSED(arg);
    AESM_DBG_INFO("start to init_ps");
    AESMLogicLock lock(_pse_mutex);
    ae_error_t psError = CPSEClass::instance().init_ps();
    UNUSED(psError);// To ignore the error that the symbol not used in release mode
    AESM_DBG_INFO("init_ps return ( ae %d)", psError);
    return AE_SUCCESS;
}

class LocalPseopServiceImp : public IPseopService
{
private:
    aesm_thread_t pse_thread;
public:
    LocalPseopServiceImp():pse_thread(NULL){}

    aesm_error_t create_session(
        uint32_t* session_id,
        uint8_t* se_dh_msg1,
        uint32_t se_dh_msg1_size)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::create_session");
        AESMLogicLock lock(_pse_mutex);
        CHECK_LONG_TERM_PAIRING_STATUS;
        ae_error_t psStatus;
        // If PSDA not loaded or CSE not provisioned
        if (CPSEClass::instance().get_status() == PSE_STATUS_INIT ||
            CPSEClass::instance().get_status() == PSE_STATUS_UNAVAILABLE )
        {
            AESM_DBG_ERROR("unexpected status PSE_STATUS_INIT : PSDA not loaded or CSE not provisioned.");
            return AESM_PSDA_UNAVAILABLE;
        }
        else
            psStatus = PlatformInfoLogic::create_session_pre_internal();
        if (AE_SUCCESS != psStatus) {
            AESM_DBG_ERROR("psStatus = 0x%X in create_session", psStatus);
        }
        if (OAL_THREAD_TIMEOUT_ERROR == psStatus){
            AESM_DBG_INFO("AESM is busy in intializing for pse");
            return AESM_BUSY;
        }
        if (PVE_PROV_ATTEST_KEY_NOT_FOUND == psStatus) {
            AESM_DBG_INFO("Key not found reported by Provisioning backend");
            return AESM_UNRECOGNIZED_PLATFORM;
        }
        if(OAL_PROXY_SETTING_ASSIST == psStatus){
            AESM_DBG_INFO("Proxy assist required in initializing for pse");
            return AESM_PROXY_SETTING_ASSIST;
        }
        if(PSW_UPDATE_REQUIRED == psStatus){
            AESM_DBG_INFO("PSW software update required");
            return AESM_UPDATE_AVAILABLE;
        }
        if (AESM_AE_OUT_OF_EPC == psStatus){
            AESM_DBG_INFO("AE out of EPC");
            return AESM_OUT_OF_EPC;
        }
        if (OAL_NETWORK_UNAVAILABLE_ERROR == psStatus){
            AESM_DBG_INFO("Network is unavailable");
            return AESM_NETWORK_ERROR;
        }
        if (AESM_PSDA_PLATFORM_KEYS_REVOKED == psStatus) {
            AESM_DBG_INFO("This platform was revoked");
            return AESM_EPID_REVOKED_ERROR;
        }

        if (PVE_PROV_ATTEST_KEY_TCB_OUT_OF_DATE == psStatus) {
            AESM_DBG_INFO("TCB out of date reported by Provisioning backend");
            return AESM_UPDATE_AVAILABLE;
        }

        if (AE_SUCCESS != psStatus) {
            AESM_DBG_ERROR("psStatus = 0x%X in create_session", psStatus);
        }

        return PSEOPAESMLogic::create_session(session_id, se_dh_msg1, se_dh_msg1_size);
    }

    aesm_error_t exchange_report(
        uint32_t session_id,
        const uint8_t* se_dh_msg2,
        uint32_t se_dh_msg2_size,
        uint8_t* se_dh_msg3,
        uint32_t se_dh_msg3_size)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::exchange_report");
        AESMLogicLock lock(_pse_mutex);
        CHECK_LONG_TERM_PAIRING_STATUS;

        return PSEOPAESMLogic::exchange_report(session_id,
                                    se_dh_msg2,
                                    se_dh_msg2_size,
                                    se_dh_msg3,
                                    se_dh_msg3_size);
    }

    aesm_error_t invoke_service(
        const uint8_t* pse_message_req,
        uint32_t pse_message_req_size,
        uint8_t* pse_message_resp,
        uint32_t pse_message_resp_size)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::invoke_service");
        AESMLogicLock lock(_pse_mutex);
        CHECK_LONG_TERM_PAIRING_STATUS;
        return PSEOPAESMLogic::invoke_service(pse_message_req,
                                            pse_message_req_size,
                                            pse_message_resp,
                                            pse_message_resp_size);
    }

     aesm_error_t get_ps_cap(
        uint64_t* ps_cap)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::get_ps_cap");
        AESMLogicLock lock(_pse_mutex);

        return PSEOPAESMLogic::get_ps_cap(ps_cap);
    }

    aesm_error_t close_session(
        uint32_t session_id)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::close_session");
        AESMLogicLock lock(_pse_mutex);

        return PSEOPAESMLogic::close_session(session_id);
    }


    aesm_error_t report_attestation_status(
    uint8_t* platform_info, uint32_t platform_info_size,
    uint32_t attestation_status,
    uint8_t* update_info, uint32_t update_info_size)
    {
        AESM_DBG_INFO("LocalPseopServiceImp::report_attestation_status");
        AESMLogicLock lock(_pse_mutex);
        CHECK_LONG_TERM_PAIRING_STATUS;
        return  PlatformInfoLogic::report_attestation_status(platform_info,platform_info_size,
            attestation_status,
            update_info, update_info_size);
    }

    ae_error_t save_psda_capability()
    {
        return PSDAService::instance().save_psda_capability();
    }

    ae_error_t PSDA_send_and_recv(
        int32_t   nCommandId,
        void* pComm,
        int32_t* responseCode,
        uint32_t flag)
    {
        return PSDAService::instance().send_and_recv(nCommandId,
            (JVM_COMM_BUFFER*)pComm,
            responseCode,
            (session_loss_retry_flag_t)flag);
    }
    bool PSDA_is_sigma20_supported()
    {
        return PSDAService::instance().is_sigma20_supported();
    }

    ae_error_t start()
    {
        AESM_DBG_INFO("Starting pseop bundle");
        get_service_wrapper(g_epid_service);
        get_service_wrapper(g_psepr_service);
        if (g_epid_service == nullptr || g_epid_service->start())
            return AE_FAILURE;
        if (g_psepr_service == nullptr || g_psepr_service->start())
            return AE_FAILURE;

        ae_error_t aesm_ret2 = aesm_create_thread(thread_to_init_pse, 0, &pse_thread);
        if(AE_SUCCESS != aesm_ret2 ){
            AESM_DBG_WARN("Fail to create thread to init PSE:( ae %d)",aesm_ret2);
            return AE_FAILURE;
        }
        AESM_DBG_INFO("pseop bundle started");
        return AE_SUCCESS;
     }

    void stop()
    {
        ae_error_t ae_ret, thread_ret;

        ae_ret = aesm_wait_thread(pse_thread, &thread_ret, AESM_STOP_TIMEOUT);
        if (ae_ret != AE_SUCCESS || thread_ret != AE_SUCCESS)
        {
            AESM_DBG_INFO("aesm_wait_thread failed(pse_thread):(ae %d) (%d)", ae_ret, thread_ret);
        }
        (void)aesm_free_thread(pse_thread);//release thread handle to free memory

        uint64_t stop_tick_count = se_get_tick_count()+500/1000;
        long_term_paring_thread.stop_thread(stop_tick_count);

        CPSEClass::instance().unload_enclave();
        AESM_DBG_INFO("pseop bundle stopped");
    }

    ae_error_t load_enclave()
    {
        return CPSEClass::instance().load_enclave();
    }

    void unload_enclave()
    {
        CPSEClass::instance().unload_enclave();
    }
    ae_error_t GetS1
        (   /*in*/  const uint8_t* pse_instance_id,
            /*out*/ upse::Buffer& s1
        )
    {
        return pse_pr_interface_psda(PSDAService::instance().is_sigma20_supported()).GetS1(pse_instance_id, s1);
    }

    ae_error_t ExchangeS2AndS3
        (   /*in*/  const uint8_t* pse_instance_id,
            /*in */ const upse::Buffer& s2,
            /*out*/ upse::Buffer& s3
        )
    {
        return pse_pr_interface_psda(PSDAService::instance().is_sigma20_supported()).ExchangeS2AndS3(pse_instance_id, s2, s3);
    }

    ae_error_t get_csme_gid(
            /*out*/ uint32_t* p_cse_gid
        )
    {
        return pse_pr_interface_psda(PSDAService::instance().is_sigma20_supported()).get_csme_gid(p_cse_gid);
    }


};

class Activator : public BundleActivator
{
  void Start(BundleContext ctx)
  {
    auto service = std::make_shared<LocalPseopServiceImp>();
    ctx.RegisterService<IPseopService>(service);
  }

  void Stop(BundleContext)
  {
    // Nothing to do
  }
};

CPPMICROSERVICES_EXPORT_BUNDLE_ACTIVATOR(Activator)

// [no-cmake]
// The code below is required if the CMake
// helper functions are not used.
#ifdef NO_CMAKE
CPPMICROSERVICES_INITIALIZE_BUNDLE(local_pseop_service_bundle_name)
#endif
