#ifndef PSEOP_SERVICE_EXPORT_H
#define PSEOP_SERVICE_EXPORT_H
#include "service.h"
#include "stdint.h"
#include "Buffer.h"
#include <aeerror.h>
#include <aesm_error.h>

struct IPseopService : virtual public IService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 2};
    virtual ~IPseopService() = default;

    virtual aesm_error_t create_session(
        uint32_t* session_id,
        uint8_t* se_dh_msg1,
        uint32_t se_dh_msg1_size) = 0;

    virtual aesm_error_t exchange_report(
        uint32_t session_id,
        const uint8_t* se_dh_msg2,
        uint32_t se_dh_msg2_size,
        uint8_t* se_dh_msg3,
        uint32_t se_dh_msg3_size) = 0;

    virtual aesm_error_t invoke_service(
        const uint8_t* pse_message_req,
        uint32_t pse_message_req_size,
        uint8_t* pse_message_resp,
        uint32_t pse_message_resp_size) = 0;

    virtual aesm_error_t get_ps_cap(
        uint64_t* ps_cap) = 0;

    virtual aesm_error_t close_session(
        uint32_t session_id) = 0;


    virtual aesm_error_t report_attestation_status(
    uint8_t* platform_info, uint32_t platform_info_size,
    uint32_t attestation_status,
    uint8_t* update_info, uint32_t update_info_size) = 0;
    
    virtual aesm_error_t check_update_status(
    uint8_t* platform_info, uint32_t platform_info_size,
    uint8_t* update_info, uint32_t update_info_size,
    uint32_t attestation_status, uint32_t* status) = 0;
        
    virtual ae_error_t save_psda_capability() = 0;


    virtual ae_error_t PSDA_send_and_recv(
        int32_t   nCommandId,
        void* pComm,
        int32_t* responseCode,
        uint32_t flag) = 0;

    virtual bool PSDA_is_sigma20_supported() = 0;
    
    virtual ae_error_t GetS1
        (   /*in*/  const uint8_t* pse_instance_id,
            /*out*/ upse::Buffer& s1
        ) = 0;

    virtual ae_error_t ExchangeS2AndS3
        (   /*in*/  const uint8_t* pse_instance_id,
            /*in */ const upse::Buffer& s2, 
            /*out*/ upse::Buffer& s3
        ) = 0;

    virtual ae_error_t get_csme_gid(
            /*out*/ uint32_t* p_cse_gid
        ) = 0;

    virtual ae_error_t load_enclave() = 0;
    virtual void unload_enclave() = 0;
};

#endif /* PSEOP_SERVICE_EXPORT_H */
