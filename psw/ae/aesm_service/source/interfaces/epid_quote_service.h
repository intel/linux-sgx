#ifndef EPID_QUOTE_SERVICE_EXPORT_H
#define EPID_QUOTE_SERVICE_EXPORT_H
#include "quote_service.h"
#include "aesm_error.h"
#include "aeerror.h"
#include "es_info.h"
#include "tlv_common.h"


struct IEpidQuoteService : public IQuoteService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 2};
    virtual ~IEpidQuoteService() = default;

    virtual aesm_error_t get_extended_epid_group_id(
        uint32_t* x_group_id) = 0;
    virtual aesm_error_t switch_extended_epid_group(
        uint32_t x_group_id) = 0;
    virtual uint32_t endpoint_selection(
        endpoint_selection_infos_t& es_info) = 0;
    virtual aesm_error_t provision(
        bool performance_rekey_used,
        uint32_t timeout_usec) = 0;
    virtual const char *get_server_url(
        aesm_network_server_enum_type_t type) = 0;
    virtual const char *get_pse_provisioning_url(
        const endpoint_selection_infos_t& es_info) = 0;
    enum {GIDMT_UNMATCHED, GIDMT_NOT_AVAILABLE, GIDMT_MATCHED,GIDMT_UNEXPECTED_ERROR};
    virtual uint32_t is_gid_matching_result_in_epid_blob(
        const GroupId& gid) = 0;
};

#endif /* EPID_QUOTE_SERVICE_EXPORT_H */
