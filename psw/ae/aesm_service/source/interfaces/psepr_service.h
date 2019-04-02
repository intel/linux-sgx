#ifndef PSEPR_SERVICE_EXPORT_H
#define PSEPR_SERVICE_EXPORT_H
#include "service.h"
#include <aeerror.h>
#include <aesm_error.h>
#include "platform_info_blob.h"


struct IPseprService : public IService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 1};
    virtual ~IPseprService() = default;

    virtual ae_error_t certificate_provisioning(
        platform_info_blob_wrapper_t* pib_wrapper) const = 0;
        
    virtual ae_error_t long_term_pairing(
        bool* p_new_pairing) const = 0;

    virtual void unload_enclave() = 0;

};

#endif /* PSEPR_SERVICE_EXPORT_H */
