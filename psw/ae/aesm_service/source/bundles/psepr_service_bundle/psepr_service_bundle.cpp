#include <network_service.h>
#include <psepr_service.h>
#include <pseop_service.h>
#include <epid_quote_service.h>

#include <cppmicroservices/BundleActivator.h>
#include "cppmicroservices/BundleContext.h"
#include <cppmicroservices/GetBundleContext.h>
#include "cppmicroservices_util.h"

#include <iostream>
#include "PSEPRClass.h"
#include "oal/oal.h"


using namespace cppmicroservices;
std::shared_ptr<IEpidQuoteService> g_epid_service;
std::shared_ptr<IPseopService> g_pseop_service;
std::shared_ptr<INetworkService> g_network_service;

class PseprServiceImp : public IPseprService
{
  private:
      bool initialized;

  public:
      PseprServiceImp():initialized(false) {}

  ae_error_t certificate_provisioning(
        platform_info_blob_wrapper_t* pib_wrapper)  const
  {
    std::cout << "PseprServiceImp::certificate_provisioning called" << std::endl;
    return CPSEPRClass::instance().certificate_provisioning(pib_wrapper);
  }


  ae_error_t long_term_pairing(
        bool* p_new_pairing) const
  {
    std::cout << "PseprServiceImp::long_term_pairing called" << std::endl;
    return CPSEPRClass::instance().long_term_pairing(p_new_pairing);
  }

  ae_error_t start()
  {
    AESM_DBG_INFO("Starting psepr bundle");
    auto context = cppmicroservices::GetBundleContext();
    get_service_wrapper(g_network_service, context);
    get_service_wrapper(g_epid_service, context);
    get_service_wrapper(g_pseop_service, context);

    if (g_epid_service == nullptr || g_epid_service->start())
        return AE_FAILURE;
    AESM_DBG_INFO("psepr bundle started");
    initialized = true;
    return AE_SUCCESS;//CPSEPRClass::instance().load_enclave();
  }

  void unload_enclave()
  {
    CPSEPRClass::instance().unload_enclave();
    initialized = false;
  }

  void stop()
  {
    CPSEPRClass::instance().unload_enclave();
    AESM_DBG_INFO("psepr bundle stopped");
  }
};

class Activator : public BundleActivator
{
  void Start(BundleContext ctx)
  {
    auto service = std::make_shared<PseprServiceImp>();
    ctx.RegisterService<IPseprService>(service);
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
CPPMICROSERVICES_INITIALIZE_BUNDLE(psepr_service_bundle_name)
#endif
