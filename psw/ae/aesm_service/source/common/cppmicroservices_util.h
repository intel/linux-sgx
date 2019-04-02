#include <cppmicroservices/Bundle.h>
#include <cppmicroservices/BundleContext.h>
#include <cppmicroservices/GetBundleContext.h>

using namespace cppmicroservices;

template <class S>
bool get_service_wrapper(std::shared_ptr<S> &service) noexcept
{
    try
    {
        auto context = cppmicroservices::GetBundleContext();
        auto ref = context.GetServiceReference<S>();
        if (S::VERSION != ref.GetBundle().GetVersion().GetMajor())
            return false;
        service = context.GetService(ref);
    }
    catch(...)
    {
        return false;
    }
    return true;
}
