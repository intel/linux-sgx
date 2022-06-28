
////////////////////////////////////////////////////////////
// OCall impl. These will be part of sgx_enclave_common.cpp
////////////////////////////////////////////////////////////
#include <functional>
using namespace std;
#define PROT_MASK (PROT_READ|PROT_WRITE|PROT_EXEC)

/*
 * Call OS to reserve region for EAUG, immediately or on-demand.
 *
 * @param[in] addr Desired page aligned start address.
 * @param[in] length Size of the region in bytes of multiples of page size.
 * @param[in] page_properties Page types to be allocated, must be one of these:
 *             - ENCLAVE_PAGE_REG: regular page type. This is the default if not specified.
 *             - ENCLAVE_PAGE_SS_FIRST: the first page in shadow stack.
 *             - ENCLAVE_PAGE_SS_REST: the rest page in shadow stack.
 * @param[in] alloc_flags A bitwise OR of flags describing committing mode, committing
 *                     order, address preference, page type. The untrusted side.
 *    implementation should always invoke mmap syscall with MAP_SHARED|MAP_FIXED_NOREPLACE, and
 *    translate following additional bits to proper parameters invoking mmap or other SGX specific
 *    syscall(s) provided by the kernel.
 *        The alloc_flags param of this interface should include exactly one of following for committing mode:
 *            - ENCLAVE_EMA_COMMIT_NOW: reserves memory range with ENCLAVE_PAGE_READ|SGX_EMA_PROT_WRITE, if supported,
 *                   kernel is given a hint to EAUG EPC pages for the area as soon as possible.
 *            - ENCLAVE_EMA_COMMIT_ON_DEMAND: reserves memory range, EPC pages can be EAUGed upon #PF.
 *        ORed with zero or one of the committing order flags:
 *            - ENCLAVE_EMA_GROWSDOWN: if supported, a hint given for the kernel to EAUG pages from higher
 *                              to lower addresses, no gaps in addresses above the last committed.
 *            - ENCLAVE_EMA_GROWSUP: if supported, a hint given for the kernel to EAUG pages from lower
 *                              to higher addresses, no gaps in addresses below the last committed.
 * @retval ENCLAVE_ERROR_SUCCESS(0) The operation was successful.
 * @retval ENCLAVE_NOT_SUPPORTED: feature is not supported by the system
 * @retval ENCLAVE_LOST: may be returned if the enclave has been removed or if it has not been initialized (via EINIT)
 * @retval ENCLAVE_INVALID_ADDRESS: the start address does not point to an enclave.
 * @retval ENCLAVE_INVALID_PARAMETER: an invalid combinations of parameters.
 * @retval ENCLAVE_OUT_OF_MEMORY: No EPC left (some OSes like Linux), or system is out of memory for internal allocation by OS or this function.
 * @retval ENCLAVE_DEVICE_NO_MEMORY: NO EPC left (some OSes like Windows)
 * @retval ENCLAVE_INVALID_ADDRESS: address does not point to an enclave or valid memory within the enclave
 * @retval ENCLAVE_NOT_INITIALIZED: may be returned if the enclave has not been initialized (via EINIT).
 *                                  Some configurations may give ENCLAVE_LOST if the enclave has not been initialized.
 * @retval ENCLAVE_UNEXPECTED, unexpected error.
 */

uint32_t COMM_API enclave_alloc(
    COMM_IN uint64_t addr,
    COMM_IN size_t length,
    COMM_IN uint32_t page_properties,
    COMM_IN uint32_t alloc_flags)
{
    int ret = ENCLAVE_UNEXPECTED;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_alloc for 0x%llX ( %llX ) with alloc flags = 0x%lX\n",
            addr, length, alloc_flags);

    if (s_driver_type == SGX_DRIVER_DCAP)
    {
        return ret;
    }
    if (s_driver_type == SGX_DRIVER_OUT_OF_TREE)
    {
        return mprotect((void *)addr, length, PROT_WRITE | PROT_READ);
    }
    int enclave_fd = get_file_handle_from_address((void *)addr);
    if (enclave_fd == -1)
        return ENCLAVE_INVALID_ADDRESS;
    int map_flags = MAP_SHARED | MAP_FIXED;
    //!TODO: support COMMIT_NOW when kernel supports
    if (alloc_flags & ENCLAVE_EMA_COMMIT_NOW)
    {
    }
    //!TODO support CET
    int type = page_properties;
    if((type == ENCLAVE_PAGE_SS_FIRST) | (type == ENCLAVE_PAGE_SS_REST))
        return ENCLAVE_NOT_SUPPORTED;
    if((type == ENCLAVE_PAGE_SS_FIRST) && length > SE_PAGE_SIZE)
        return ENCLAVE_INVALID_PARAMETER;
    void *out = mmap((void *)addr, length, PROT_WRITE | PROT_READ, map_flags, enclave_fd, 0);
    if (out == MAP_FAILED)
    {
        ret = errno;
        SE_TRACE(SE_TRACE_WARNING, "mmap failed, error = %d\n", ret);
        ret = error_driver2api(-1, ret);
    }else
        ret = 0;
    return ret;
}

uint64_t get_offset_for_address(uint64_t target_address)
{
    uint64_t enclave_base_addr = (uint64_t)get_enclave_base_address_from_address((void *)target_address);
    assert(enclave_base_addr != 0);
    assert(target_address >= enclave_base_addr);
    return (uint64_t)target_address - (uint64_t)enclave_base_addr;
}

static int emodt(int fd, uint64_t addr, size_t length, uint64_t type)
{
    struct sgx_enclave_modify_types ioc;
    if (length == 0)
        return EINVAL;

    SE_TRACE(SE_TRACE_DEBUG,
        "MODT for 0x%llX ( %llX ), type: 0x%llX\n",
            addr, length, type);
    memset(&ioc, 0, sizeof(ioc));

    ioc.page_type = type;
    ioc.offset = get_offset_for_address(addr);
    ioc.length = length;
    do
    {
        int ret = ioctl(fd, SGX_IOC_ENCLAVE_MODIFY_TYPES, &ioc);

        if (ret && ioc.count == 0 && errno != EBUSY && errno != EAGAIN)
        { //total failure
            int err = errno;
            SE_TRACE(SE_TRACE_WARNING,
                "MODT failed, error = %d for 0x%llX ( %llX ), type: 0x%llX\n",
                    err, addr, length, type);
            return err;
        }
        //for recoverable partial errors
        length -= ioc.count;
        ioc.offset += ioc.count;
        ioc.result = 0;
        ioc.count = 0;
    } while (length != 0);

    return 0;
}

static int trim(int fd, uint64_t addr, size_t length)
{
    return emodt(fd, addr, length, (SGX_EMA_PAGE_TYPE_TRIM >> SGX_EMA_PAGE_TYPE_SHIFT));
}
static int mktcs(int fd, uint64_t addr, size_t length)
{

    return emodt(fd, addr, length, (SGX_EMA_PAGE_TYPE_TCS >> SGX_EMA_PAGE_TYPE_SHIFT));
}
static int trim_accept(int fd, uint64_t addr, size_t length)
{
    struct sgx_enclave_remove_pages ioc;
    memset(&ioc, 0, sizeof(ioc));

    SE_TRACE(SE_TRACE_DEBUG,
        "REMOVE for 0x%llX ( %llX )\n",
            addr, length);
    ioc.offset = get_offset_for_address(addr);
    ioc.length = length;
    int ret = 0;
    do {
        ret = ioctl(fd, SGX_IOC_ENCLAVE_REMOVE_PAGES, &ioc);
        if(ret && ioc.count == 0 && errno != EBUSY && errno != EAGAIN )
        { //total failure
            int err = errno;
            SE_TRACE(SE_TRACE_WARNING,
                "REMOVE failed, error = %d for 0x%llX ( %llX )\n",
                err, addr, length);
            return err;
        }
        ioc.length -= ioc.count;
        ioc.offset += ioc.count;
        ioc.count = 0;
    } while (ioc.length != 0);

    return 0;
}
static int emodpr(int fd, uint64_t addr, size_t length, uint64_t prot)
{
    struct sgx_enclave_restrict_permissions ioc;
    if (length == 0)
        return EINVAL;

    SE_TRACE(SE_TRACE_DEBUG,
        "MODP for 0x%llX ( %llX ), prot: 0x%llX\n",
            addr, length, prot);
    memset(&ioc, 0, sizeof(ioc));

    ioc.permissions = prot;
    ioc.offset = get_offset_for_address(addr);
    ioc.length = length;

    do
    {
        int ret = ioctl(fd, SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS, &ioc);
        //TODO: use error code
        if (ret && ioc.count == 0 && errno != EBUSY && errno!=EAGAIN )
        { //total failure
            int err = errno;
            SE_TRACE(SE_TRACE_WARNING,
                "MODP failed, error = %d for 0x%llX ( %llX ), prot: 0x%llX\n",
                    err, addr, length, prot);
            return err;
        }
        ioc.length -= ioc.count;
        ioc.offset += ioc.count;
        ioc.result = 0;
        ioc.count = 0;
    } while (ioc.length != 0);

    return 0;
}

// legacy support for EDMM

static int trim_accept_legacy(int fd, uint64_t addr, size_t len)
{
    sgx_range params;
    memset(&params, 0, sizeof(sgx_range));
    params.start_addr = (unsigned long)addr;
    params.nr_pages = (unsigned int)(len / SE_PAGE_SIZE);

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_NOTIFY_ACCEPT, &params);

    if (ret)
    {
        return errno;
    }

    return SGX_SUCCESS;
}

static int trim_legacy(int fd, uint64_t fromaddr, uint64_t len)
{
    sgx_range params;
    memset(&params, 0, sizeof(sgx_range));
    params.start_addr = (unsigned long)fromaddr;
    params.nr_pages = (unsigned int)((len) / SE_PAGE_SIZE);

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_TRIM, &params);
    if (ret)
    {
        return errno;
    }

    return SGX_SUCCESS;
}

static int mktcs_legacy(int fd, uint64_t tcs_addr, size_t len)
{
    if (len != SE_PAGE_SIZE)
        return EINVAL;
    sgx_range params;
    memset(&params, 0, sizeof(sgx_range));
    params.start_addr = (unsigned long)tcs_addr;
    params.nr_pages = 1;

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_MKTCS, &params);
    if (ret)
    {
        return errno;
    }
    return SGX_SUCCESS;
}

static int emodpr_legacy(int fd, uint64_t addr, uint64_t size, uint64_t flag)
{
    sgx_modification_param params;
    memset(&params, 0, sizeof(sgx_modification_param));
    params.range.start_addr = (unsigned long)addr;
    params.range.nr_pages = (unsigned int)(size / SE_PAGE_SIZE);
    params.flags = (unsigned long)flag;

    int ret = ioctl(fd, SGX_IOC_ENCLAVE_EMODPR, &params);
    if (ret)
    {
        return errno;
    }

    return SGX_SUCCESS;
}

/*
 * Call OS to change permissions, type, or notify EACCEPT done after TRIM.
 *
 * @param[in] addr Start address of the memory to change protections.
 * @param[in] length Length of the area.  This must be a multiple of the page size.
 * @param[in] page_properties_from The original EPCM flags of the EPC pages to be modified.
 *            Must be bitwise OR of following:
 *            ENCLAVE_PAGE_READ
 *            ENCLAVE_PAGE_WRITE
 *            ENCLAVE_PAGE_EXEC
 *            ENCLAVE_PAGE_REG: regular page, changeable to TRIM or TCS
 *            ENCLAVE_PAGE_TRIM: signal to the kernel EACCEPT is done for TRIM pages.
 * @param[in] page_properties_to The target EPCM flags. This must be bitwise OR of following:
 *            ENCLAVE_PAGE_READ
 *            ENCLAVE_PAGE_WRITE
 *            ENCLAVE_PAGE_EXEC
 *            ENCLAVE_PAGE_TRIM: change the page type to PT_TRIM. Note the address
 *                      range for trimmed pages may still be reserved by enclave with
 *                      proper permissions.
 *            ENCLAVE_PAGE_TCS: change the page type to PT_TCS
 * @retval ENCLAVE_ERROR_SUCCESS(0) The operation was successful.
 * @retval ENCLAVE_NOT_SUPPORTED: SGX EDMM is not supported by the system
 * @retval ENCLAVE_LOST: may be returned if the enclave has been removed or if it has not been initialized (via EINIT)
 * @retval ENCLAVE_INVALID_PARAMETER: an invalid combination of flags was provided.
 * @retval ENCLAVE_OUT_OF_MEMORY: No EPC left (some OSes like Linux), or system is out of memory for internal allocation by OS or this function.
 * @retval ENCLAVE_DEVICE_NO_MEMORY: NO EPC left (some OSes like Windows)
 * @retval ENCLAVE_INVALID_ADDRESS: address does not point to an enclave or valid memory within the enclave
 * @retval ENCLAVE_NOT_INITIALIZED: may be returned if the enclave has not been initialized (via EINIT).
 *                                  Some configurations may give ENCLAVE_LOST if the enclave has not been initialized.
 * @retval ENCLAVE_UNEXPECTED, unexpected error.
 */

uint32_t COMM_API enclave_modify(
    COMM_IN uint64_t addr,
    COMM_IN size_t length,
    COMM_IN uint32_t page_properties_from,
    COMM_IN uint32_t page_properties_to)
{
    int ret = ENCLAVE_UNEXPECTED;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_modify for 0x%llX ( %llX ) from 0x%lX to %lX\n",
            addr, length, page_properties_from, page_properties_to);
    if (s_driver_type == SGX_DRIVER_DCAP)
    {
        return ENCLAVE_NOT_SUPPORTED;
    }
    uint64_t enclave_base = (uint64_t)get_enclave_base_address_from_address((void *)addr);
    if (enclave_base == 0)
    {
        return ENCLAVE_INVALID_ADDRESS;
    }
    if (length % SE_PAGE_SIZE != 0)
        return ENCLAVE_INVALID_PARAMETER;
    function<int(int, uint64_t, size_t)> _trim = trim;
    function<int(int, uint64_t, size_t)> _trim_accept = trim_accept;
    function<int(int, uint64_t, size_t)> _mktcs = mktcs;
    function<int(int, uint64_t, size_t, int)> _emodpr = emodpr;
    int fd = get_file_handle_from_address((void *)addr);
    if (s_driver_type == SGX_DRIVER_OUT_OF_TREE)
    {
        _trim = trim_legacy;
        _trim_accept = trim_accept_legacy;
        _mktcs = mktcs_legacy;
        _emodpr = emodpr_legacy;
        fd = s_hdevice;
    }
    if(fd == -1) return ENCLAVE_INVALID_ADDRESS;

    int type_to = (page_properties_to & SGX_EMA_PAGE_TYPE_MASK);
    int type_from = (page_properties_from & SGX_EMA_PAGE_TYPE_MASK);
    if (type_from == SGX_EMA_PAGE_TYPE_TRIM && type_to != SGX_EMA_PAGE_TYPE_TRIM)
    {
        return ENCLAVE_INVALID_PARAMETER;
    }
    int prot_to = (page_properties_to & PROT_MASK);
    int prot_from = (page_properties_from & PROT_MASK);
    if ((prot_to != prot_from) && (type_to != type_from))
    {
        return ENCLAVE_INVALID_PARAMETER;
    }

    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_TRIM))
    {
        //user space can only do EACCEPT for PT_TRIM type
        ret = _trim_accept(fd, addr, length);
        if (ret)
            return error_driver2api(-1, ret);
        if (prot_to == PROT_NONE)
        {
            //EACCEPT done and notified.
            //if user wants to remove permissions,
            //only mprotect is needed
            ret = mprotect((void *)addr, length, prot_to);
            if (ret == -1)
                return error_driver2api(ret, errno);
        }
        return ret;
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TRIM)
    {
        assert(type_from != SGX_EMA_PAGE_TYPE_TRIM);
        if (prot_to != prot_from)
            return ENCLAVE_INVALID_PARAMETER;
        ret = _trim(fd, addr, length);
        if (ret)
            return error_driver2api(-1, ret);
        return 0;
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TCS)
    {
        if (type_from != SGX_EMA_PAGE_TYPE_REG)
            return ENCLAVE_INVALID_PARAMETER;
        if ((prot_from != (SGX_EMA_PROT_READ_WRITE)) && prot_to != prot_from)
            return ENCLAVE_INVALID_PARAMETER;
        ret =  _mktcs(fd, addr, length);
        if (ret)
            return error_driver2api(-1, ret);
        return 0;
    }

    if (type_to != type_from)
        return ENCLAVE_INVALID_PARAMETER;

    if (prot_to == prot_from)
    {
        return 0; //nothing to be done.
    }
    // Permissions changes. Only do emodpr for PT_REG pages
    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_MASK) == SGX_EMA_PAGE_TYPE_REG)
    {
        ret = _emodpr(fd, addr, length, prot_to);
        if (ret)
            return error_driver2api(-1, ret);
    }
    else
    {
        return ENCLAVE_INVALID_PARAMETER;
    }
    ret = mprotect((void *)addr, length, prot_to);
    if (ret == -1)
        return error_driver2api(ret, errno);
    return ret;
}
