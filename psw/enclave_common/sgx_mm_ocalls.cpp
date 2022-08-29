
////////////////////////////////////////////////////////////
// OCall impl. These will be part of sgx_enclave_common.cpp
////////////////////////////////////////////////////////////
#include <functional>
using namespace std;
#define PROT_MASK (PROT_READ|PROT_WRITE|PROT_EXEC)

uint32_t COMM_API enclave_alloc(
    COMM_IN void* target_addr,
    COMM_IN size_t target_size,
    COMM_IN uint32_t data_properties,
    COMM_IN uint32_t alloc_flags,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    int ret = ENCLAVE_UNEXPECTED;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_alloc for %p ( %llX ) with alloc flags = 0x%lX\n",
            target_addr, target_size, alloc_flags);

    if (s_driver_type == SGX_DRIVER_DCAP)
    {
        if (enclave_error != NULL)
            *enclave_error = ret;
        return ret;
    }
    if (s_driver_type == SGX_DRIVER_OUT_OF_TREE)
    {
        ret = mprotect(target_addr, target_size, PROT_WRITE | PROT_READ);
        if ((ret != 0) && (enclave_error != NULL))
        {
            *enclave_error = ENCLAVE_UNEXPECTED;
        }
        return ret;
    }
    int enclave_fd = get_file_handle_from_address(target_addr);
    if (enclave_fd == -1)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_ADDRESS;
        return ENCLAVE_INVALID_ADDRESS;
    }
    int map_flags = MAP_SHARED | MAP_FIXED;
    //COMMIT_NOW not supported by  kernel yet
    if (alloc_flags & ENCLAVE_EMA_COMMIT_NOW)
    {
    }
    //CET pages not supported by kernel yet
    int type = data_properties;
    if((type == ENCLAVE_PAGE_SS_FIRST) | (type == ENCLAVE_PAGE_SS_REST))
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return ENCLAVE_NOT_SUPPORTED;
    }
    if((type == ENCLAVE_PAGE_SS_FIRST) && target_size > SE_PAGE_SIZE)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }
    void *out = mmap(target_addr, target_size, PROT_WRITE | PROT_READ, map_flags, enclave_fd, 0);
    if (out == MAP_FAILED)
    {
        ret = errno;
        SE_TRACE(SE_TRACE_WARNING, "mmap failed, error = %d\n", ret);
        ret = error_driver2api(-1, ret);
        if (enclave_error != NULL)
            *enclave_error = ret;
    }
    else
    {
        ret = 0;
    }
    return ret;
}

uint64_t get_offset_for_address(uint64_t target_address)
{
    uint64_t enclave_base_addr = (uint64_t)get_enclave_base_address_from_address((void *)target_address);
    assert(enclave_base_addr != 0);
    assert(target_address >= enclave_base_addr);
    return (uint64_t)target_address - (uint64_t)enclave_base_addr;
}

static int emodt(int fd, void *addr, size_t length, uint64_t type)
{
    struct sgx_enclave_modify_types ioc;
    if (length == 0)
        return EINVAL;

    SE_TRACE(SE_TRACE_DEBUG,
        "MODT for %p ( %llX ), type: 0x%llX\n",
            addr, length, type);
    memset(&ioc, 0, sizeof(ioc));

    ioc.page_type = type;
    ioc.offset = get_offset_for_address((uint64_t)addr);
    ioc.length = length;
    do
    {
        int ret = ioctl(fd, SGX_IOC_ENCLAVE_MODIFY_TYPES, &ioc);

        if (ret && ioc.count == 0 && errno != EBUSY && errno != EAGAIN)
        { //total failure
            int err = errno;
            SE_TRACE(SE_TRACE_WARNING,
                "MODT failed, error = %d for %p ( %llX ), type: 0x%llX\n",
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

static int trim(int fd, void *addr, size_t length)
{
    return emodt(fd, addr, length, (SGX_EMA_PAGE_TYPE_TRIM >> SGX_EMA_PAGE_TYPE_SHIFT));
}
static int mktcs(int fd, void *addr, size_t length)
{

    return emodt(fd, addr, length, (SGX_EMA_PAGE_TYPE_TCS >> SGX_EMA_PAGE_TYPE_SHIFT));
}
static int trim_accept(int fd, void *addr, size_t length)
{
    struct sgx_enclave_remove_pages ioc;
    memset(&ioc, 0, sizeof(ioc));

    SE_TRACE(SE_TRACE_DEBUG,
        "REMOVE for 0x%llX ( %llX )\n",
            addr, length);
    ioc.offset = get_offset_for_address((uint64_t)addr);
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
static int emodpr(int fd, void *addr, size_t length, uint64_t prot)
{
    struct sgx_enclave_restrict_permissions ioc;
    if (length == 0)
        return EINVAL;

    SE_TRACE(SE_TRACE_DEBUG,
        "MODP for 0x%llX ( %llX ), prot: 0x%llX\n",
            addr, length, prot);
    memset(&ioc, 0, sizeof(ioc));

    ioc.permissions = prot;
    ioc.offset = get_offset_for_address((uint64_t)addr);
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

static int trim_accept_legacy(int fd, void *addr, size_t len)
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

static int trim_legacy(int fd, void *fromaddr, uint64_t len)
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

static int mktcs_legacy(int fd, void *tcs_addr, size_t len)
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

static int emodpr_legacy(int fd, void *addr, uint64_t size, uint64_t flag)
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

uint32_t COMM_API enclave_modify(
    COMM_IN void* target_addr,
    COMM_IN size_t target_size,
    COMM_IN uint32_t from_data_properties,
    COMM_IN uint32_t to_data_properties,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    int ret = ENCLAVE_UNEXPECTED;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_modify for %p ( %llX ) from 0x%lX to %lX\n",
            target_addr, target_size, from_data_properties, to_data_properties);
    if (s_driver_type == SGX_DRIVER_DCAP)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return ENCLAVE_NOT_SUPPORTED;
    }
    uint64_t enclave_base = (uint64_t)get_enclave_base_address_from_address(target_addr);
    if (enclave_base == 0)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_ADDRESS;
        return ENCLAVE_INVALID_ADDRESS;
    }
    if (target_size % SE_PAGE_SIZE != 0)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }
    function<int(int, void *, size_t)> _trim = trim;
    function<int(int, void *, size_t)> _trim_accept = trim_accept;
    function<int(int, void *, size_t)> _mktcs = mktcs;
    function<int(int, void *, size_t, int)> _emodpr = emodpr;
    int fd = get_file_handle_from_address(target_addr);
    if (s_driver_type == SGX_DRIVER_OUT_OF_TREE)
    {
        _trim = trim_legacy;
        _trim_accept = trim_accept_legacy;
        _mktcs = mktcs_legacy;
        _emodpr = emodpr_legacy;
        fd = s_hdevice;
    }
    if(fd == -1)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_ADDRESS;
        return ENCLAVE_INVALID_ADDRESS;
    }

    int type_to = (to_data_properties & SGX_EMA_PAGE_TYPE_MASK);
    int type_from = (from_data_properties & SGX_EMA_PAGE_TYPE_MASK);
    if (type_from == SGX_EMA_PAGE_TYPE_TRIM && type_to != SGX_EMA_PAGE_TYPE_TRIM)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }
    int prot_to = (to_data_properties & PROT_MASK);
    int prot_from = (from_data_properties & PROT_MASK);
    if ((prot_to != prot_from) && (type_to != type_from))
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }

    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_TRIM))
    {
        //user space can only do EACCEPT for PT_TRIM type
        ret = _trim_accept(fd, target_addr, target_size);
        if (ret)
        {
            ret = error_driver2api(-1, ret);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
        if (prot_to == PROT_NONE)
        {
            //EACCEPT done and notified.
            //if user wants to remove permissions,
            //only mprotect is needed
            ret = mprotect(target_addr, target_size, prot_to);
            if (ret == -1)
            {
                ret = error_driver2api(ret, errno);
                if (enclave_error != NULL)
                    *enclave_error = ret;
                return ret;
            }
        }
        return ret;
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TRIM)
    {
        assert(type_from != SGX_EMA_PAGE_TYPE_TRIM);
        if (prot_to != prot_from)
        {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_INVALID_PARAMETER;
            return ENCLAVE_INVALID_PARAMETER;
        }
        ret = _trim(fd, target_addr, target_size);
        if (ret)
        {
            ret = error_driver2api(-1, ret);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
        return 0;
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TCS)
    {
        if (type_from != SGX_EMA_PAGE_TYPE_REG)
        {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_INVALID_PARAMETER;
            return ENCLAVE_INVALID_PARAMETER;
        }
        if ((prot_from != (SGX_EMA_PROT_READ_WRITE)) && prot_to != prot_from)
        {
            if (enclave_error != NULL)
                *enclave_error = ENCLAVE_INVALID_PARAMETER;
            return ENCLAVE_INVALID_PARAMETER;
        }
        ret =  _mktcs(fd, target_addr, target_size);
        if (ret)
        {
            ret = error_driver2api(-1, ret);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
        return 0;
    }

    if (type_to != type_from)
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }
    // type_to == type_from
    // this is for emodpr to epcm.NONE, enclave EACCEPT with pte.R
    // separate mprotect is needed to change pte.R to pte.NONE
    if (prot_to == prot_from && prot_to == PROT_NONE)
    {
        ret = mprotect(target_addr, target_size, prot_to);
        if (ret == -1)
        {
            ret = error_driver2api(ret, errno);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
    }

    if (prot_to == prot_from)
    {
        return 0; //nothing to be done.
    }
    // Permissions changes. Only do emodpr for PT_REG pages
    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_MASK) == SGX_EMA_PAGE_TYPE_REG)
    {
        ret = _emodpr(fd, target_addr, target_size, prot_to);
        if (ret)
        {
            ret = error_driver2api(-1, ret);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
    }
    else
    {
        if (enclave_error != NULL)
            *enclave_error = ENCLAVE_INVALID_PARAMETER;
        return ENCLAVE_INVALID_PARAMETER;
    }
    //EACCEPT needs at least pte.R, PROT_NONE case done above.
    if (prot_to != PROT_NONE)
    {
        ret = mprotect((void *)target_addr, target_size, prot_to);
        if (ret == -1)
        {
            ret = error_driver2api(ret, errno);
            if (enclave_error != NULL)
                *enclave_error = ret;
            return ret;
        }
    }
    return ret;
}
