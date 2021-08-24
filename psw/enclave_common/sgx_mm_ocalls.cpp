
////////////////////////////////////////////////////////////
// OCall impl. These will be part of sgx_enclave_common.cpp
////////////////////////////////////////////////////////////
#include <functional>
using namespace std;
#define PROT_MASK (PROT_READ|PROT_WRITE|PROT_EXEC)
/*
 * Call OS to reserve region for EAUG, immediately or on-demand.
 *
 * @param[in] addr Desired page aligned start address, NULL if no desired address.
 * @param[in] length Size of the region in bytes of multiples of page size.
 * @param[in] flags A bitwise OR of flags describing committing mode, committing
 *                     order, address preference, page type. The untrusted side.
 *    implementation should always invoke mmap syscall with MAP_SHARED|MAP_FIXED, and
 *    translate following additional bits to proper parameters invoking mmap or other SGX specific
 *    syscall(s) provided by the kernel.
 *        The flags param of this interface should include exactly one of following for committing mode:
 *            - SGX_EMA_COMMIT_NOW: reserves memory range with SGX_EMA_PROT_READ|SGX_EMA_PROT_WRITE, if supported,
 *                   kernel is given a hint to EAUG EPC pages for the area as soon as possible.
 *            - SGX_EMA_COMMIT_ON_DEMAND: reserves memory range, EPC pages can be EAUGed upon #PF.
 *        ORed with zero or one of the committing order flags:
 *            - SGX_EMA_GROWSDOWN: if supported, a hint given for the kernel to EAUG pages from higher
 *                              to lower addresses, no gaps in addresses above the last committed.
 *            - SGX_EMA_GROWSUP: if supported, a hint given for the kernel to EAUG pages from lower
 *                              to higher addresses, no gaps in addresses below the last committed.
 *        Optionally ORed with one of following page types:
 *             - SGX_EMA_PAGE_TYPE_REG: regular page type. This is the default if not specified.
 *             - SGX_EMA_PAGE_TYPE_SS_FIRST: the first page in shadow stack.
 *             - SGX_EMA_PAGE_TYPE_SS_REST: the rest page in shadow stack.
 * @retval 0 The operation was successful.
 * @retval EINVAL Any parameter passed in is not valid.
 * @retval errno Error as reported by dependent syscalls, e.g., mmap().
 */
extern "C" int COMM_API enclave_alloc(uint64_t addr, size_t length, int flags)
{
    int ret = EINVAL;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_alloc for 0x%llX ( %llX ) with 0x%lX\n",
            addr, length, flags);

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
        return ret;
    int map_flags = MAP_SHARED | MAP_FIXED;
    //!TODO: support COMMIT_NOW when kernel supports
    if (flags & SGX_EMA_COMMIT_NOW)
    {
    }
    //!TODO support CET
    int type = flags & SGX_EMA_PAGE_TYPE_MASK;
    if((type == SGX_EMA_PAGE_TYPE_SS_FIRST) | (type == SGX_EMA_PAGE_TYPE_SS_REST))
        return EFAULT;
    if((type == SGX_EMA_PAGE_TYPE_SS_FIRST) && length > SE_PAGE_SIZE)
        return ret;
    void *out = mmap((void *)addr, length, PROT_WRITE | PROT_READ, map_flags, enclave_fd, 0);
    if (out == MAP_FAILED)
    {
        SE_TRACE(SE_TRACE_WARNING, "mmap failed, error = %d\n", errno);
        ret = errno;
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
    struct sgx_page_modt ioc;
    if (length == 0)
        return EINVAL;
    memset(&ioc, 0, sizeof(ioc));

    SE_TRACE(SE_TRACE_DEBUG,
        "MODT for 0x%llX ( %llX ), type: 0x%llX\n",
            addr, length, type);
    memset(&ioc, 0, sizeof(ioc));
    ioc.type = type;
    ioc.offset = get_offset_for_address(addr);
    ioc.length = SE_PAGE_SIZE;//TODO: change back to length
    do
    {
        int ret = ioctl(fd, SGX_IOC_PAGE_MODT, &ioc);
        //TODO: use error code
        if (ret && ioc.count == 0 && errno != EBUSY)
        { //total failure
            SE_TRACE(SE_TRACE_WARNING,
                "MODT failed, error = %d for 0x%llX ( %llX ), type: 0x%llX\n",
                    errno, addr, length, type);
            return errno;
        }
        ioc.offset += SE_PAGE_SIZE;
        ioc.result = 0;
        ioc.count = 0;
        length -= SE_PAGE_SIZE;
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
    struct sgx_page_remove remove_ioc;
    memset(&remove_ioc, 0, sizeof(remove_ioc));

    SE_TRACE(SE_TRACE_DEBUG,
        "REMOVE for 0x%llX ( %llX )\n",
            addr, length);
    remove_ioc.offset = get_offset_for_address(addr);
    remove_ioc.length = length;

    int ret = ioctl(fd, SGX_IOC_PAGE_REMOVE, &remove_ioc);
    if(ret)
    {
        SE_TRACE(SE_TRACE_WARNING,
            "REMOVE failed, error = %d for 0x%llX ( %llX )\n",
               errno, addr, length);
        return errno;
    }else
    return 0;
}
static int emodpr(int fd, uint64_t addr, size_t length, uint64_t prot)
{
    struct sgx_page_modp ioc;
    if (length == 0)
        return EINVAL;
    memset(&ioc, 0, sizeof(ioc));

    SE_TRACE(SE_TRACE_DEBUG,
        "MODP for 0x%llX ( %llX ), prot: 0x%llX\n",
            addr, length, prot);
    ioc.prot = prot;
    ioc.offset = get_offset_for_address(addr);
    ioc.length = length;

    do
    {
        int ret = ioctl(fd, SGX_IOC_PAGE_MODP, &ioc);
        //TODO: use error code
        if (ret && ioc.count == 0 && errno != EBUSY )
        { //total failure
            SE_TRACE(SE_TRACE_WARNING,
                "MODP failed, error = %d for 0x%llX ( %llX ), prot: 0x%llX\n",
                    errno, addr, length, prot);
            return errno;
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
 * @param[in] flags_from The original EPCM flags of the EPC pages to be modified.
 *            Must be bitwise OR of following:
 *            SGX_EMA_PROT_READ
 *            SGX_EMA_PROT_WRITE
 *            SGX_EMA_PROT_EXEC
 *            SGX_EMA_PAGE_TYPE_REG: regular page, changeable to TRIM or TCS
 *            SGX_EMA_PAGE_TYPE_TRIM: signal to the kernel EACCEPT is done for TRIM pages.
 * @param[in] flags_to The target EPCM flags. This must be bitwise OR of following:
 *            SGX_EMA_PROT_READ
 *            SGX_EMA_PROT_WRITE
 *            SGX_EMA_PROT_EXEC
 *            SGX_EMA_PAGE_TYPE_TRIM: change the page type to PT_TRIM. Note the address
 *                      range for trimmed pages may still be reserved by enclave with
 *                      proper permissions.
 *            SGX_EMA_PAGE_TYPE_TCS: change the page type to PT_TCS
 * @retval 0 The operation was successful.
 * @retval EINVAL A parameter passed in is not valid.
 * @retval errno Error as reported by dependent syscalls, e.g., mprotect().
 */

extern "C" int COMM_API enclave_modify(uint64_t addr, size_t length, int flags_from, int flags_to)
{
    int ret = EFAULT;
    SE_TRACE(SE_TRACE_DEBUG,
        "enclave_modify for 0x%llX ( %llX ) from 0x%lX to %lX\n",
            addr, length, flags_from, flags_to);
    if (s_driver_type == SGX_DRIVER_DCAP)
    {
        return ret;
    }
    uint64_t enclave_base = (uint64_t)get_enclave_base_address_from_address((void *)addr);
    if (enclave_base == 0)
    {
        return EINVAL;
    }
    if (length % SE_PAGE_SIZE != 0)
        return EINVAL;
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
    if(fd == -1) return EINVAL;

    int type_to = (flags_to & SGX_EMA_PAGE_TYPE_MASK);
    int type_from = (flags_from & SGX_EMA_PAGE_TYPE_MASK);
    if (type_from == SGX_EMA_PAGE_TYPE_TRIM && type_to != SGX_EMA_PAGE_TYPE_TRIM)
    {
        return EINVAL;
    }
    int prot_to = (flags_to & PROT_MASK);
    int prot_from = (flags_from & PROT_MASK);
    if ((prot_to != prot_from) && (type_to != type_from))
    {
        return EINVAL;
    }

    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_TRIM))
    {
        //user space can only do EACCEPT for PT_TRIM type
        ret = _trim_accept(fd, addr, length);
        if (ret)
            return ret;
        if (prot_to == PROT_NONE)
        {
            //EACCEPT done and notified.
            //if user wants to remove permissions,
            //only mprotect is needed
            ret = mprotect((void *)addr, length, prot_to);
            if (ret == -1)
                return ret;
        }
        return ret;
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TRIM)
    {
        assert(type_from != SGX_EMA_PAGE_TYPE_TRIM);
        if (prot_to != prot_from)
            return EINVAL;
        //user must be able to  do EACCEPT
        if (prot_to == PROT_NONE)
            return EINVAL;
        return _trim(fd, addr, length);
    }

    if (type_to == SGX_EMA_PAGE_TYPE_TCS)
    {
        if (type_from != SGX_EMA_PAGE_TYPE_REG)
            return EINVAL;
        if ((prot_from != (SGX_EMA_PROT_READ_WRITE)) && prot_to != prot_from)
            return EINVAL;
        return _mktcs(fd, addr, length);
    }

    if (type_to != type_from)
        return EINVAL;
    // type_to == type_from
    // this is for emodpr to epcm.NONE, enclave EACCEPT with pte.R
    // separate mprotecte is needed to change ptt.R to pte.NONE
    if (prot_to == prot_from && prot_to == PROT_NONE)
    {
        ret = mprotect((void *)addr, length, prot_to);
        if (ret == -1)
            return errno;
    }

    if (prot_to == prot_from)
    {
        return 0; //nothing to be done.
    }
    // Permissions changes. Only do emodpr for PT_REG pages
    if ((type_from & type_to & SGX_EMA_PAGE_TYPE_MASK) == SGX_EMA_PAGE_TYPE_REG)
    {
        ret = _emodpr(fd, addr, length, prot_to);
        if (ret)
            return ret;
    }
    else
    {
        return EINVAL;
    }
    //EACCEPT needs at least pte.R, PROT_NONE case done above.
    if (prot_to != PROT_NONE)
    {
        ret = mprotect((void *)addr, length, prot_to);
        if (ret == -1)
            return errno;
    }
    return ret;
}
