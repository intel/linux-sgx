SGX Enclave Memory Manager
=================================

## Introduction ##

An enclave's memory is backed by a special reserved region in RAM, called
Enclave Page Cache (EPC). Enclave memory management tasks include
allocating/reserving virtual address ranges, committing physical EPC pages,
changing EPC page permissions or page types, and removing EPC pages.
Those tasks require collaboration between the trusted runtime, the untrusted
runtime, and the OS. The SGX enclave memory manager (EMM) serves as a central
component in the enclave trusted runtime that abstracts the interaction with
the untrusted runtime for all memory management flows and provides APIs for
its clients to reserve virtual address ranges, commit EPC memory to the reserved
address ranges, and modify attributes of the reserved/committed pages.

For details of specific memory management related flows, please refer to
[the SGX EDMM driver API spec](SGX_EDMM_driver_interface.md).

As shown in the figure below,  the EMM provides a set of public APIs to be invoked
by upper layer components for specific usages, such as dynamic heap/stack, mmap,
mprotect, higher level language JIT compiler, etc. Another goal of this design is
to make the EMM implementation portable across different runtimes such as
Intel SGX SDK and OpenEnclave. To achieve that, it requires the runtimes to implement
a runtime abstraction layer with APIs defined in this document. The main purpose of
the abstraction layer is to provide an OCall bridge to the enclave common loader outside
the enclave, which interacts with the OS to support the EDMM flows.

![SGX2 EMM architecture](images/SGX2_emm_arch.svg)


**Note:**  As the EMM is a component inside enclave, it should not have direct OS dependencies.
However, the design proposed in this document only considers call flows and semantics for Linux.
And the OCall implementation in enclave common loader is currently specified for Linux only though
similar implementation is possible on other OSes. 


## User Experience ##

**Porting EMM to Different Runtimes**

To port EMM implementation portable across different SGX enclave runtimes, e.g., the Open Enclave and Intel SGX SDKs,
the runtimes needs to implement the runtime abstraction layer APIs. These APIs  encapsulate runtime specific support
such as making OCalls, registering callbacks on page faults, on which the EMM implementation relies to collaborate with the OS.

Additionally, the runtime needs to properly initialize the EMM and reserve its own regions using the private APIs
as described in the section on [Support for EMM Initialization](#support-for-emm-initialization).  

The EMM source code will be hosted and maintained in the [Intel SGX PSW and SDK repository](https://github.com/intel/linux-sgx).
The EMM can be built as a separate library then linked into any runtime that implements the abstraction layer APIs.

**Allocate, Deallocate Enclave Memory**

The EMM provides an API, sgx_mm_alloc, for its clients to request enclave memory
allocations. An enclave memory allocation represents both a reserved virtual
address range and a commitment of EPC pages.  EPC pages are committed for
enclaves via special SGX instructions: loaded by EADD/EEXTEND before EINIT
or dynamically added using EAUG followed by EACCEPT.

The sgx_mm_alloc API allows clients to specify one of three committing modes
for an allocation:
- SGX_EMA_RESERVE, only the virtual address range is reserved. No EPC pages will
be committed in this mode.
- SGX_EMA_COMMIT_NOW: reserves and commits physical EPC upon allocation.
EACCEPT will be done immediately on SGX2 platforms.
- SGX_EMA_COMMIT_ON_DEMAND: EACCEPT is done on demand, see below on committing
and uncommitting.

An allocation, once created, will own its address range until the deallocation
API, sgx_mm_dealloc, is called upon. No two active allocations can have
overlapping address ranges.

**Commit, Uncommit Enclave Memory**

When a page in COMMIT_ON_DEMAND allocations is accessed, a page fault occurs if
the page was not yet committed.  The EMM will perform EACCEPT to commit the EPC
page on page fault after OS doing EAUG.

The clients can also call the EMM commit API, sgx_mm_commit, to proactively
commit specific sub-regions in a COMMIT_ON_DEMAND allocation to avoid
future page fault.

Some EMM clients, <i>e.g.</i>, a dynamic code loader wishing to load code on
page faults, can register a custom handler for page faults at the time of
allocation request. In the custom page fault handler, it can invoke an API,
sgx_mm_commit_data, to commit and load data to newly committed EPC page at
the same time as supported by EACCEPTCOPY.

Committed pages will stay committed (regardless how they were committed) until
the clients calls the uncommit API, sgx_mm_uncommit, on them or the allocation
they belong to is deallocated by sgx_mm_dealloc.

**Modify Page Attributes**

The EMM clients may call sgx_mm_modify_permissions/sgx_mm_modify_type to request permissions
or page type changes for pages in existing allocations.

## Notes on Internal Design ##

The enclave memory manager keeps track of memory allocation and layout info inside
enclave address range (ELRANGE) using an internal structure called the Enclave Memory
Area (EMA) List. The EMA and the EMA list are considered private data structures of the memory
manager, and their internals are not exposed in client-facing APIs.
- The EMA list tracks all memory regions in use (reserved, committed,
commit-on-demand) in ELRANGE.
- Ranges in ELRANGE not tracked by an EMA are considered free and ready for new allocations.
- The EMM labels certain EMAs reserved for runtime or its internal usage and make them
not accessible from public APIs.
- A thread calling an EMM API on an EMA with an operation pending in another thread will wait
until the pending operation is finished.

**Assumptions:**

- When an enclave is loaded, the OS reserves the whole address range covered by ELRANGE.
It is assumed the host app will not remap any part of this reserved range.
- When an enclave is loaded with base address at zero, only a partial ELRANGE may be
  reserved by the OS. In that case, the EMM will assume the partial ELRANGE as a valid reserved
  range for use inside the enclave.
  - The runtime can setup the partial valid range in ELRANGE by marking the unusable range up front
  as SGX_EMA_RESERVE using the EMM private EMA_allocate API.
- The memory manager does not check EPC pressure, or proactively trim pages when EPC runs low.
The OS can reclaim EPC pages when EPC running low or cgroups threshold reached
- The memory manager does not maintain and recycle committed then freed pages
  - Whenever a page is freed (via dealloc or uncommit API), it is trimmed from the enclave
  and needs to be re-allocated and committed before re-use.
  - The owner of a region can re-purpose a sub-region of it by calling sgx_mm_modify_type/permissions
  to split out the sub-region to be reused.
- The memory manager does not call back into the client for #GP handling. Memory manager code will ensure that
itself would not cause #GP, and only register a #PF handler with the enclave global exception
handler registry through the runtime abstraction layer. A client wishing to handle #GP can register
its own exception handler with the global handler registry.
- The memory manager is implemented on SGX2 platforms only. 

Public APIs
-----------------

### sgx_mm_alloc

Allocate a new memory region inside enclave and optionally register a custom page fault handler
for the region

```
/**
 * Page fault (#PF) info reported in the SGX SSA MISC region.
 */
typedef struct _sgx_pfinfo
{
    uint64_t maddr; // address for #PF.
    union _pfec
    {
        uint32_t errcd;
        struct
        {                     // PFEC bits.
            uint32_t p : 1;   // P flag.
            uint32_t rw : 1;  // RW access flag, 0 for read, 1 for write.
            uint32_t : 13;    // U/S, I/O, PK and reserved bits not relevant for SGX PF.
            uint32_t sgx : 1; // SGX bit.
            uint32_t : 16;    // reserved bits.
        };
    } pfec;
    uint32_t reserved;
} sgx_pfinfo;

/* Return value used by the EMM #PF handler to indicate
 *  to the dispatcher that it should continue searching for the next handler.
 */
#define SGX_MM_EXCEPTION_CONTINUE_SEARCH 0

/* Return value used by the EMM #PF handler to indicate
 *  to the dispatcher that it should stop searching and continue execution.
 */
#define SGX_MM_EXCEPTION_CONTINUE_EXECUTION -1


/*
 * Custom page fault (#PF) handler, do usage specific processing upon #PF,
 * e.g., loading data and verify its trustworthiness, then call sgx_mm_commit_data
 * to explicitly EACCEPTCOPY data.
 * This custom handler is passed into sgx_mm_alloc, and associated with the
 * newly allocated region. The memory manager calls the handler when a #PF
 * happens in the associated region. The handler may invoke abort() if it
 * determines the exception is invalid based on certain internal states
 * it maintains.
 *
 * @param[in] pfinfo info reported in the SSA MISC region for page fault.
 * @param[in] private_data private data provided by handler in sgx_mm_alloc call.
 * @retval SGX_MM_EXCEPTION_CONTINUE_EXECUTION Success on handling the exception.
 * @retval SGX_MM_EXCEPTION_CONTINUE_SEARCH Exception not handled and should be passed to
 *         some other handler.
 *
 */
typedef int (*sgx_enclave_fault_handler_t)(const sgx_pfinfo *pfinfo, void *private_data);

/* bit 0 - 7 are allocation flags. */
#define SGX_EMA_ALLOC_FLAGS_SHIFT 0
#define SGX_EMA_ALLOC_FLAGS(n) (((unsigned int)(n) << SGX_EMA_ALLOC_FLAGS_SHIFT))
#define SGX_EMA_ALLOC_FLAGS_MASK    SGX_EMA_ALLOC_FLAGS(0xFF)

/* Only reserve an address range, no physical memory committed.*/
#define SGX_EMA_RESERVE             SGX_EMA_ALLOC_FLAGS(1)

/* Reserve an address range and commit physical memory. */
#define SGX_EMA_COMMIT_NOW          SGX_EMA_ALLOC_FLAGS(2)

/* Reserve an address range and commit physical memory on demand.*/
#define SGX_EMA_COMMIT_ON_DEMAND    SGX_EMA_ALLOC_FLAGS(4)

/* Always commit pages from higher to lower addresses,
 *  no gaps in addresses above the last committed.
 */
#define SGX_EMA_GROWSDOWN           SGX_EMA_ALLOC_FLAGS(0x10)

/* Always commit pages from lower to higher addresses,
 * no gaps in addresses below the last committed.
*/
#define SGX_EMA_GROWSUP  SGX_EMA_ALLOC_FLAGS(0x20)

/* Map addr must be exactly as requested. */
#define SGX_EMA_FIXED SGX_EMA_ALLOC_FLAGS(0x40)

/* bit 8 - 15 are page types. */
#define SGX_EMA_PAGE_TYPE_SHIFT 8
#define SGX_EMA_PAGE_TYPE(n) ((n) << SGX_EMA_PAGE_TYPE_SHIFT)
#define SGX_EMA_PAGE_TYPE_MASK      SGX_EMA_PAGE_TYPE(0xFF)
#define SGX_EMA_PAGE_TYPE_TCS       SGX_EMA_PAGE_TYPE(0x1)  /* TCS page type. */
#define SGX_EMA_PAGE_TYPE_REG       SGX_EMA_PAGE_TYPE(0x2)  /* regular page type, default if not specified. */
#define SGX_EMA_PAGE_TYPE_TRIM      SGX_EMA_PAGE_TYPE(0x4)  /* TRIM page type. */
#define SGX_EMA_PAGE_TYPE_SS_FIRST  SGX_EMA_PAGE_TYPE(0x5)  /* the first page in shadow stack. */
#define SGX_EMA_PAGE_TYPE_SS_REST   SGX_EMA_PAGE_TYPE(0x6)  /* the rest pages in shadow stack. */

/* Use bit 24-31 for alignment masks. */
#define SGX_EMA_ALIGNMENT_SHIFT 24
/*
 * Alignment (expressed in log2).  Must be >= log2(PAGE_SIZE) and
 * < # bits in a pointer (32 or 64).
 */
#define SGX_EMA_ALIGNED(n) (((unsigned int)(n) << SGX_EMA_ALIGNMENT_SHIFT))
#define SGX_EMA_ALIGNMENT_MASK SGX_EMA_ALIGNED(0xFFUL)
#define SGX_EMA_ALIGNMENT_64KB SGX_EMA_ALIGNED(16UL)
#define SGX_EMA_ALIGNMENT_16MB SGX_EMA_ALIGNED(24UL)
#define SGX_EMA_ALIGNMENT_4GB SGX_EMA_ALIGNED(32UL)

/* Permissions flags */
#define SGX_EMA_PROT_NONE   0x0
#define SGX_EMA_PROT_READ       0x1
#define SGX_EMA_PROT_WRITE      0x2
#define SGX_EMA_PROT_EXEC       0x4
#define SGX_EMA_PROT_READ_WRITE (SGX_EMA_PROT_READ|SGX_EMA_PROT_WRITE)
#define SGX_EMA_PROT_READ_EXEC (SGX_EMA_PROT_READ|SGX_EMA_PROT_EXEC)
#define SGX_EMA_PROT_READ_WRITE_EXEC (SGX_EMA_PROT_READ_WRITE|SGX_EMA_PROT_EXEC)
/*
 * Allocate a new memory region in enclave address space (ELRANGE).
 * @param[in] addr Starting address of the region, page aligned. If NULL is provided,
 *                  then the function will select the starting address.
 * @param[in] length Size of the region in bytes of multiples of page size.
 * @param[in] flags A bitwise OR of flags describing committing mode, committing
 * order, address preference, and page type.
 *        Flags should include exactly one of following for committing mode:
 *            - SGX_EMA_RESERVE: just reserve an address range, no EPC committed.
 *                           To allocate memory on a reserved range, call this
 *                           function again with SGX_EMA_COMMIT_ON_DEMAND or SGX_EMA_COMMIT_NOW.
 *            - SGX_EMA_COMMIT_NOW: reserves memory range and commit EPC pages. EAUG and
 *                              EACCEPT are done on SGX2 platforms.
 *            - SGX_EMA_COMMIT_ON_DEMAND: reserves memory range, EPC pages
 *                              are committed (EACCEPT) on demand upon #PF on SGX2 platforms.
 *        ORed with zero or one of the committing order flags for SGX2 platforms:
 *            - SGX_EMA_GROWSDOWN: always commit pages from higher to lower addresses,
 *                             no gaps in addresses above the last committed.
 *            - SGX_EMA_GROWSUP: always commit pages from lower to higher addresses,
 *                             no gaps in addresses below the last committed.
 *        Optionally ORed with
 *            -  SGX_EMA_FIXED: allocate at fixed address, will return error if the
 *                           requested address is in use.
 *            -  SGX_EMA_ALIGNED(n):	Align the region on a requested	boundary.
 *                           Fail if a suitable region cannot be found,
 *                           The argument n specifies the binary logarithm of
 *                           the desired alignment and must be at least 12.
 *        Optionally ORed with one of following page types:
 *             - SGX_EMA_PAGE_TYPE_REG: regular page type. This is the default if not specified.
 *             - SGX_EMA_PAGE_TYPE_SS_FIRST: the first page in shadow stack.
 *             - SGX_EMA_PAGE_TYPE_SS_REST: the rest page in shadow stack.
 *
 * @param[in] handler A custom handler for page faults in this region, NULL if
 *                     no custom handling needed.
 * @param[in] handler_private Private data for the @handler, which will be passed
 *                     back when the handler is called.
 * @param[out] out_addr Pointer to store the start address of allocated range.
 *                     Set to valid address by the function on success, NULL otherwise.
 * @retval 0 The operation was successful.
 * @retval EACCES Region is outside enclave address space.
 * @retval EEXIST Any page in range requested is in use and SGX_EMA_FIXED is set.
 * @retval EINVAL Invalid alignment bouandary, i.e., n < 12 in SGX_EMA_ALIGNED(n).
 * @retval ENOMEM Out of memory, or no free space to satisfy alignment boundary.
 */
int sgx_mm_alloc(void *addr, size_t length, int flags,
                 sgx_enclave_fault_handler_t handler, void *handler_private,
                 void **out_addr);

```

**Remarks:**
- Permissions of newly allocated regions are always SGX_EMA_PROT_READ|SGX_EMA_PROT_WRITE and of page
    type SGX_EMA_PAGE_TYPE_REG, except for SGX_EMA_RESERVE mode regions which will have SGX_EMA_PROT_NONE.
- Once allocated by sgx_mm_alloc, a region will stay in the allocated state and become
    deallocated once sgx_mm_dealloc is called.
- If sgx_mm_dealloc on a partial range of a previously allocated region, then the
    region is split, and the freed range is deallocated. The remainder of the
    region stays allocated.
- If all pages in the region are freed by sgx_mm_dealloc, then the whole region
    is released, and the memory manager no longer tracks the region.


### sgx_mm_uncommit and sgx_mm_dealloc

```
/*
 * Uncommit (trim) physical EPC pages in a previously committed range.
 * The pages in the allocation are freed, but the address range is still reserved.
 * @param[in] addr Page aligned start address of the region to be trimmed.
 * @param[in] length Size in bytes of multiples of page size.
 * @retval 0 The operation was successful.
 * @retval EINVAL The address range is not allocated or outside enclave.
 */
int sgx_mm_uncommit(void *addr, size_t length);

/*
 * Deallocate the address range.
 * The pages in the allocation are freed and the address range is released for future allocation.
 * @param[in] addr Page aligned start address of the region to be freed and released.
 * @param[in] length Size in bytes of multiples of page size.
 * @retval 0 The operation was successful.
 * @retval EINVAL The address range is not allocated or outside enclave.
 */
int sgx_mm_dealloc(void *addr, size_t length);

```

### sgx_mm_modify_type, sgx_mm_modify_permissions

```
/*
 * Change permissions of an allocated region.
 * @param[in] addr Start address of the region, must be page aligned.
 * @param[in] length Size in bytes of multiples of page size.
 * @param[in] prot permissions bitwise OR of following with:
 *        - SGX_EMA_PROT_READ: Pages may be read.
 *        - SGX_EMA_PROT_WRITE: Pages may be written.
 *        - SGX_EMA_PROT_EXEC: Pages may be executed.
 * @retval 0 The operation was successful.
 * @retval EACCES Original page type can not be changed to target type.
 * @retval EINVAL The memory region was not allocated or outside enclave
 *                or other invalid parameters that are not supported.
 * @retval EPERM The request permissions are not allowed, e.g., by target page type or
 *               SELinux policy.
 */
int sgx_mm_modify_permissions(void *addr, size_t length, int prot);

/*
 * Change the page type of an allocated region.
 * @param[in] addr Start address of the region, must be page aligned.
 * @param[in] length Size in bytes of multiples of page size.
 * @param[in] type page type, only SGX_EMA_PAGE_TYPE_TCS is supported.
 *
 * @retval 0 The operation was successful.
 * @retval EACCES Original page type can not be changed to target type.
 * @retval EINVAL The memory region was not allocated or outside enclave
 *                or other invalid parameters that are not supported.
 * @retval EPERM  Target page type is no allowed by this API, e.g., PT_TRIM,
 *               PT_SS_FIRST, PT_SS_REST.
 */
int sgx_mm_modify_type(void *addr, size_t length, int type);

```
**Remarks:**
- The memory manager will track current permissions for each region, and can
    determine whether new permissions require an OCall for EMODPR, e.g., RW<->RX, RW->R.
- These APIs should not be used to change EPC page type to PT_TRIM. Trimming pages
    are done by sgx_mm_uncommit and sgx_mm_dealloc only.


### sgx_mm_commit

```

/*
 * Commit a partial or full range of memory allocated previously with SGX_EMA_COMMIT_ON_DEMAND.
 * The API will return 0 if all pages in the requested range are successfully committed.
 * Calling this API on pages already committed has no effect.
 * @param[in] addr Page aligned starting address.
 * @param[in] length Length of the region in bytes of multiples of page size.
 * @retval 0 The operation was successful.
 * @retval EINVAL Any requested page is not in any previously allocated regions, or
 *                 outside the enclave address range.
 * @retval EFAULT All other errors.
 */
int sgx_mm_commit(void *addr, size_t length);

```

### sgx_mm_commit_data

```

/*
 * Load data into target pages within a region previously allocated by sgx_mm_alloc.
 * This can be called to load data and set target permissions at the same time,
 * e.g., dynamic code loading. The caller has verified data to be trusted and expected
 * to be loaded to the target address range. Calling this API on pages already committed
 * will fail.
 *  
 * @param[in] addr Page aligned target starting addr.
 * @param[in] length Length of data, in bytes of multiples of page size.
 * @param[in] data Data of @length.
 * @param[in] prot Target permissions.
 * @retval 0 The operation was successful.
 * @retval EINVAL Any page in requested address range is not previously allocated, or
 *                outside the enclave address range.
 * @retval EPERM Any page in requested range is previously committed.
 * @retval EPERM The target permissions are not allowed by OS security policy,
 *                  e.g., SELinux rules.
 */
int sgx_mm_commit_data(void *addr, size_t length, uint8_t *data, int prot);

```
**Remarks:**
- The memory manager decides whether OCalls are needed to ask the OS to make Page Table Entry (PTE)
permissions changes. No separate sgx_mm_modify_permissions call is needed.

Runtime Abstraction Layer
----------------------------------

To support and use the EMM, an SGX trusted runtime shall implement following
abstraction layer APIs.

### Exception Handler Registration

```
/*
 * The EMM page fault (#PF) handler.
 *
 * @param[in] pfinfo Info reported in the SSA MISC region for page fault.
 * @retval SGX_EXCEPTION_CONTINUE_EXECUTION Success handling the exception.
 * @retval SGX_EXCEPTION_CONTINUE_SEARCH The EMM does not handle the exception.
 */
typedef int (*sgx_mm_pfhandler_t)(const sgx_pfinfo *pfinfo);

/*
 * Register the EMM handler with the global exception handler registry
 * The Runtime should ensure this handler is called first in case of
 * a #PF before all other handlers.
 *
 * @param[in] pfhandler The EMM page fault handler.
 * @retval true Success.
 * @retval false Failure.
 */
bool sgx_mm_register_pfhandler(sgx_mm_pfhandler_t pfhandler);

/*
 * Unregister the EMM handler with the global exception handler registry.
 * @param[in] pfhandler The EMM page fault handler.
 * @retval true Success.
 * @retval false Failure.
 */
bool sgx_mm_unregister_pfhandler(sgx_mm_pfhandler_t pfhandler);

```

### OCalls

```
/*
 * Call OS to reserve region for EAUG, immediately or on-demand.
 *
 * @param[in] addr Desired page aligned start address.
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
int sgx_mm_alloc_ocall(uint64_t addr, size_t length, int flags);

/*
 * Call OS to change permissions, type, or notify EACCEPT done after TRIM.
 *
 * @param[in] addr Start address of the memory to change protections.
 * @param[in] length Length of the area.  This must be a multiple of the page size.
 * @param[in] flags_from The original EPCM flags of the EPC pages to be modified.
 *              Must be bitwise OR of following:
 *            SGX_EMA_PROT_READ
 *            SGX_EMA_PROT_WRITE
 *            SGX_EMA_PROT_EXEC
 *            SGX_EMA_PAGE_TYPE_REG: regular page, changeable to TRIM and TCS
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

int sgx_mm_modify_ocall(uint64_t addr, size_t length, int flags_from, int flags_to);

```

### Other Utilities

```
/*
 * Define a mutex and create/lock/unlock/destroy functions.
 */
typedef struct _sgx_mm_mutex sgx_mm_mutex;
sgx_mm_mutex *sgx_mm_mutex_create(void);
int sgx_mm_mutex_lock(sgx_mm_mutex *mutex);
int sgx_mm_mutex_unlock(sgx_mm_mutex *mutex);
int sgx_mm_mutex_destroy(sgx_mm_mutex *mutex);

/*
 * Check whether the given buffer is strictly within the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly within the enclave's memory. If so, return true. If any
 * portion of the buffer lies outside the enclave's memory, return false.
 *
 * @param[in] ptr The pointer to the buffer.
 * @param[in] size The size of the buffer.
 *
 * @retval true The buffer is strictly within the enclave.
 * @retval false At least some part of the buffer is outside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool sgx_mm_is_within_enclave(const void *ptr, size_t size);

```

### Support for EMM Initialization

In addition to implement the abstraction layer APIs, a runtime shall provide
iniitial enclave memory layout information to the EMM during early
initialization phase of the enclave.
The memory manager must be initialized in the first ECALL (ECMD_INIT_ENCLAVE in
Intel SGX SDK) before any other clients can use it. Therefore, code and data
of the memory manager will be part of initial enclave image that are loaded
with EADD before EINIT, and as a part of the trusted runtime.

To initialize EMM internals, the trusted runtime should first invoke sgx_mm_init,
passing in an address range available for non-system or so-called user allocations.

```
/*
 * Initialize the EMM internals and reserve the whole range available for user
 * allocations via the public sgx_mm_alloc API. This should be called before
 * any other APIs invoked. The runtime should not intend to allocate any subregion
 * in [user_start, user_end) for system usage, i.e., the EMM will fail any allocation
 * request with SGX_EMA_SYSTEM flag in this range and return an EINVAL error.
 * @param[in] user_start The start of the user address range, page aligned.
 * @param[in] user_end The end (exclusive) of the user address range, page aligned.
 */
void sgx_mm_init(size_t user_start, size_t user_end);
```

The EMM consumes some minimal amount of memory to store the EMA objects for
book keeping of all allocations. During initialization, the EMM reserves an initial area
in the user range for those internal use. And it would allocate more of such reserves on
demand as EMAs created for allocation requests and the active reserves run out. The size
of the user range accomodate this internal consumption overhead, which can be estimated as
the total size of all regions to be tracked (both system and expected user allocations)
divided by 2^14. At runtime, in case the EMM could not find space to allocate EMA objects
then its API would return ENOMEM.

After initialization, the trusted runtime should enumerate all initial committed regions (code,
data, heap, stack, TCS, and SSA), and call the EMM private APIs to set up
initial entries in the EMA list to track existing regions. These regions
are typically created by the enclave loader at predetermined locations and
some are loaded with content from the enclave image. Thus it's necessary to
reserve their ranges this way so that they won't be modifiable by EMM public APIs.

### EMM Private APIs for Trusted Runtimes
These private APIs can be used by the trusted runtime to reserve and allocate
regions not accessible from public APIs. They have the identical signature
as the public API counterparts and replace "sgx_mm_" prefix with "mm_" prefix.
The main difference is that the private mm_alloc allows an extra flag
SGX_EMA_SYSTEM passed in.

```

#define SGX_EMA_SYSTEM SGX_EMA_ALLOC_FLAGS(0x80) /* EMA reserved by system */

/*
 * Initialize an EMA. This can be used to setup EMAs to account regions that
 * are loaded and initialized with EADD before EINIT.
 * @param[in] addr Starting address of the region, page aligned. If NULL is provided,
 *                  then the function will select the starting address.
 * @param[in] size Size of the region in multiples of page size in bytes.
 * @param[in] flags SGX_EMA_SYSTEM, or SGX_EMA_SYSTEM | SGX_EMA_RESERVE
 *           bitwise ORed with one of following page types:
 *             - SGX_EMA_PAGE_TYPE_REG: regular page type. This is the default if not specified.
 *             - SGX_EMA_PAGE_TYPE_TCS: TCS page.
 *             - SGX_EMA_PAGE_TYPE_SS_FIRST: the first page in shadow stack.
 *             - SGX_EMA_PAGE_TYPE_SS_REST: the rest page in shadow stack.
 * @param[in] prot permissions, either SGX_EMA_PROT_NONE or a bitwise OR of following with:
 *        - SGX_EMA_PROT_READ: Pages may be read.
 *        - SGX_EMA_PROT_WRITE: Pages may be written.
 *        - SGX_EMA_PROT_EXEC: Pages may be executed.
 * @param[in] handler A custom handler for page faults in this region, NULL if
 *                     no custom handling needed.
 * @param[in] handler_private Private data for the @handler, which will be passed
 *                     back when the handler is called.
 * @retval 0 The operation was successful.
 * @retval EACCES Region is outside enclave address space.
 * @retval EEXIST Any page in range requested is in use.
 * @retval EINVAL Invalid page type, flags, or addr and length are not page aligned.
 */
int mm_init_ema(void *addr, size_t size, int flags, int prot,
                  sgx_enclave_fault_handler_t handler,
                  void *handler_private);
/**
 * Same as sgx_mm_alloc, SGX_EMA_SYSTEM can be OR'ed with flags to indicate
 * that the EMA can not be modified thru public APIs.
 */
int mm_alloc(void *addr, size_t size, uint32_t flags,
              sgx_enclave_fault_handler_t handler, void *private_data, void** out_addr);
int mm_dealloc(void *addr, size_t size);
int mm_uncommit(void *addr, size_t size);
int mm_commit(void *addr, size_t size);
int mm_commit_data(void *addr, size_t size, uint8_t *data, int prot);
int mm_modify_type(void *addr, size_t size, int type);
int mm_modify_permissions(void *addr, size_t size, int prot);

```

Internal APIs and Structures
-------------------------------------

The following are internal functions and structures to be used by the EMM implementation.
They can evolve over time, and are shown here for reference only.

### Enclave Memory Area (EMA) struct

Each enclave has a global doubly linked EMA list to keep track of all dynamically
allocated regions in enclave address space (ELRANGE).

```
typedef struct _ema_t {
    size_t              start_addr;     // starting address, should be on a page boundary.
    size_t              size;           // in bytes of multiples of page size.
    uint32_t            alloc_flags;    // SGX_EMA_RESERVE, SGX_EMA_COMMIT_NOW, SGX_EMA_COMMIT_ON_DEMAND,
                                        // OR'ed with SGX_EMA_SYSTEM, SGX_EMA_GROWSDOWN, ENA_GROWSUP.
    uint64_t            si_flags;       // SGX_EMA_PROT_NONE, SGX_EMA_PROT_READ |{SGX_EMA_PROT_WRITE, SGX_EMA_PROT_EXEC}.
                                        // Or'd with one of SGX_EMA_PAGE_TYPE_REG, SGX_EMA_PAGE_TYPE_TCS, SGX_EMA_PAGE_TYPE_TRIM.
    ema_bit_array*      eaccept_map;    // bitmap for EACCEPT status, bit 0 in eaccept_map[0] for the page at start address.
                                        // bit i in eaccept_map[j] for page at start_address+(i+j<<3)<<12.
    sgx_mutex_t*        lock;           // lock to prevent concurrent modification.
    int                 transition;     // state to indicate whether a transition in progress, e.g page type/permission changes.
    sgx_enclave_fault_handler_t
                        h;              // custom PF handler  (for EACCEPTCOPY use).
    void*               hprivate;       // private data for handler.
    _ema_t*             next;           // next in doubly linked list.
    _ema_t*             prev;           // prev in doubly linked list.
} ema_t;

```
 **Remarks:**
 - Accesses to the list (find, insert, remove EMAs) are synchronized for thread-safety.
 - Initial implementation will also have one lock per EMA to synchronize access and
 modifications to the same EMA. We may optimize this as needed.

### SGX primitives

```
typedef struct _sec_info_t
{
    uint64_t         flags;
    uint64_t         reserved[7];
} sec_info_t;

// EACCEPT
int do_eaccept(const sec_info_t* si, size_t addr);
// EMODPE
int do_emodpe(const sec_info_t* si, size_t addr);
// EACCEPTCOPY
int do_eacceptcopy(const sec_info_t* si, size_t dest, size_t src);

```


Metadata,  File format
---------------------------------------

The enclave metadata and file format are runtime specific. A detailed design is
out of scope of this document.

It is required that the enclave file should include metadata of memory layout
of initial code and data (e.g., program headers and PT_LOAD segments in ELF
file), any reserved region for special purposes, e.g., minimal heap, stack,
TCS areas, SSAs for expected minimal number of threads, etc. The runtime
would read those info to populate the initial EMAs described in the section
above on [Support for EMM Initialization](#support-for-emm-initialization)
The memory layout can also contain an entry for the user range mentioned
above if the enclave intends to dynamically allocate and manage some regions
using the EMM public APIs.
