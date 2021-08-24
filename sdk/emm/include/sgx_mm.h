/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SGX_MM_H_
#define SGX_MM_H_

#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

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

/**
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
#define SGX_EMA_ALLOC_FLAGS(n) ((n) << SGX_EMA_ALLOC_FLAGS_SHIFT)
#define SGX_EMA_ALLOC_FLAGS_MASK    SGX_EMA_ALLOC_FLAGS(0xFF)

/* Only reserve an address range, no physical memory committed.*/
#define SGX_EMA_RESERVE             SGX_EMA_ALLOC_FLAGS(0x1)

/* Reserve an address range and commit physical memory. */
#define SGX_EMA_COMMIT_NOW          SGX_EMA_ALLOC_FLAGS(0x2)

/* Reserve an address range and commit physical memory on demand.*/
#define SGX_EMA_COMMIT_ON_DEMAND    SGX_EMA_ALLOC_FLAGS(0x4)

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
#define SGX_EMA_PROT_NONE 0x0
#define SGX_EMA_PROT_READ       0x1
#define SGX_EMA_PROT_WRITE      0x2
#define SGX_EMA_PROT_EXEC       0x4
#define SGX_EMA_PROT_READ_WRITE (SGX_EMA_PROT_READ|SGX_EMA_PROT_WRITE)
#define SGX_EMA_PROT_READ_EXEC  (SGX_EMA_PROT_READ|SGX_EMA_PROT_EXEC)
#define SGX_EMA_PROT_MASK (SGX_EMA_PROT_READ_WRITE|SGX_EMA_PROT_EXEC)
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

/* Return value used by the EMM #PF handler to indicate
 *  to the dispatcher that it should continue searching for the next handler.
 */
#define SGX_MM_EXCEPTION_CONTINUE_SEARCH 0

/* Return value used by the EMM #PF handler to indicate
 *  to the dispatcher that it should stop searching and continue execution.
 */
#define SGX_MM_EXCEPTION_CONTINUE_EXECUTION -1


#ifdef __cplusplus
}
#endif
#endif
