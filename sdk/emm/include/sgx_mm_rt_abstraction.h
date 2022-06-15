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

#ifndef SGX_MM_RT_ABSTRACTION_H_
#define SGX_MM_RT_ABSTRACTION_H_

#include "sgx_mm.h"
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

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

    /*
 * Define a mutex and init/lock/unlock/destroy functions.
 */
    typedef struct _sgx_mm_mutex sgx_mm_mutex;
    sgx_mm_mutex* sgx_mm_mutex_create(void);
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


#define SGX_EMA_SYSTEM SGX_EMA_ALLOC_FLAGS(0x80UL) /* EMA reserved by system */

#ifdef __cplusplus
}
#endif

#endif
