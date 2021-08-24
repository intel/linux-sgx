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

#ifndef EMM_PRIVATE_H_
#define EMM_PRIVATE_H_

#include <stdint.h>
#include <stddef.h>
#include "sgx_mm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_EMA_SYSTEM SGX_EMA_ALLOC_FLAGS(0x80UL) /* EMA reserved by system */
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
 *        - SGX_EMA_PROT_EXECUTE: Pages may be executed.
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
// See documentation in sgx_mm.h
int mm_alloc(void *addr, size_t size, uint32_t flags,
              sgx_enclave_fault_handler_t handler, void *private_data, void** out_addr);
int mm_dealloc(void *addr, size_t size);
int mm_uncommit(void *addr, size_t size);
int mm_commit(void *addr, size_t size);
int mm_commit_data(void *addr, size_t size, uint8_t *data, int prot);
int mm_modify_type(void *addr, size_t size, int type);
int mm_modify_permissions(void *addr, size_t size, int prot);

#ifdef __cplusplus
}
#endif

#endif
