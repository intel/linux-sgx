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

#ifndef __SGX_EMA_H__
#define __SGX_EMA_H__

#include <stdbool.h>
#include "sgx_mm.h"

#ifndef SGX_SECINFO_ALIGN
#define SGX_SECINFO_ALIGN __attribute__((aligned(sizeof(sec_info_t))))
#endif

#define SGX_PAGE_SIZE   0x1000ULL
#define SGX_PAGE_SHIFT  12

typedef struct ema_root_ ema_root_t;
typedef struct ema_t_ ema_t;

#ifdef __cplusplus
extern "C" {
#endif

bool ema_root_empty(ema_root_t* r);
bool ema_exist_in(ema_root_t* r, size_t addr, size_t size);
bool ema_exist(size_t addr, size_t size);

#ifndef NDEBUG
ema_t * ema_next(ema_t *node);
#endif
#ifdef TEST
void    destroy_ema_root(ema_root_t *);
void    dump_ema_root(ema_root_t *);
size_t  ema_base(ema_t *node);
size_t  ema_size(ema_t *node);
int ema_split(ema_t *ema, size_t addr, bool new_lower, ema_t** new_node);
int ema_split_ex(ema_t *ema, size_t start, size_t end, ema_t** new_node);
ema_t * ema_merge(ema_t *lo_ema, ema_t *hi_ema);
#endif

uint32_t get_ema_alloc_flags(ema_t *node);
uint64_t get_ema_si_flags(ema_t *node);

sgx_enclave_fault_handler_t ema_fault_handler(ema_t* node, void** private_data);
bool    is_ema_transition(ema_t *node);

ema_t *ema_new(size_t addr, size_t size, uint32_t alloc_flags,
                 uint64_t si_flags,
                 sgx_enclave_fault_handler_t handler,
                 void *private_data,
                 ema_t* next_ema);
void    ema_destroy(ema_t *ema);

int     ema_set_eaccept_full(ema_t *node);
int     ema_clear_eaccept_full(ema_t *node);
int     ema_set_eaccept(ema_t *node, size_t start, size_t end);
bool    ema_page_committed(ema_t *ema, size_t addr);

ema_t * search_ema(ema_root_t *root, size_t addr);
int     search_ema_range(ema_root_t *root,
                        size_t start, size_t end,
                        ema_t **ema_begin, ema_t **ema_end);

bool    find_free_region(ema_root_t *root,
                      size_t size, size_t align, size_t *addr,
                      ema_t **next_ema);

bool    find_free_region_at(ema_root_t *root,
                         size_t addr, size_t size,
                         ema_t **next_ema);


int do_commit(size_t start, size_t size, uint64_t si_flags, bool grow_up);
int ema_do_commit(ema_t *node, size_t start, size_t end);
int ema_do_commit_loop(ema_t *first, ema_t *last, size_t start, size_t end);

int ema_do_uncommit(ema_t *node, size_t start, size_t end);
int ema_do_uncommit_loop(ema_t *first, ema_t *last, size_t start, size_t end);

int ema_do_dealloc(ema_t *node, size_t start, size_t end);
int ema_do_dealloc_loop(ema_t *first, ema_t *last, size_t start, size_t end);

int ema_modify_permissions(ema_t *node, size_t start, size_t end, int new_prot);
int ema_modify_permissions_loop(ema_t *first, ema_t *last, size_t start, size_t end, int prot);
int ema_change_to_tcs(ema_t *node, size_t addr);

int ema_do_commit_data(ema_t *node, size_t start, size_t end, uint8_t *data, int prot);
int ema_do_commit_data_loop(ema_t *firsr, ema_t *last, size_t start,
                                size_t end, uint8_t *data, int prot);

int ema_do_alloc(ema_t* node);
ema_t* ema_realloc_from_reserve_range(ema_t* first, ema_t* last,
            size_t start, size_t end,
            uint32_t alloc_flags, uint64_t si_flags,
            sgx_enclave_fault_handler_t handler,
            void *private_data);

#ifdef __cplusplus
}
#endif

#endif
