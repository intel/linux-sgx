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

#include <stdio.h>
#include <assert.h>
#include "ema.h"

extern ema_root_t g_user_ema_root;
extern ema_root_t g_rts_ema_root;
struct ema_root_ {
    ema_t *guard;
};

int main()
{
    //make sure rts is inited.
    ema_t *node0 = ema_new(0, 0xFFF00000,
                           SGX_EMA_COMMIT_NOW,
                           SGX_EMA_PROT_READ_WRITE | SGX_EMA_PAGE_TYPE_REG,
                           NULL, NULL, g_rts_ema_root.guard);

    assert(node0);
    // find_build/insert node
    size_t addr = 0;
    ema_t *next_ema = NULL;
    bool ret = find_free_region(&g_user_ema_root,
                    0x2000, SGX_PAGE_SIZE, &addr, &next_ema);

    assert(ret == true);
    assert(addr == 0xFFF00000);
    assert(next_ema == g_user_ema_root.guard);

    node0 = ema_new(0xFFF00000, 0x2000,
                            SGX_EMA_COMMIT_ON_DEMAND,
                            SGX_EMA_PROT_READ_WRITE | SGX_EMA_PAGE_TYPE_REG,
                            NULL, NULL, next_ema);

    
    // find at/build/push_back node

    ret = find_free_region_at(&g_user_ema_root, 0xFFF03000,
                         0x1000,
                         &next_ema);

    assert(ret == true);
    assert(next_ema == g_user_ema_root.guard);

    ema_t *node1 = ema_new(0xFFF03000, 0x1000,
                           SGX_EMA_COMMIT_NOW,
                           SGX_EMA_PROT_READ_WRITE | SGX_EMA_PAGE_TYPE_REG,
                           NULL, NULL, g_user_ema_root.guard);


    // negative case for find_at
    ret = find_free_region_at(&g_user_ema_root,
                    0xFFF02000, 0x3000, &next_ema);

    assert(ret == false);
    assert(next_ema == NULL);


    // find_at/build/insert node
    ret = find_free_region_at(&g_user_ema_root,
                    0xFFF06000, 0x3000, &next_ema);

    assert(ret == true);
    assert(next_ema == g_user_ema_root.guard);

    ema_t *node2 = ema_new(0xFFF06000, 0x3000,
                            SGX_EMA_COMMIT_ON_DEMAND,
                            SGX_EMA_PROT_READ_WRITE | SGX_EMA_PAGE_TYPE_REG,
                            NULL, NULL, next_ema);

    // dump current nodes on the root
    dump_ema_root(&g_user_ema_root);

    ema_t *first = NULL, *last = NULL;

    // search_ema_range #1
    int r = search_ema_range(&g_user_ema_root,
                             0xFFF00000, 0xFFF06000,
                             &first, &last);
    assert(r == 0);
    assert(first == node0);
    assert(last == node2);


    // search_ema_range #2
    r = search_ema_range(&g_user_ema_root,
                             0xFFF02000, 0xFFF06000,
                             &first, &last);
    assert(r == 0);
    assert(first == node1);
    assert(last == node2);


    // search_ema_range #3
    r = search_ema_range(&g_user_ema_root,
                             0xFFF02000, 0xFFF09000,
                             &first, &last);
    assert(r == 0);
    assert(first == node1);
    assert(last == g_user_ema_root.guard);
    
    // search_ema_range #4
    r = search_ema_range(&g_user_ema_root,
                         0xFFF01000, 0xFFF05000,
                         &first, &last);
    assert(r == 0);
    assert(first == node0);
    assert(last == node2);

    // negative case, middle address region
    r = search_ema_range(&g_user_ema_root,
                         0xFFF04000, 0xFFF05000,
                         &first, &last);
    assert(r == -1);
    assert(first == NULL);
    assert(last == NULL);

    // negative case, front address region
    r = search_ema_range(&g_user_ema_root,
                         0xFFE00000, 0xFFF00000,
                         &first, &last);
    assert(r == -1);
    assert(first == NULL);
    assert(last == NULL);

    // negative case, rear address region
    r = search_ema_range(&g_user_ema_root,
                         0xFFF0A000, 0xFFF0B000,
                         &first, &last);
    assert(r == -1);
    assert(first == NULL);
    assert(last == NULL);


    // ema split: split point is out of range
    ema_t *tmp_node =  NULL;
    r = ema_split(node0, 0xFFE00000, true, &tmp_node);
    assert(tmp_node == NULL);

    // ema split: split point is out of range
    tmp_node = NULL;
    r = ema_split(node0, 0xFFF02000, false, &tmp_node);
    assert(tmp_node == NULL);

    // ema split: split point is within range
    size_t node0_base = ema_base(node0);
    tmp_node = NULL;
    ema_split(node0, 0xFFF01000, true, &tmp_node);
    assert(ema_next(tmp_node) == node0);
    assert(ema_base(tmp_node) == node0_base);
    assert(ema_size(tmp_node) == 0x1000);

    tmp_node = NULL;
    r = ema_split_ex(node2, 0xFFF07000, 0xFFF08000, &tmp_node);
    assert(ema_base(tmp_node) == 0xFFF07000);
    assert(ema_size(tmp_node) == 0x1000);
    dump_ema_root(&g_user_ema_root);
    destroy_ema_root(&g_user_ema_root);

    return 0;
}
