/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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

#ifndef _SL_BITOPS_H_
#define _SL_BITOPS_H_

#include <sl_atomic.h>

__BEGIN_DECLS


static inline void set_bit(volatile uint64_t* l, uint32_t i) 
{
    lock_or64(l, 1UL << i);
}

static inline int32_t test_and_clear_bit(volatile uint64_t* l, uint32_t i)
{
    uint64_t old_l, new_l;
retry:
    old_l = *l;
    if (unlikely((old_l & (1UL << i)) == 0)) return 0;

    new_l = old_l & (~(1UL << i));
    if (unlikely(lock_cmpxchg64(l, old_l, new_l) != old_l)) goto retry;
    return 1;
}

static inline int32_t extract_one_bit(volatile uint64_t* l)
{
    uint64_t old_l;
    while ((old_l = *l) != 0) 
	{
        int32_t j = __builtin_ctzl(old_l);
        if (unlikely(test_and_clear_bit(l, (uint32_t)j) == 0)) continue;
        return j;
    }
    return -1;
}

__END_DECLS

#endif /* _SL_BITOPS_H_ */
