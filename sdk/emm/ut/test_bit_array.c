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

#include <assert.h>
#include "bit_array.h"

int main()
{
    bit_array *ba = bit_array_new_set(31);

    assert(bit_array_size(ba) == 31);

    assert(bit_array_any(ba) == true);
    assert(bit_array_none(ba) == false);
    
    assert(bit_array_test(ba, 0) == true);
    assert(bit_array_test(ba, 15) == true);
    assert(bit_array_test(ba, 18) == true);
    assert(bit_array_test(ba, 24) == true);
    assert(bit_array_test(ba, 30) == true);

    assert(bit_array_test_range(ba, 17, 10) == true);
    assert(bit_array_all(ba) == true);

    bit_array_reset_range(ba, 17, 10);
    assert(bit_array_test_range(ba, 17, 10) == false);
    assert(bit_array_test(ba, 17) == false);
    assert(bit_array_test(ba, 18) == false);
    assert(bit_array_test(ba, 24) == false);
    assert(bit_array_test(ba, 26) == false);
    assert(bit_array_test(ba, 27) == true);
    
    bit_array_flip(ba, 30);
    assert(bit_array_test(ba, 30) == false);

    bit_array *lo  = NULL, *hi = NULL;
    int ret = bit_array_split(ba, 0, &lo, &hi);
    assert(ret == 0);
    assert(lo == NULL);
    assert(hi == ba);

    ret = bit_array_split(ba, 31, &lo, &hi);
    assert(ret == 0);
    assert(lo == ba);
    assert(hi == NULL);

    ret = bit_array_split(ba, 17, &lo, &hi);
    assert(lo == ba);
    assert(ret == 0);
    bit_array_delete(lo);

    bit_array *new_ba = NULL, *new_hi = NULL;
    ret = bit_array_split(hi, 10, &new_ba, &new_hi);
    assert(ret == 0);
    assert(new_ba == hi);
    assert(bit_array_size(new_ba) == 10);
    assert(bit_array_none(new_ba) == true);
    assert(bit_array_size(new_hi) == 4);
    assert(bit_array_all(new_hi) == false);
    assert(bit_array_test(new_hi, 3) == false);

    bit_array_delete(new_ba);
    bit_array_delete(new_hi);
    return 0;
}
