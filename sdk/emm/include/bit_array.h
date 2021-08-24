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

#ifndef BIT_ARRAY_H_
#define BIT_ARRAY_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct bit_array_ bit_array;

#ifdef __cplusplus
extern "C" {
#endif

// Create a new bit array to track the status of 'num' of bits.
// The contents of the data is not initialized.
bit_array *bit_array_new(size_t num_of_bits);

// Create a new bit array to track the status of 'num' of bits.
// All the tracked bits are set (value 1).
bit_array *bit_array_new_set(size_t num_of_bits);

// Create a new bit array to track the status of 'num' of bits.
// All the tracked bits are reset (value 0).
bit_array *bit_array_new_reset(size_t num_of_bits);

// Reset the bit_array 'ba' to track the new 'data', which has 'num' of bits.
void bit_array_reattach(bit_array *ba, size_t num_of_bits, uint8_t *data);

// Delete the bit_array 'ba' and the data it owns
void bit_array_delete(bit_array *ba);

// Returns the number of tracked bits in the bit_array
size_t bit_array_size(bit_array *ba);

// Returns whether the bit at position 'pos' is set
bool bit_array_test(bit_array *ba, size_t pos);

// Return whether the bits in range [pos, pos+len) are all set
bool bit_array_test_range(bit_array *ba, size_t pos, size_t len);

// Retuen whether any bit in range [pos, pos+len) is set
bool bit_array_test_range_any(bit_array *ba, size_t pos, size_t len);

// Returns whether any of the bits is set
bool bit_array_any(bit_array *ba);

// Returns whether none of the bits is set
bool bit_array_none(bit_array *ba);

// Returns whether all of the bits are set
bool bit_array_all(bit_array *ba);

// Set the bit at 'pos'
void bit_array_set(bit_array *ba, size_t pos);

// Set the bits in range [pos, pos+len)
void bit_array_set_range(bit_array *ba, size_t pos, size_t len);

// Set all the bits
void bit_array_set_all(bit_array *ba);

// Clear the bit at 'pos'
void bit_array_reset(bit_array *ba, size_t pos);

// Clear the bits in range [pos, pos+len)
void bit_array_reset_range(bit_array *ba, size_t pos, size_t len);

// Clear all the bits
void bit_array_reset_all(bit_array *ba);

// Flip the bit at 'pos'
void bit_array_flip(bit_array *ba, size_t pos);

// Split the bit array at 'pos'
// Returns pointers to two new bit arrays
int bit_array_split(bit_array *ba, size_t pos, bit_array **, bit_array **);

// Merge two bit arrays
// Returns a new bit array,  merging two input bit arrays
bit_array* bit_array_merge(bit_array *ba1, bit_array *ba2);

#ifdef __cplusplus
}
#endif

#endif
