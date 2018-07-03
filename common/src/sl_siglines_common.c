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


#include <sl_siglines.h>
#include <sl_debug.h>
#include <sl_bitops.h>

int is_direction_sender(sl_siglines_dir_t dir) 
{
#ifdef SL_INSIDE_ENCLAVE /* trusted */
    return dir == SL_SIGLINES_DIR_T2U;
#else /* untrusted */
    return dir == SL_SIGLINES_DIR_U2T;
#endif
}

static inline int is_direction_receiver(sl_siglines_dir_t dir) 
{
#ifdef SL_INSIDE_ENCLAVE /* trusted */
    return dir == SL_SIGLINES_DIR_U2T;
#else /* untrusted */
    return dir == SL_SIGLINES_DIR_T2U;
#endif
}

static inline int is_line_valid(struct sl_siglines* sglns, sl_sigline_t line) 
{
    return (line < sglns->num_lines);
}

sl_sigline_t sl_siglines_alloc_line(struct sl_siglines* sglns) 
{
    BUG_ON(!is_direction_sender(sglns->dir));

    uint32_t i, max_i = (sglns->num_lines / NBITS_PER_UINT64);
    uint64_t* bits_p;

    for (i = 0; i < max_i; i++)
    {
        bits_p = &sglns->free_lines[i];

        int32_t j = extract_one_bit(bits_p);
        if (j < 0) continue;

        sl_sigline_t free_line = NBITS_PER_UINT64 * i + (uint32_t)j;
        return free_line;

    }
    
    return SL_INVALID_SIGLINE;
}

void sl_siglines_free_line(struct sl_siglines* sglns, sl_sigline_t line)
{
    BUG_ON(!is_direction_sender(sglns->dir));
    BUG_ON(!is_line_valid(sglns, line));
	uint32_t i = line / NBITS_PER_UINT64;
	uint32_t j = line % NBITS_PER_UINT64;
    set_bit(&sglns->free_lines[i], j);
}


int sl_siglines_trigger_signal(struct sl_siglines* sglns, sl_sigline_t line) 
{
    BUG_ON(!is_direction_sender(sglns->dir));
    BUG_ON(!is_line_valid(sglns, line));
	uint32_t i = line / NBITS_PER_UINT64;
	uint32_t j = line % NBITS_PER_UINT64;
    set_bit(&sglns->event_lines[i], j);
    return 0;
}

int sl_siglines_revoke_signal(struct sl_siglines* sglns, sl_sigline_t line) 
{
    BUG_ON(!is_direction_sender(sglns->dir));
    BUG_ON(!is_line_valid(sglns, line));
	uint32_t i = line / NBITS_PER_UINT64;
	uint32_t j = line % NBITS_PER_UINT64;
    return test_and_clear_bit(&sglns->event_lines[i], j) == 0;
}

uint32_t sl_siglines_process_signals(struct sl_siglines* sglns) 
{
    BUG_ON(!is_direction_receiver(sglns->dir));

	uint32_t nprocessed = 0;
	uint32_t i, bit_n, start_bit, end_bit, max_i = (sglns->num_lines/ NBITS_PER_UINT64);
	uint64_t* bits_p;
	uint64_t  bits_value;

	for (i = 0; i < max_i;	i++)
	{
		bits_p = &sglns->event_lines[i];
		bits_value = *bits_p;

		if (bits_value != 0)
		{
			start_bit = (uint32_t)__builtin_ctzl(bits_value);
			end_bit = NBITS_PER_UINT64 - (uint32_t)__builtin_clzl(bits_value);

			for (bit_n = start_bit; bit_n < end_bit; bit_n++)
			{
				if (unlikely(test_and_clear_bit(bits_p, bit_n) == 0)) continue;

				sl_sigline_t line = NBITS_PER_UINT64 * i + bit_n;
				sglns->handler(sglns, line);

				nprocessed++;
			}
		}
	}

    return nprocessed;
}
