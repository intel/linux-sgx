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

#include "sl_siglines.h"
#include <sl_util.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sl_siglines.h>
#include <sl_debug.h>
#include <sl_bitops.h>


int sl_siglines_init(struct sl_siglines* sglns,
                     sl_siglines_dir_t dir,
                     uint32_t num_lines,
                     sl_sighandler_t handler)
{
    BUG_ON(is_direction_sender(dir) && (handler != NULL));

    if (num_lines <= 0) return -EINVAL;
    num_lines = ALIGN_UP(num_lines, NBITS_PER_UINT64);
    uint32_t nlong = num_lines / NBITS_PER_UINT64;

    uint64_t *event_lines = NULL, *free_lines = NULL;
    uint32_t i = 0;
    event_lines = (uint64_t*)calloc(nlong, sizeof(uint64_t));
    if (event_lines == NULL) goto on_error;

    if (is_direction_sender(dir))
	{
        free_lines = (uint64_t*)malloc(sizeof(uint64_t) * nlong);
        if (free_lines == NULL) goto on_error;
        for (; i < nlong; i++) free_lines[i] = (uint64_t)(-1); // all 1's -> free
    }

    sglns->dir = dir;
    sglns->num_lines = num_lines;
    sglns->event_lines = event_lines;
    sglns->free_lines = free_lines;

    sglns->handler = handler;
    return 0;
on_error:
    free(event_lines);
    free(free_lines);
    return -ENOMEM;
}

void sl_siglines_destroy(struct sl_siglines* sglns) 
{
    free(sglns->event_lines);
    free(sglns->free_lines);
}
