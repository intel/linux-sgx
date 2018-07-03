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

#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sl_memlog.h>
#include <sl_util.h>
#include "mini_snprintf.h"

/* XXX: investigate why setting max size to 512B leads to segmentation
 * fault in preemption handler */
//~ #define MEMLOG_MAX_MSG 256

static char* memlog_buf = NULL;
static volatile size_t* memlog_pos = NULL;
static size_t memlog_size = 0;

int sl_memlog_init(char* buf, size_t size, size_t* pos) {
    if (buf == NULL || pos == NULL) return EINVAL;
    if (size <= 1) return EINVAL;

    memlog_buf = buf;
    memlog_pos = (volatile size_t*) pos;
    memlog_size = size - 1;

    // Make sure the buffer as a whole is null terminated
    memlog_buf[memlog_size - 1] = '\0';
    return 0;
}

static int mini_vsnprintf(char* buf, size_t size, const char* fmt, va_list ag) {
    if (size == 0) return 0;
    return __vsnprintf(buf, size, fmt, ag);
}

static int __vprintf(const char* fmt, va_list args) {
    int len;
    char msg[MEMLOG_MAX_MSG];

    // Make the string according to the format given
    len = mini_vsnprintf(msg, MEMLOG_MAX_MSG, fmt, args);
    // Disgard the portion that overflows the buffer
    if (len >= MEMLOG_MAX_MSG) len = MEMLOG_MAX_MSG - 1;

    // Note: vsprintf garantees that the output string is null terminated
    // if the length is greater than zero. So we don't need to set null
    // at the end of string

    // Move the cursor forward atomically
    size_t begin_pos = __sync_fetch_and_add(memlog_pos, len);
    if (begin_pos >= memlog_size) return 0;

    len = (int) MIN((size_t)len, memlog_size - begin_pos);
    memcpy(memlog_buf + begin_pos, msg, (size_t)len);

    return len;
}

int sl_memlog_vprintf(const char* fmt, va_list args) {
    // If not initialized, report error
    if (memlog_pos == NULL) return EINVAL;
    if (*memlog_pos >= memlog_size) return 0;

    return __vprintf(fmt, args);
}

int sl_memlog_printf(const char* fmt, ...) {
    // If not initialized, report error
    if (memlog_pos == NULL) return EINVAL;
    if (*memlog_pos >= memlog_size) return 0;

    int len;
    va_list args;
    va_start(args, fmt);
    len = __vprintf(fmt, args);
    va_end(args);
    return len;
}

size_t sl_memlog_getlen(void) {
    return MIN(*memlog_pos, memlog_size);
}

char* sl_memlog_getbuf(void) {
    return memlog_buf;
}

void sl_memlog_clear(void) {
    *memlog_pos = 0;
}

