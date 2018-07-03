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

#ifndef _SL_MEMLOG_H_
#define _SL_MEMLOG_H_

/*
 * sl_memlog - Memlog is an in-memory logger tailed for debug purpose.
 *
 * Features:
 *
 * 1) Efficiency. No OCalls or file I/O. All log messages are
 * stored in a fixed-size buffer given when memlog is initialized.
 * Thus, writing messages to memlog is just manipulating a buffer.
 * Efficiency proves to be crucial to debug some race conditions as
 * the latency introduced by logging may slow down the execution of
 * the program
 *
 * 2) No dependency. Memlog is independent of other modules or
 * libraries; to make it work, all it takes is a memory buffer. Thus,
 * memlog can work in situations that more sophisticated methods may
 * fail. For example, one cannot use an OCall-based logging facility
 * inside the preemption handler (see sl_preempt.c).
 *
 * 3) Concurrency. Memlog is thread-safe.
 *
 * 4) Unified interface. Memlog works both inside and outside enclave.
 * And if initialized with the same underlying buffer, logs generated
 * from both inside and outside enclave can store in one place.
 *
 *
 * Notes:
 *
 * 1) Persistence. Due to its nature of in-memory storage, log messages
 * can get lost if the program crashes. This problems can be solved by
 * using a memory-mapped buffer backed with a file. For more details
 * with this practice, see /test/common/mmaplog.h.
 *
 * 2) Security. The Memlog is a debug tool and not a general-purpose
 * logger. If Memlog is initialized with a buffer outside enclave,
 * there can be security vulnerabilities. Memlog should not be disabled
 * in release version.
 */

#include <stdarg.h>
#include <sl_types.h>

#define MEMLOG_MAX_MSG 256

__BEGIN_DECLS

int sl_memlog_init(char* buf, size_t size, size_t* pos);

/* Format only accepts %d, %u, %ld, %lu and %s */
int sl_memlog_printf(const char* fmt, ...);
int sl_memlog_vprintf(const char* fmt, va_list args);

void sl_memlog_clear(void);

size_t sl_memlog_getlen(void);
char* sl_memlog_getbuf(void);

__END_DECLS

#endif /* _SL_MEMLOG_H_ */
