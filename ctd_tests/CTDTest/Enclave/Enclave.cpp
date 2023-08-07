/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_trts_exception.h"
#include "sgx_trts_aex.h"
#include "../TestStructure.h"
#include <assert.h>

extern uint32_t test_data;

extern "C" uint64_t asm_test(test_cpu_context_t *ctx1, test_cpu_context_t *ctx2, uint32_t *addr);

int ud_handler(sgx_exception_info_t *info) {
	if (*((unsigned short *)info->cpu_context.rip) == 0x0B0F) {
		info->cpu_context.rip += 2;
		return -1;
	}
	return 0;
}

void init() {
	assert(sgx_register_exception_handler(1 /* is_first_handler */, ud_handler));
}

uint64_t test(test_cpu_context_t *ctx1, test_cpu_context_t *ctx2) {
	uint64_t ret;
	sgx_set_ssa_aexnotify(1);
	ret = asm_test(ctx1, ctx2, &test_data);
	sgx_set_ssa_aexnotify(0);
	return ret;
}

uint64_t get_test_address() {
	return (uint64_t)&test_data;
}
