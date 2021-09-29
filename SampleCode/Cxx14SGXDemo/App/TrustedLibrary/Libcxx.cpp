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

#include "../App.h"
#include "Enclave_u.h"
#include <thread>

// Examples for C++14 library and compiler features
void ecall_libcxx_functions(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = ecall_cxx14_standard_user_defined_literals(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_tuple_via_type(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_make_unique(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_integral_constant(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_integer_sequence(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_constant_begin_end(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_exchage(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_is_final(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_equal_mismatch_permutation_new_overloads(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_heterogeneous_lookup(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_function_return_type_deduction(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_variable_template(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_binary_literals(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_digit_separators(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_generic_lambdas(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_lambda_capture_expression(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_attribute_deprecated(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_aggregate_member_init(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_relaxed_constexpr(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_alternate_type_deduction(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    ret = ecall_cxx14_quoted(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

