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
#include <thread>

#include "../App.h"
#include "Enclave_u.h"

typedef sgx_status_t(*ecall_cxx17_func)(sgx_enclave_id_t);

ecall_cxx17_func functions_to_test[] = {
    ecall_cxx17_static_assert,
    ecall_cxx17_template_parameter,
    ecall_cxx17_auto_deduction_from_braced_init_list,
    ecall_cxx17_nested_namespace,
    ecall_cxx17_u8_character_literals,
    ecall_cxx17_hexadecimal_floating_point_literals,
    ecall_cxx17_structured_binding,
    ecall_cxx17_fold_expression,
    ecall_cxx17_compile_time_if,
    ecall_cxx17_initializer_in_if_switch,
    ecall_cxx17_CTAD,
    ecall_cxx17_inline_variable,
    ecall_cxx17_lambda_capture_this_by_value,
    ecall_cxx17_constexpr_lambda,
    ecall_cxx17_uncaught_exceptions,
    ecall_cxx17_invoke,
    ecall_cxx17_reference,
    ecall_cxx17_uninitialized_memory_algorithms,
    ecall_cxx17_aligned_alloc,
    ecall_cxx17_owner_less,
    ecall_cxx17_shared_ptr_for_array,
    ecall_cxx17_std_byte,
    ecall_cxx17_std_conjunction_disjunction_negation,
    ecall_cxx17_is_aggregate,
    ecall_cxx17_is_swappable,
    ecall_cxx17_searchers,
    ecall_cxx17_std_has_unique_object_representations,
    ecall_cxx17_clamp,
    ecall_cxx17_reduce,
    ecall_cxx17_inclusive_exclusive_scan,
    ecall_cxx17_gcd_lcm,
    ecall_cxx17_map_extract_merge,
    ecall_cxx17_map_try_emplace_insert_or_assign,
    ecall_cxx17_std_size_empty_data,
    ecall_cxx17_std_as_const,
    ecall_cxx17_optional,
    ecall_cxx17_make_from_tuple,
    ecall_cxx17_tuple_deduction_guides,
    ecall_cxx17_any,
    ecall_cxx17_variant,
    ecall_cxx17_apply,
    ecall_cxx17_align_new_delete,
    ecall_cxx17_has_include,
    ecall_cxx17_string_view,
};

void demo_cond_var_run()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_condition_variable_run(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

void demo_cond_var_load()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_condition_variable_load(global_eid);
    if (ret != SGX_SUCCESS)
        abort();
}

// Examples for C++17 library and compiler features
void ecall_libcxx_functions(void)
{
    for (auto f : functions_to_test) {   
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        ret = f(global_eid);
        if (ret != SGX_SUCCESS)
            abort();
    }

    std::thread th1(demo_cond_var_run);
    std::thread th2(demo_cond_var_load);
    th2.join();
    th1.join();
}
