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

#include <string>
#include <vector>
#include <iterator>
#include <typeinfo>
#include <functional>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <initializer_list>
#include <tuple>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <map>
#include <array>
#include <utility>
#include <set>
#include <iomanip>
#include <sstream>

#include "../Enclave.h"
#include "Enclave_t.h"

// Examples for the following new language and library features introduced by C++14:
// standard user-defined literals
// tuple addressing via type
// std::make_unique
// std::integral_constant
// std::integer_sequence
// std::cbegin/std::cend and std::crbegin/std::crend
// std::exchange
// std::is_final
// std::equal/std::mismatch/std::is_permutation new overloads
// heterogeneous lookup
// function return type deduction
// variable template
// binary literals
// digit separators
// generic lambdas
// lambda capture expressions
// attribute [[deprecated]]
// aggregate member initialization
// relaxed constexpr restrictions
// alternate type deduction on declaration
// std:quoted

using namespace std::literals;

class A{};
class B final {};

struct Vec {
    int x = 0, y = 0;
    Vec() = default;
    Vec(int x, int y) : x(x), y(y) {}
    void dump(){
        printf("{%d, %d}", x, y);
    }
};

struct R {
    int x;
    R(int i) : x{i} { printf("R{%d} ", i); }
    bool operator<(R const &r) const { return x < r.x; }
};

bool operator<(R const &r, int i) { return r.x < i; }
bool operator<(int i, R const &r) { return i < r.x; }

// debugging aid
template<typename T, T... ints>
void print_sequence(std::integer_sequence<T, ints...> int_seq)
{
    printf("The sequence of size %lu: ", int_seq.size());
    (printf("%lu ", ints), ...);
    printf("\n");
}

// convert array into a tuple
template<typename Array, std::size_t... I>
auto a2t_impl(const Array& a, std::index_sequence<I...>)
{
    return std::make_tuple(a[I]...);
}

template<typename T, std::size_t N, typename Indices = std::make_index_sequence<N>>
auto a2t(const std::array<T, N>& a)
{
    return a2t_impl(a, Indices{});
}

// pretty-print a tuple
template<typename Tuple, std::size_t... Is>
void print_tuple_impl(const Tuple& t, std::index_sequence<Is...>)
{
    (printf("%s%d", Is == 0 ? "" : ", ", std::get<Is>(t)), ...);
}

template<typename... Args>
void dump_tuple(const std::tuple<Args...>& t)
{
    printf("(");
    print_tuple_impl(t, std::index_sequence_for<Args...>{});
    printf(")");
    printf("\n");
}

//Function return type deduction
auto fibonacci(int n)
{
    if (n < 2)
        return 1;
    return fibonacci(n-1) + fibonacci(n-2);
}

// variable templates
template<typename T>
constexpr T pi = T(3.141592653589793238462643383);

template<>
constexpr const char* pi<const char*> = "pi";

template<typename T>
T circular_area(T r)
{
    return pi<T> * r * r;
}

// attribute [[deprecated]]
[[deprecated]] int f_depre() {return 0;}
[[deprecated("g_depre() is thread-unsafe. Use h() instead")]]
void g_depre(int &x) {return;}

// aggregate member initialization
struct Aggr {
    struct B {
        int a = 21;
        int b;
        int c = 22;
        int d;
        int e = 23;
    };
    B b1 = {11, 12};
    B b2 = {11, 12, 13};
    int x;
};

// Relaxed constexpr restrictions
constexpr bool even(int x) {
    if (x % 2 == 0)
        return true;
    return false;
}

constexpr int while_loop(int x) {
    int i = 0;
    do {
        ++i;
    }while (i < x);
    return i;
}

void ecall_cxx14_standard_user_defined_literals()
{
    auto str = "hello world"s;
    printf("%s\n", str.c_str());
}

void ecall_cxx14_tuple_via_type()
{
    std::tuple<std::string, int, double> t("foo", 99, 1.0);
    auto i = std::get<int>(t);
    auto d = std::get<double>(t);
    auto s = std::get<std::string>(t);
    printf("%d, %f, %s\n", i, d, s.c_str());
}

void ecall_cxx14_make_unique()
{
    auto v1 = std::make_unique<Vec>();
    auto v2 = std::make_unique<Vec>(1, 2);
    auto v3 = std::make_unique<Vec[]>(5);

    printf("make_unique<Vec>():      ");
    (*v1).dump();
    printf("\n");

    printf("make_unique<Vec>(1, 2): ");
    (*v2).dump();
    printf("\n");
    
    printf("make_unique<Vec[]>(5):   ");
    printf("\n");
    for (int i = 0; i < 5; i++) {
        printf("     ");
        v3[i].dump();
        printf("\n");
    }
}

void ecall_cxx14_integral_constant()
{
    typedef std::integral_constant<int, 2> two_t;
    typedef std::integral_constant<int, 4> four_t;

    static_assert(two_t()*2 == four_t(), "2*2 != 4");
}

void ecall_cxx14_integer_sequence()
{
    print_sequence(std::integer_sequence<size_t, 9, 2, 5, 1>{});
    print_sequence(std::make_integer_sequence<size_t, 20>{});
    print_sequence(std::make_index_sequence<10>{});
    print_sequence(std::index_sequence_for<float, R, char>{});
    std::array<int, 4> array = {1, 2, 3, 4};
    auto tuple = a2t(array);
    static_assert(std::is_same<decltype(tuple),
                    std::tuple<int, int, int, int>>::value, "");
    dump_tuple(tuple);
}

void ecall_cxx14_constant_begin_end()
{
    std::vector<int> v = {3, 1, 4};

    if (std::find(std::cbegin(v), std::cend(v), 3) != std::cend(v)) {
        printf("Forward search: found the target in vector v!\n");
    }

    if (std::find(std::crbegin(v), std::crend(v), 3) != std::crend(v)) {
        printf("Backward search: found the target in vector v!\n");
    }
}

void ecall_cxx14_exchage()
{
    std::vector<int> vexc;
    std::exchange(vexc, {1, 2,  3, 4});
    for (const auto &vi : vexc)
        printf("%d  ", vi);
    printf("\n");
}

void ecall_cxx14_is_final()
{
    printf("A is final: %s\nB is final: %s\n",
           std::is_final<A>() ? "True" : "False",
           std::is_final<B>() ? "True" : "False");
}

void ecall_cxx14_equal_mismatch_permutation_new_overloads()
{
    std::vector<int> veq1{1, 2, 3};
    std::vector<int> veq2{1, 2, 3};
    auto is_equal = std::equal(veq1.cbegin(), veq1.cend(),
                               veq2.cbegin(), veq2.cend());
    printf("veq1 and veq2 is equal: %s\n", is_equal ? "True" : "False");

    std::vector<int> vmis{1, 3, 2};
    auto diff_pair = std::mismatch(veq1.cbegin(), veq1.cend(),
                                   vmis.cbegin(), vmis.cend());
    printf("first pair of different values: (%d, %d)\n",
           *diff_pair.first, *diff_pair.second);

    auto v_permu1 = {1, 2, 3, 4, 5};
    auto v_permu2 = {3, 5, 4, 1, 9};
    printf("v_permu1 and v_permu2 is_permutation: %s\n",
           std::is_permutation(v_permu1.begin(), v_permu1.end(),
                                     v_permu2.begin()) ? "True" : "False");
}

void ecall_cxx14_heterogeneous_lookup()
{
    std::set<R, std::less<>> r{3, 1, 4, 1, 5};
    printf(": %lu, %lu\n", r.count(1), r.count(2));
}

void ecall_cxx14_function_return_type_deduction()
{
    auto fibo_ret = fibonacci(10);
    printf("The fibonacci number at index 10: %u\n", fibo_ret);
}

void ecall_cxx14_variable_template()
{
    printf("pi as a const char: %s\n", pi<const char *>);
    printf("circular area (integer): %u\n", circular_area(10));
    printf("circular area (floating point): %f\n", circular_area(10.0));
}

void ecall_cxx14_binary_literals()
{
    printf("The hex represented by '0b10100101' is: 0x%x\n", 0b10100101);
}

void ecall_cxx14_digit_separators()
{
    printf("digit separator for integer: %u\n", 1'000'000);
    printf("digit separator for floating: %f\n", 0.001'015);
    printf("digit separator for binary literal: 0x%x\n", 0b0100'1100'0110);
}

void ecall_cxx14_generic_lambdas()
{
    auto lambda_sum = [](auto x, auto y) {return x + y;};
    printf("lambda_sum for (10, 10): %u\n", lambda_sum(10, 10));
    printf("lambda_sum for (10, 10.0): %f\n", lambda_sum(10, 10.0));
}

void ecall_cxx14_lambda_capture_expression()
{
    auto ptr = std::make_unique<int>(10);
    printf("result from lambda capture: %d\n", [value = std::move(ptr)]{return *value;}());
}

void ecall_cxx14_attribute_deprecated()
{
    auto depre = f_depre();
    g_depre(depre);
}

void ecall_cxx14_aggregate_member_init()
{
    Aggr a = {{1, 2, 3, 4}, {1}, 5};
}

void ecall_cxx14_relaxed_constexpr()
{
    printf("2 is an even number: %s\n", even(2) ? "true" : "false");
    printf("result from constexpr while_loop(10): %d\n", while_loop(10));
}

void ecall_cxx14_alternate_type_deduction()
{
    auto dedu_a = 1+2;               // type of a : int
    decltype(auto) dedu_b1 = dedu_a;      // type of b1: int
    decltype(auto) dedu_b2 = (dedu_a);    // type of b2: int&
    printf("before modification: a: %d, b1: %d, b2: %d\n", dedu_a, dedu_b1, dedu_b2);
    ++dedu_b2;
    printf("after modification: a: %d, b1: %d, b2: %d\n", dedu_a, dedu_b1, dedu_b2);
}

void ecall_cxx14_quoted()
{
    std::stringstream ss;
    std::string in = "String with spaces, and embedded \"quotes\" too";
    std::string out;

    auto show = [&](const auto& what) {
        &what == &in
            ?   printf("read in     [%s]\nstored as   [%s]\n", in.c_str(), ss.str().c_str())
            :   printf("written out [%s]\n\n", out.c_str());
    };

    ss << std::quoted(in);
    show(in);
    ss >> std::quoted(out);
    show(out);

    ss.str("");

    in = "String with spaces, and embedded $quotes$ too";
    const char delim {'$'};
    const char escape {'%'};
    ss << std::quoted(in, delim, escape);
    show(in);
    ss >> std::quoted(out, delim, escape);
    show(out);
}

