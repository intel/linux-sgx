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
#include <typeinfo>
#include <functional>
#include <algorithm>
#include <initializer_list>
#include <tuple>
#include <memory>
#include <map>
#include <utility>
#include <set>
#include <new>
#include <string_view>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <optional>
#include <any>
#include <variant>
#include <cassert>
#include <exception>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <numeric>
#include <mutex>
#include <condition_variable>

#include "../Enclave.h"
#include "Enclave_t.h"

using namespace std::literals;

// Examples for new language and library features introduced by C++17:

// New language features:
//   fold-expressions
//   class template argument deduction
//   non-type template parameters declared with auto
//   compile-time if constexpr
//   inline variables
//   structured bindings
//   initializers for if and switch
//   u8 character literal
//   simplified nested namespaces
//   using-declaration declaring multiple names
//   made noexcept part of type system
//   new order of evaluation rules
//   guaranteed copy elision
//   temporary materialization
//   lambda capture of *this
//   constexpr lambda
//   attribute namespaces don't have to repeat
//   new attributes:
//     [[fallthrough]]
//     [[maybe_unused]]
//     [[nodiscard]]
//   __has_include

// New library features:
//  Utility types
//    std::tuple:
//      std::apply
//      std::make_from_tuple
//    std::any
//    std::optional
//    std::variant
//    searchers
//    std::as_const
//    std::not_fn

//  Memory management
//      uninitialized memory algorithms
//      std::destroy_at
//      std::destroy
//      std::destroy_n
//      std::uninitialized_move
//      std::uninitialized_value_construct
//    weak_from_this
//    std::aligned_alloc
//    transparent std::owner_less
//    array support for std::shared_ptr
//    allocation functions with explicit alignment

//  Compile-time programming
//    std::byte
//    std::conjunction/std::disjunction/std::negation
//    type trait variable templates (xxx_+v)
//    std::is_swappable
//    is_invocable
//    is_aggregate
//    std::has_unique_object_representations

//  Algorithms
//    std::clamp
//    std::reduce
//    std::inclusive_scan
//    std::exclusive_scan
//    std::gcd
//    std::lcm

//  Iterators and containers
//    map/set extract and map/set merge
//    map/unordered_map try_emplace and insert_or_assign
//    contiguous iterators (LegacyContiguousIterator)
//    non-member std::size/std::empty/std::data

//  Other
//    std::launder
//    std::uncaught_exceptions


// Fold expressions, for variadic templates 
template<typename ...Args>
int sum(Args&&... args)
{
    return (args + ...);
}
void ecall_cxx17_fold_expression() {
    printf("sum of 1, 2, 3, 4 is %d\n", sum(1, 2, 3, 4));
}

void ecall_cxx17_CTAD() {
    std::pair p(2, 4.5);
    auto [p1, p2] = p;
    printf("std::pair <%d, %.1f>\n", p1, p2);

    std::tuple t(4, 3, 2.5);
    auto [t1, t2, t3] = t;
    printf("std::tuple (%d, %d, %.1f)\n", t1, t2, t3);
}

template<typename T>
class my_array {};
// two type template parameters and one template template parameter:
template<typename K, typename V, template<typename> typename C = my_array>
class Map
{
public:
    Map() {
        printf("Map instance constructed\n");
    }

    C<K> key;
    C<V> value;
};
// Use of `auto` as the type for a non-type template parameter
template<auto n>
struct B {};
void ecall_cxx17_template_parameter() {
    // Allow typename (as an alternative to class) in a template template parameter
    [[maybe_unused]] auto myMap = Map<std::string, int>{};

    // A non-type template parameter with a placeholder type
    [[maybe_unused]] B<5> b1;   // OK: non-type template parameter type is int
    [[maybe_unused]] B<'a'> b2; // OK: non-type template parameter type is char
}

// compile-time static `if`
template<typename T>
auto get_value(T t)
{
    if constexpr (std::is_pointer_v<T>)
        return *t; // deduces return type to int for T = int*
    else
        return t;  // deduces return type to int for T = int
}
void ecall_cxx17_compile_time_if() {
    int v = 1234;
    assert(get_value(&v) == get_value(v));
}

void ecall_cxx17_inline_variable() {
    printf("inline variable: %s\n", message);
}

void ecall_cxx17_structured_binding() {
    std::set<std::string> myset{"hello"};
    std::stringstream ss;
    for (int i{2}; i; --i) {
        ss.str("");
        if (auto [iter, success] = myset.insert("Hello"); success) {
            ss << std::quoted(*iter);
            printf("Insert is successful. The value is %s\n", ss.str().c_str());
        } else {
            ss << std::quoted(*iter);
            printf("The value %s already exists in the set.\n", ss.str().c_str());
        }
    }
}

void ecall_cxx17_initializer_in_if_switch() {
    struct Device
    {
        enum State { SLEEP, READY, BAD };
        auto state() const { return m_state; }
    private:
        State m_state{};
    };
 
    switch (auto dev = Device{}; dev.state())
    {
        case Device::SLEEP:
            printf("device state: SLEEP\n");
            break;
        case Device::READY:
            printf("device state: READY\n");
            break;
        case Device::BAD:
            printf("device state: BAD\n");
            break;
    }

    std::map<int, std::string> m{{0, "Intel"}, {1, "SGX"}, {2, "SDK"}};
    if (auto it = m.find(1); it != m.end()) {
        printf("%s\n", it->second.c_str()); 
    } else {
        printf("Not found\n");
    }

}

void ecall_cxx17_u8_character_literals() {
    printf("UTF-8 character literals: u8'a' is decimal %d\n", u8'a');
}

namespace Intel::SGX::SDK {
    void cxx17_nested_namespace() {
        printf("Hello from nested namespace\n");
    }
}
void ecall_cxx17_nested_namespace() {
    Intel::SGX::SDK::cxx17_nested_namespace();
}

struct LambdaCapture {
    int accu = 0, incre = 0;
    LambdaCapture(int a, int b):accu(a), incre(b) {}
    LambdaCapture &increment() {
        accu += incre;
        return *this;
    }
    void show() const {
        [*this]() {
            printf("accu: %d, incre: %d\n", accu, incre);
        }();
    }
};
void ecall_cxx17_lambda_capture_this_by_value() {
    auto lc = LambdaCapture(10, 5);
    lc.increment().increment();
    lc.show();
}

void ecall_cxx17_constexpr_lambda() {
    auto Fwd = [](int(*fp)(int), auto a){ return fp(a); };
    auto C = [](auto a){ return a; };
    static_assert(Fwd(C, 3) == 3);
}

void g(){}
void h(){}
void i(){}
void cxx17_fallthrough(int n) {
  switch (n) {
    case 1:
    case 2:
      g();
     [[fallthrough]];
    case 3: // no warning on fallthrough
      h();
    case 4: // compiler may warn on fallthrough
      if(n < 3) {
          i();
          [[fallthrough]]; // OK
      }
      else {
          return;
      }
    case 5:
      while (false) {
        [[fallthrough]]; // ill-formed: next statement is not part of the same iteration
      }
    case 6:
      [[fallthrough]]; // ill-formed, no subsequent case or default label
  }
}

struct [[nodiscard]] error_info {};
error_info enable_missile_safety_mode() {return {};}
void cxx17_nodiscard() {
   enable_missile_safety_mode(); // compiler may warn on discarding a nodiscard value
}

#if __has_include(<optional>)
#  include <optional>
#  define has_optional 1
   template<class T> using optional_t = std::optional<T>;
#elif __has_include(<experimental/optional>)
#  include <experimental/optional>
#  define has_optional -1
   template<class T> using optional_t = std::experimental::optional<T>;
#else
#  define has_optional 0
#  include <utility>

template<class V>
class optional_t
{
    V v_{}; bool has_{false};
public:
    optional_t() = default;
    optional_t(V&& v) : v_(v), has_{true} {}
    V value_or(V&& alt) const& { return has_ ? v_ : alt; }
    /*...*/
};
#endif
void ecall_cxx17_has_include() {
    if (has_optional > 0)
        printf("<optional> is present\n");
    else if (has_optional < 0)
        printf("<experimental/optional> is present\n");
    else
        printf("<optional> is not present\n");

    optional_t<int> op;
    printf("op = %d\n", op.value_or(-1));
    op = 42;
    printf("op = %d\n", op.value_or(-1));
}

int add(int first, int second) { return first + second; }
void ecall_cxx17_apply() {
    printf("sum of the pair elements: %d\n", std::apply(add, std::pair(1, 2)));
}

struct FromTuple {
    FromTuple(int first, float second, int third) {
        printf("%d, %.2f, %d\n", first, second, third);
    }
};
void ecall_cxx17_make_from_tuple() {
   auto tuple = std::make_tuple(42, 3.14f, 0);
   std::make_from_tuple<FromTuple>(std::move(tuple));
}

void ecall_cxx17_tuple_deduction_guides() {
#if !defined(__cpp_deduction_guides) || __cpp_deduction_guides < 201611
    // not supported
    return;
#else
    int a[2], b[3], c[4];
    std::tuple t1{a, b, c};
#endif
}

void ecall_cxx17_any() {
    std::any a = 1;
    printf("%s:%d\n", a.type().name(), std::any_cast<int>(a));
    a = 3.14;
    printf("%s:%f\n", a.type().name(), std::any_cast<double>(a));
    a = true;
    printf("%s:%d\n", a.type().name(), std::any_cast<bool>(a));

    try
    {
        a = 1;
        printf("%f\n", std::any_cast<float>(a));
    }
    catch (const std::bad_any_cast& e)
    {
        printf("%s\n", e.what());
    }

    a = 2;
    if (a.has_value())
    {
        printf("%s:%d\n", a.type().name(), std::any_cast<int>(a));
    }

    a.reset();
    if (!a.has_value())
    {
        printf("no value\n");
    }

    a = 3;
    int* ia = std::any_cast<int>(&a);
    printf("%d\n", *ia);
}

// optional can be used as the return type of a factory that may fail
std::optional<std::string> create(bool b) {
    if (b)
        return "Godzilla";
    return {};
}
// std::nullopt can be used to create any (empty) std::optional
auto create2(bool b) {
    return b ? std::optional<std::string>{"Godzilla"} : std::nullopt;
}
// std::reference_wrapper may be used to return a reference
auto create_ref(bool b) {
    static std::string value = "Godzilla";
    return b ? std::optional<std::reference_wrapper<std::string>>{value}
             : std::nullopt;
}
void ecall_cxx17_optional() {
    printf("create(false) returned %s\n", create(false).value_or("empty").c_str());

    // optional-returning factory functions are usable as conditions of while and if
    if (auto str = create2(true)) {
        printf("create2(true) returned %s\n", (*str).c_str());
    }

    if (auto str = create_ref(true)) {
        // using get() to access the reference_wrapper's value
        printf("create_ref(true) returned %s\n", str->get().c_str());
        str->get() = "Mothra";
        printf("modifying it changed it to %s\n", str->get().c_str());
    }
}

void ecall_cxx17_variant() {
    std::variant<int, float> v, w;
    v = 42;                     // v contains int
    int i = std::get<int>(v);
    assert(42 == i);            // succeeds
    w = std::get<int>(v);
    w = std::get<0>(v);         // same effect as the previous line
    w = v;                      // same effect as the previous line

    // std::get<double>(v);     // error: no double in [int, float]
    // std::get<3>(v);          // error: valid index values are 0 and 1

    try {
      std::get<float>(w);       // w contains int, not float: will throw
    }
    catch (const std::bad_variant_access& ex) {
        printf("%s\n", ex.what());
    }

    std::variant<std::string> x("abc");
    // converting constructors work when unambiguous
    x = "def";                  // converting assignment also works when unambiguous

    std::variant<std::string, void const*> y("abc");
    // casts to void const * when passed a char const *
    assert(std::holds_alternative<void const*>(y));
    y = "xyz"s;
    assert(std::holds_alternative<std::string>(y));
}

#include <experimental/functional>
void ecall_cxx17_searchers() {
    std::string haystack = "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
                     " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";
    std::string needle = "pisci";

    printf("Using std::default_searcher\n");
    // default_searcher
    auto it = std::search(haystack.begin(), haystack.end(),
                   std::default_searcher(
                       needle.begin(), needle.end()));
    if(it != haystack.end())
        printf("The string %s found at offset %d\n", needle.c_str(), it - haystack.begin());
    else
        printf("The string %s not found\n", needle.c_str());

    printf("Using std::boyer_moore_searcher\n");
    if (const auto it = std::search(haystack.begin(), haystack.end(),
            std::experimental::fundamentals_v1::boyer_moore_searcher(needle.begin(), needle.end()));
        it != haystack.end()
    ) {
        printf("The string %s found at offset %d\n", needle.c_str(), it - haystack.begin());
    } else {
        printf("The string %s not found\n", needle.c_str());
    }

    printf("Using std::boyer_moore_searcher\n");
    if (const auto it = std::search(haystack.begin(), haystack.end(),
            std::experimental::fundamentals_v1::boyer_moore_horspool_searcher(needle.begin(), needle.end()));
        it != haystack.end()
    ) {
        printf("The string %s found at offset %d\n", needle.c_str(), it - haystack.begin());
    } else {
        printf("The string %s not found\n", needle.c_str());
    }
}

void ecall_cxx17_std_as_const() {
    std::string mutableString = "Hello World!";
    auto&& constRef = std::as_const(mutableString);
    // mutableString.clear(); // OK
    // constRef.clear();      // error: 'constRef' is 'const' qualified but 'clear' is not marked const
    assert( &constRef == &mutableString );
}

static void print(std::string rem, auto first, auto last) {
    printf("%s", rem.c_str());
    for (; first != last; ++first)
        printf("%s ", (*first).c_str());
    printf("\n");
}
void ecall_cxx17_uninitialized_memory_algorithms() {
    struct Tracer {
        int value;
        ~Tracer() { printf("%d destructed\n", value); }
    };

    alignas(Tracer) unsigned char buffer[sizeof(Tracer) * 3];

    for (int i = 0; i < 3; ++i)
        new(buffer + sizeof(Tracer) * i) Tracer{i}; //manually construct objects

    auto ptr = std::launder(reinterpret_cast<Tracer*>(buffer));

    for (int i = 0; i < 3; ++i)
        std::destroy_at(ptr + i);


    for (int i = 0; i < 3; ++i)
        new(buffer + sizeof(Tracer) * i) Tracer{i}; //manually construct objects

    auto ptr2 = std::launder(reinterpret_cast<Tracer*>(buffer));

    std::destroy(ptr2, ptr2 + 3);


    for (int i = 0; i < 3; ++i)
        new(buffer + sizeof(Tracer) * i) Tracer{i}; //manually construct objects

    auto ptr3 = std::launder(reinterpret_cast<Tracer*>(buffer));

    std::destroy_n(ptr3, 3);

    struct S { std::string m{ "Default value" }; };

    constexpr int n {3};
    alignas(alignof(S)) unsigned char mem[n * sizeof(S)];

    try
    {
        auto first {reinterpret_cast<S*>(mem)};
        auto last {first + n};

        std::uninitialized_value_construct(first, last);

        for (auto it {first}; it != last; ++it) {
            printf("%s\n", it->m.c_str());
        }

        std::destroy(first, last);
    }
    catch(...)
    {
        printf("Exception!\n");
    }

    // Notice that for "trivial types" the uninitialized_value_construct
    // zero-fills the given uninitialized memory area.
    int v[] { 1, 2, 3, 4 };
    for (const int i : v) { printf("%d ", i); }
    printf("\n");
    std::uninitialized_value_construct(std::begin(v), std::end(v));
    for (const int i : v) { printf("%d ", i); }
    printf("\n");

    std::string in[] { "Home", "Work!" };
    print("initially, in: ", std::begin(in), std::end(in));

    constexpr auto sz = std::size(in);
    alignas(alignof(std::string)) unsigned char out[sizeof(std::string) * sz];
    try {
        auto first {reinterpret_cast<std::string*>(out)};
        auto last {first + sz};
        std::uninitialized_move(std::begin(in), std::end(in), first);

        print("after move, in: ", std::begin(in), std::end(in));
        print("after move, out: ", first, last);

        std::destroy(first, last);
    }
    catch (...) {
        printf("Exception!\n");
    }
}

void ecall_cxx17_aligned_alloc() {
    int* p = static_cast<int*>(std::aligned_alloc(1024, 1024));
    printf("1024-byte aligned address: %p\n", static_cast<void*>(p));
    free(p);
}

void ecall_cxx17_owner_less() {
    int * p = new int (10);

    std::shared_ptr<int> a (new int (20));
    std::shared_ptr<int> b (a,p);

    // standard set container: cannot contain duplicates.
    std::set < std::shared_ptr<int> > value_based;
    std::set < std::shared_ptr<int>, std::owner_less<std::shared_ptr<int>> > owner_based;

    value_based.insert (a);
    value_based.insert (b);

    owner_based.insert (a);
    owner_based.insert (b);  // overwrites (same owned pointer)

    printf("value_based.size() is %d\n", value_based.size());
    printf("owner_based.size() is %d\n", owner_based.size());

    delete p;
}

void ecall_cxx17_shared_ptr_for_array() {
    const std::size_t arr_size = 10;
    std::shared_ptr<int[]> pis(new int[10]{0,1,2,3,4,5,6,7,8,9});
    for (std::size_t i = 0; i < arr_size; i++){
        printf("%d ", pis[i]);
    }
    printf("\n");
}

class alignas(64) Vec3d {
    double x, y, z;
};
void ecall_cxx17_align_new_delete() {
    printf("sizeof(Vec3d) is %u\n", sizeof(Vec3d));
    printf("alignof(Vec3d) is %u\n", alignof(Vec3d));

    auto vec3d = Vec3d{};
    auto pVec = new Vec3d[10];

    if(reinterpret_cast<uintptr_t>(&vec3d) % alignof(Vec3d) == 0)
        printf("vec3d is aligned to alignof(Vec3d)!\n");
    else
        printf("vec3d is not aligned to alignof(Vec3d)!\n");

    if(reinterpret_cast<uintptr_t>(pVec) % alignof(Vec3d) == 0)
        printf("pVec is aligned to alignof(Vec3d)!\n");
    else
        printf("pVec is not aligned to alignof(Vec3d)!\n");

    delete[] pVec;
}

void ecall_cxx17_std_byte() {
    std::byte b{0b10100101};
    printf("1. %d\n", std::to_integer<int>(b));
 
    b <<= 1;
    printf("2. %d\n", std::to_integer<int>(b));
 
    printf("3. %d\n", std::to_integer<int>(b>>1));
    printf("4. %d\n", std::to_integer<int>(b<<1));
 
    b |= std::byte{0b11110000};
    printf("5. %d\n", std::to_integer<int>(b));
 
    b &= std::byte{0b11110000};
    printf("6. %d\n", std::to_integer<int>(b));
 
    b ^= std::byte{0b11111111};
    printf("7. %d\n", std::to_integer<int>(b));
}

// func is enabled if all Ts... have the same type as T
template<typename T, typename... Ts>
std::enable_if_t<std::conjunction_v<std::is_same<T, Ts>...>>
func(T, Ts...) {
    printf("all types in pack are T\n");
}
// otherwise
template<typename T, typename... Ts>
std::enable_if_t<!std::conjunction_v<std::is_same<T, Ts>...>>
func(T, Ts...) {
    printf("not all types in pack are T\n");
}
// values_equal<a, b, T>::value is true if and only if a == b.
template <auto V1, decltype(V1) V2, typename T>
struct values_equal : std::bool_constant<V1 == V2> {
  using type = T;
};
// default_type<T>::value is always true
template <typename T>
struct default_type : std::true_type {
  using type = T;
};
// Now we can use disjunction like a switch statement:
template <int I>
using int_of_size = typename std::disjunction<  //
    values_equal<I, 1, std::int8_t>,            //
    values_equal<I, 2, std::int16_t>,           //
    values_equal<I, 4, std::int32_t>,           //
    values_equal<I, 8, std::int64_t>,           //
    default_type<void>                          // must be last!
    >::type;

void ecall_cxx17_std_conjunction_disjunction_negation() {
    func(1, 2, 3);
    func(1, 2, "hello!");

    static_assert(sizeof(int_of_size<1>) == 1);
    static_assert(sizeof(int_of_size<2>) == 2);
    static_assert(sizeof(int_of_size<4>) == 4);
    static_assert(sizeof(int_of_size<8>) == 8);
    static_assert(std::is_same_v<int_of_size<13>, void>);

    static_assert(
    std::is_same_v<
        std::bool_constant<true>,
        typename std::negation<std::bool_constant<false>>::type>,
    "");

    static_assert(
    std::is_same_v<
        std::bool_constant<false>,
        typename std::negation<std::bool_constant<true>>::type>,
    "");
}

auto func2(char) -> int (*)() { return nullptr; }
void ecall_cxx17_invoke() {
    static_assert( std::is_invocable_v<int()> );
    static_assert( not std::is_invocable_v<int(), int> );
    static_assert( std::is_invocable_r_v<int, int()> );
    static_assert( not std::is_invocable_r_v<int*, int()> );
    static_assert( std::is_invocable_r_v<void, void(int), int> );
    static_assert( not std::is_invocable_r_v<void, void(int), void> );
    static_assert( std::is_invocable_r_v<int(*)(), decltype(func2), char> );
    static_assert( not std::is_invocable_r_v<int(*)(), decltype(func2), void> );

	auto add1 = [](int a) -> int { return a + 1; };
	static_assert(std::is_invocable_r_v<int, decltype(add1), int>);
	static_assert(__cpp_lib_invoke);
	assert(std::invoke(add1, 2) == 3);

    static_assert(std::negation_v<std::bool_constant<false>>);
}

// constructs a T at the uninitialized memory pointed to by p
// using list-initialization for aggregates and non-list initialization otherwise
template<class T, class... Args>
T* construct(T* p, Args&&... args) {
    if constexpr(std::is_aggregate_v<T>) {
        return ::new (static_cast<void*>(p)) T{std::forward<Args>(args)...};
    }
    else {
        return ::new (static_cast<void*>(p)) T(std::forward<Args>(args)...);
    }
}
struct A { int x, y; };
struct Na { Na(int, const char*) { } };

void ecall_cxx17_is_aggregate() {
    std::aligned_union_t<1, A, Na> storage;
    [[maybe_unused]] A* a = construct(reinterpret_cast<A*>(&storage), 1, 2);
    [[maybe_unused]] Na* b = construct(reinterpret_cast<Na*>(&storage), 1, "hello");
}

void ecall_cxx17_is_swappable() {
    printf("std::is_swappable<int&>::value: %s\n", std::is_swappable<int&>::value ? "true" : "false");
}

void ecall_cxx17_std_has_unique_object_representations() {
    printf("A has unique object representation: %d\n", std::has_unique_object_representations_v<A>);
    printf("Na has unique object representation: %d\n", std::has_unique_object_representations_v<Na>);
}

void ecall_cxx17_clamp() {
    static_assert(std::clamp(1, 2, 10) == 2);
    static_assert(std::clamp(3, 2, 10) == 3);
    static_assert(std::clamp(12, 2, 10) == 10);
}

void ecall_cxx17_reduce() {
    const std::vector<double> v(100000, 0.1);
    auto sum = std::reduce(v.cbegin(), v.cend());
    printf("sum: %.2f\n", sum);
}

void ecall_cxx17_inclusive_exclusive_scan() {
    std::vector data {3, 1, 4, 1, 5, 9, 2, 6};
    decltype(data) ret;
 
    printf("exclusive sum: ");
    std::exclusive_scan(data.begin(), data.end(),
        std::back_inserter(ret),
        0);
    for (auto e : ret) {
        printf("%d ", e);
    }
    printf("\n");

    ret.clear();
    printf("inclusive product: ");
    std::inclusive_scan(data.begin(), data.end(),
	    std::back_inserter(ret),
	    std::multiplies<>{});
    for (auto e : ret) {
        printf("%d ", e);
    }
    printf("\n");
}

void ecall_cxx17_gcd_lcm() {
    constexpr int p {2 * 2 * 3};
    constexpr int q {2 * 3 * 3};
    static_assert(2 * 3 == std::gcd(p, q));
    static_assert(2 * 2 * 3 * 3 == std::lcm(p, q));
}

void print_map(std::string_view comment, const auto& data)
{
    printf("%s", comment);
    for (auto [k, v] : data)
        printf("  %d(%c)", k, v);
    printf("\n");
}
void ecall_cxx17_map_extract_merge() {
    std::map<int, char> cont{{1, 'a'}, {2, 'b'}, {3, 'c'}};
 
    print_map("Start:", cont);
 
    // Extract node handle and change key
    auto nh = cont.extract(1);
    nh.key() = 4; 
 
    print_map("After extract and before insert:", cont);
 
    // Insert node handle back
    cont.insert(std::move(nh));
 
    print_map("End:", cont);

    std::map<int, std::string> ma {{1, "apple"}, {5, "pear"}, {10, "banana"}};
    std::map<int, std::string> mb {{2, "zorro"}, {4, "batman"}, {5, "X"}, {8, "alpaca"}};
    std::map<int, std::string> u;
    u.merge(ma);
    printf("ma.size(): %d\n", ma.size());
    u.merge(mb);
    printf("mb.size(): %d\n", mb.size());
    printf("mb.at(5): %s\n", mb.at(5).c_str());
    for(auto const &kv: u)
        printf("%d, %s\n", kv.first, kv.second.c_str());
}

auto print_node = [](const auto &node) {
    printf("[%s] = %s\n", node.first.c_str(), node.second.c_str());
};
auto print_result_emplace = [](auto const &pair) {
    printf("%s", (pair.second ? "inserted: " : "ignored:  "));
    print_node(*pair.first);
};
auto print_result_insert = [](auto const &pair) {
    printf("%s", (pair.second ? "inserted: " : "assigned:  "));
    print_node(*pair.first);
};
void ecall_cxx17_map_try_emplace_insert_or_assign() {
    using namespace std::literals;
    std::map<std::string, std::string> m;
    print_result_emplace( m.try_emplace("a", "a"s) );
    print_result_emplace( m.try_emplace("b", "abcd") );
    print_result_emplace( m.try_emplace("c", 10, 'c') );
    print_result_emplace( m.try_emplace("c", "Won't be inserted") );
    for (const auto &p : m) { print_node(p); }

    std::map<std::string, std::string> myMap;
    print_result_insert( myMap.insert_or_assign("a", "apple"     ) );
    print_result_insert( myMap.insert_or_assign("b", "banana"    ) );
    print_result_insert( myMap.insert_or_assign("c", "cherry"    ) );
    print_result_insert( myMap.insert_or_assign("c", "clementine") );
    for (const auto &node : myMap) { print_node(node); }
}

void ecall_cxx17_std_size_empty_data() {
    std::vector<int> v = { 3, 1, 4 };
    printf("size of vector: %d, empty? %s\n", std::size(v), std::empty(v) ? "true" : "false"); 
    int a[] = { -5, 10, 15 };
    printf("size of array: %d, empty? %s\n", std::size(a), std::empty(v) ? "true" : "false"); 

    std::string s {"Hello SGX!\n"};
    char cstr[20];
    std::strncpy(cstr, std::data(s), std::size(s)+1);
    printf("%s", cstr);
}

struct Foo {
    int count = std::uncaught_exceptions();
    ~Foo() {
        printf("%s\n", count == std::uncaught_exceptions()
            ? "~Foo() called normally"
            : "~Foo() called during stack unwinding");
    }
};
void ecall_cxx17_uncaught_exceptions() {
    Foo f;
    try {
        Foo f;
        printf("Exception thrown\n");
        throw std::runtime_error("test exception");
    } catch (const std::exception& e) {
        printf("Exception caught: %s\n", e.what());
    }
}

void ecall_cxx17_reference() {
    static_assert(std::is_reference_v<char&>);
	static_assert(std::is_lvalue_reference_v<char&>);
	static_assert(std::is_rvalue_reference_v<char&&>);

}

void ecall_cxx17_static_assert() {
    static_assert(03746 == 2022); // since C++17 the message string is optional
}

void ecall_cxx17_auto_deduction_from_braced_init_list() {
    auto s = std::string{"Hello C++17"};
    printf("%s\n", s.c_str());
}

void ecall_cxx17_hexadecimal_floating_point_literals() {
    printf("Hexadecimal floating literals:\n");
    printf("  0x10.1p0 is %f\n", 0x10.1p0);
    printf("  0x1p5 is %f\n", 0x1p5);
}

void ecall_cxx17_string_view() {
    constexpr std::string_view unicode[] {
        "▀▄─", "▄▀─", "▀─▄", "▄─▀"
    };

    for (int y{}, p{}; y != 3; ++y, p = ((p + 1) % 4)) {
        for (int x{}; x != 16; ++x)
            printf("%s", unicode[p]);
        printf("\n");
    }
}

class DemoConditionVariable
{
    std::mutex mtx;
    std::condition_variable cond_var;
    bool data_loaded;
public:
    DemoConditionVariable()
    {
        data_loaded = false;
    }
    void load_data()
    {
        //Simulating loading of the data
        printf("[condition_variable] Loading Data...\n");
		{
			// Locking the data structure
			std::scoped_lock guard(mtx);
			// Setting the flag to true to signal load data completion
			data_loaded = true;
		}
        // Notify to unblock the waiting thread
        cond_var.notify_one();
    }
    bool is_data_loaded()
    {
        return data_loaded;
    }
    void main_task()
    {
        printf("\n");
        printf("[condition_variable] Running condition variable demo.\n");

        // Acquire the lock
        std::unique_lock<std::mutex> lck(mtx);

        printf("[condition_variable] Waiting for the data to be loaded in the other thread.\n");
        cond_var.wait(lck, std::bind(&DemoConditionVariable::is_data_loaded, this));
        printf("[condition_variable] Processing the loaded data.\n");
        printf("[condition_variable] Done.\n");
    }
};

DemoConditionVariable app;

//E-call used by condition_variable demo - processing thread
void ecall_condition_variable_run()
{
    app.main_task();
}

//E-call used by condifion_variable demo - loader thread
void ecall_condition_variable_load()
{
    app.load_data();
}
