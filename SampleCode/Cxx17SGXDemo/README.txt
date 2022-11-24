-----------------------
Purpose of Cxx17SGXDemo
-----------------------

The project demonstrates several C++17 features inside the Enclave:

- New language features:
-   fold-expressions
-   class template argument deduction
-   non-type template parameters declared with auto
-   compile-time if constexpr
-   inline variables
-   structured bindings
-   initializers for if and switch
-   u8 character literal
-   simplified nested namespaces
-   using-declaration declaring multiple names
-   made noexcept part of type system
-   new order of evaluation rules
-   guaranteed copy elision
-   temporary materialization
-   lambda capture of *this
-   constexpr lambda
-   attribute namespaces don't have to repeat
-   new attributes:
-     [[fallthrough]]
-     [[maybe_unused]]
-     [[nodiscard]]
-   __has_include
-
- New library features:
-  Utility types
-    std::tuple:
-      std::apply
-      std::make_from_tuple
-    std::any
-    std::optional
-    std::variant
-    searchers
-    std::as_const
-    std::not_fn
-
-  Memory management
-      uninitialized memory algorithms
-      std::destroy_at
-      std::destroy
-      std::destroy_n
-      std::uninitialized_move
-      std::uninitialized_value_construct
-    weak_from_this
-    std::aligned_alloc
-    transparent std::owner_less
-    array support for std::shared_ptr
-    allocation functions with explicit alignment
-
-  Compile-time programming
-    std::byte
-    std::conjunction/std::disjunction/std::negation
-    type trait variable templates (xxx_+v)
-    std::is_swappable
-    is_invocable
-    is_aggregate
-    std::has_unique_object_representations
-
-  Algorithms
-    std::clamp
-    std::reduce
-    std::inclusive_scan
-    std::exclusive_scan
-    std::gcd
-    std::lcm
-
-  Iterators and containers
-    map/set extract and map/set merge
-    map/unordered_map try_emplace and insert_or_assign
-    contiguous iterators (LegacyContiguousIterator)
-    non-member std::size/std::empty/std::data
-
-  Other
-    std::launder
-    std::uncaught_exceptions

---------------------------------------------
How to Build/Execute the C++17 sample program
---------------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
3. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make
    b. Hardware Mode, Pre-release build:
        $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Hardware Mode, Release build:
        $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
4. Execute the binary directly:
    $ ./app
5. Remember to "make clean" before switching build mode

-------------------------------------------------
Launch token initialization
-------------------------------------------------
If using libsgx-enclave-common or sgxpsw under version 2.4, an initialized variable launch_token needs to be passed as the 3rd parameter of API sgx_create_enclave. For example,

sgx_launch_token_t launch_token = {0};
sgx_create_enclave(ENCLAVE_F7LENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
