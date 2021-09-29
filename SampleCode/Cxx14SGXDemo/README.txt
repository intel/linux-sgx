-----------------------
Purpose of Cxx14SGXDemo
-----------------------

The project demonstrates several C++14 features inside the Enclave:
- standard user-defined literals
- tuple addressing via type
- std::make_unique
- std::integral_constant
- std::integer_sequence
- std::cbegin/std::cend and std::crbegin/std::crend
- std::exchange
- std::is_final
- std:quoted
- std::equal/std::mismatch/std::is_permutation new overloads
- heterogeneous lookup
- function return type deduction
- variable template
- binary literals
- digit separators
- generic lambdas
- lambda capture expressions
- attribute [[deprecated]]
- aggregate member initialization
- relaxed constexpr restrictions
- alternate type deduction on declaration

---------------------------------------------
How to Build/Execute the C++14 sample program
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
sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
