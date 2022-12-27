------------------------------
Purpose of SampleEnclaveStdcex
------------------------------
The project demonstrates several fundamental usages of Syscall and other APIs in the Stdc_ex branch of Intel(R) Software Guard Extensions (Intel(R) SGX) SDK:
- printf()
- memset_s()
- fchmod()
- mmap()
- time()
- socket related APIs

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Enclave test key(two options):
    a. Install openssl first, then the project will generate a test key<Enclave_private_test.pem> automatically when you build the project.
    b. Rename your test key(3072-bit RSA private key) to <Enclave_private_test.pem> and put it under the <Enclave> folder.
3. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
4. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        1) Enclave with no mitigation:
            $ make
    b. Hardware Mode, Pre-release build:
        1) Enclave with no mitigation:
            $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Hardware Mode, Release build:
        1) Enclave with no mitigation:
            $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
5. Execute the binary directly:
    $ ./app
6. Remember to "make clean" before switching build mode

-------------------------------------------------
Launch token initialization
-------------------------------------------------
If using libsgx-enclave-common or sgxpsw under version 2.4, an initialized variable launch_token needs to be passed as the 3rd parameter of API sgx_create_enclave. For example,

sgx_launch_token_t launch_token = {0};
sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
