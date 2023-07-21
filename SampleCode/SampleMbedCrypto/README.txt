---------------------------
Purpose of SampleMbedCrypto
---------------------------
The project demonstrates how to use Mbedtls cryptographic APIs inside SGX Enclaves.

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
        $ make SGX_MODE=HW SGX_DEBUG=1
    b. Hardware Mode, Pre-release build:
        $ make SGX_MODE=HW SGX_PRERELEASE=1
    c. Hardware Mode, Release build:
        $ make SGX_MODE=HW
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
5. Execute the binary directly:
    $ ./app
6. Remember to "make clean" before switching build mode
