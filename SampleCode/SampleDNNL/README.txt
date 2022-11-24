--------------------------
Purpose of Deep Neural Network Library (DNNL)
--------------------------
The project demonstrates Intel(R) Deep Neural Network Library (DNNL) functions inside Intel(R) SGX environment

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Enclave test key(two options):
    a. Install openssl first, then the project will generate a test key<Enclave_private_test.pem> automatically when you build the project.
    b. Rename your test key(3072-bit RSA private key) to <Enclave_private_test.pem> and put it under the <Enclave> folder.
3. Build Intel(R) SGX DNNL library.
   a. Download Intel(R) SGX source codes from: https://github.com/intel/linux-sgx
   b. Build the library.
      $ cd ./external/dnnl
      $ make
4. Install Intel(R) SGX DNNL library and header files.
   a. Copy Intel(R) SGX DNNL lib to the Intel(R) SGX SDK installation directory.
      $ cp "./sgx_dnnl/lib/libsgx_dnnl.a" "$(SGX_SDK)/lib64"
   b. Copy Intel(R) SGX DNNL header files to the Intel(R) SGX SDK header file directory.
      $ cp "./sgx_dnnl/include/*" "$(SGX_SDK)/include"

5. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
6. Build the project with the prepared Makefile:
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
7. Execute the binary directly:
    $ ./app
8. Remember to "make clean" before switching build mode

