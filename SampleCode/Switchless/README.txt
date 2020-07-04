------------------------
Purpose of Switchless
------------------------
The project demonstrates how to use Fast OCalls provided by sgx_switchless.

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make SGX_MODE=HW SGX_DEBUG=1
    b. Hardware Mode, Pre-release build:
        $ make SGX_MODE=HW SGX_PRERELEASE=1
    c. Hardware Mode, Release build:
        $ make SGX_MODE=HW
3. Execute the binary directly:
    $ ./app

-------------------------------------------------
Launch token initialization
-------------------------------------------------
If using libsgx-enclave-common or sgxpsw under version 2.4, an initialized variable launch_token needs to be passed as the 3rd parameter of API sgx_create_enclave. For example,

sgx_launch_token_t launch_token = {0};
sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
