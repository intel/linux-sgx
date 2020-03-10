------------------------
Purpose of SampleCommonLoader
------------------------
The project demonstrates how to use these Enclave Common Loader Layer APIs: 
- enclave_create
- enclave_load_data
- enclave_initialize
- enclave_delete

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) Enclave Common Loader and its development package for Linux* OS
2. Build the project with the prepared Makefile:
    a. Build the project
        $ make
    b. Clean the project
        $ make clean
    c. Re-build the project
        $ make rebuild
3. Execute the binary directly:
    $ ./sample
