Intel(R) Software Guard Extensions Protected Code Loader (Intel(R) SGX PCL) for Linux\* OS
================================================
Introduction
------------
Intel(R) SGX PCL is intended to protect Intellectual Property (IP) within the code for Intel(R) SGX enclave applications running on the Linux* OS.

**Problem:** Intel(R) SGX provides integrity of code and confidentiality and integrity of data at run-time. However, it does NOT provide confidentiality of code offline as a binary file on disk. Adversaries can reverse engineer the binary enclave shared object.

**Solution:** The enclave shared object (.so) is encrypted at build time. It is decrypted at enclave load time. 

Intel(R) SGX PCL provides: 
1. **sgx_encrypt:** A tool to encrypt the shared object at build time. 

   See sources at sdk\encrypt_enclave.
   
2. **libsgx_pcl.a:** A library that is statically linked to the enclave and enables the decryption of the enclave at load time.

   See sources at sdk\protected_code_loader.

3. **SampleEnclavePCL:** Sample code which demonstrates how the tool and lib need to be integrated into an existing enclave project. 

Purpose of this code sample:
--------------------------
Enclave writers should compare SampleEnclave and SampleEnclavePCL. This demonstrates how the Intel(R) SGX PCL is to be integrated into the project of the enclave writer.  

Build and test the Intel(R) SGX PCL with the sample code
--------------------------------------------------------

- To compile and run the sample
```
  $ cd SampleEnclavePCL
  $ make
  $ ./app
```
