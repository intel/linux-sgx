The ippcp library is built based on the IPP Cryptography open source project:
   * https://github.com/intel/ipp-crypto/
   * tag: [ippcp_2021.7](https://github.com/intel/ipp-crypto/tree/ippcp_2021.7)

In order to build your own IPP crypto, please follow below steps:
1. Download the prebuilt mitigation tools package `as.ld.objdump.{ver}.tar.gz` from [01.org](https://download.01.org/intel-sgx/latest/linux-latest/), extract the package and copy the tools to `/usr/local/bin`.
2. Read the ipp-crypto README to prepare your build environment.
3. Make sure ipp-crypto source code is prepared.
4. Build the target ippcp library with the prepared Makefile:
    1. Build the target ippcp library with All-Loads-Mitigation:
       $ make MITIGATION-CVE-2020-0551=LOAD
    2. Build the target ippcp library with Branch-Mitigation:
       $ make MITIGATION-CVE-2020-0551=CF
    3. Build the target ippcp library with No-Mitigation:
       $ make
The built static library `libippcp.a` and header files will be copied into the right place.
Remember to "make clean" before switching the build.

For the IPP crypto reproducible build, please follow the instructions in [reproducibility README.md](../../linux/reproducibility/README.md) to reproduce the prebuilt IPP crypto.

These are the steps to build the IPP Crypto-based dispatcher code after you built the library:
1. `cd ./ipp-crypto/tools/ipp_custom_library_tool_python`
2. `awk -F\, '/IPPAPI\(/ {print $2}' ../../../inc/ippcp.h | awk '{print $1}' >functions.txt`
3. `python3 main.py -c -g -p ./ -ff functions.txt -arch intel64 -d sse42 avx2 avx512ifma -root ../../build/.build/RELEASE/ --prefix sgx_disp_`
`Intel(R) Custom Library Tool console version is on...`
`Current package: Intel(R) Integrated Performance Primitives Cryptography Version 2021.7.0 (11.5 )`
`Generation completed!`
4. `./build_custom_library_intel64.sh`
`Build completed!`
5. `cp custom_dispatcher/intel64/* ../../../../../sdk/tlibcrypto/ipp/ipp_disp/intel64/`
