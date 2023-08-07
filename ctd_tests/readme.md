# CTD Test Scripts

## Overview

We provide 3 tests for CTD:
- decoding correctness test(differential testing with existing decoder Xed)
- constant time test(one formal verification and one execution test).
- a unit test that triggers the CTD within an SGX enclave
The performance test is already in the sdk repo by controlling the `sample` run times. In this folder, the `dudect` and `pitchfork` are for constant time testing, `xed` is for the differential testing, and `CTDTest` is the unit test. Each folder has its own README.

## Precondtions

To launch the test, we need to install: Rust, llvm-11, minisat and need to convert the source code into clang-11 compiled version.

## Instructions on how to convert source code to be compiled by clang-11

There are 3 parts need to be changed:

1. Built-in intrinsic. Previously we use gcc intrinsic in the source code since the sdk doesn't allow us to include avx2 header file. We need to add the header file and convert them back, otherwise these intrinsic are gcc only. The following intrinsic are I encountered(gcc_version -> clang_version):

                __builtin_ia32_pandn128 -> _mm_andnot_si128
                __builtin_ia32_andnotsi256 -> _mm256_andnot_si256
                __builtin_ia32_vinsertf128_si256 -> _mm256_insertf128_si256
                __builtin_ia32_si256_si -> _mm256_castsi128_si256

2. Inline asm. Somehow clang doesn't recognize the inline asm in the gcc style. We can just delete them and leave them as `?:` operator in C. It's guaranteed clang will output CMOVcc instrictions for optimization levels greater than 1.

3. For formal verification in pitchfork, we need to comment the `cselect` operations in `register_select` function otherwise the symbolic engine will overflow.

## Launch test

For details on how to launch each test, check their folders for details.