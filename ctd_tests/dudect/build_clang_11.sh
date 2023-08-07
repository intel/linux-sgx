#!/bin/bash
clang-11 -mavx2  -masm=intel -O3 -g -DSAMPLES=1 -DCTD_UNIT_TEST ctd.c -o ctd_test -lm
clang-11 -mavx2 -emit-llvm -masm=intel -O3 -g -DSAMPLES=1 -DCT_VERIFY=1 -DCTD_UNIT_TEST -c ctd.c -o file.bc
