#
# Copyright (C) 2011-2023 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

# build 2 librarys of libcbor : 
# libcbor.a run in untrusted
# libsgx_cbor.a run in trusted


include ../../buildenv.mk

C_ENCLAVE_FLAGS = $(ENCLAVE_CFLAGS)

CXX_ENCLAVE_FLAGS = $(C_ENCLAVE_FLAGS)
CXX_ENCLAVE_FLAGS := $(subst -nostdinc,, $(CXX_ENCLAVE_FLAGS))
CXX_ENCLAVE_FLAGS += -nostdinc++

# cbor in untrusted
CBOR_SRC = libcbor
RAW_LIBCBOR = ./untrusted/lib/libcbor.a
CBOR_DIR = ./untrusted
CBOR_LIB = $(CBOR_DIR)/lib
CBOR_LIB64 = $(CBOR_DIR)/lib64
CBOR_INCLUDE = $(CBOR_DIR)/include

# cbor in trusted
SGX_CBOR_SRC = sgx_libcbor
SGX_LIBCBOR = ./trusted/lib/libsgx_cbor.a
SGX_CBOR_DIR = ./trusted
SGX_CBOR_LIB = $(SGX_CBOR_DIR)/lib
SGX_CBOR_LIB64 = $(SGX_CBOR_DIR)/lib64
SGX_CBOR_INCLUDE = $(SGX_CBOR_DIR)/include

CBOR_CONFIG = -DCMAKE_BUILD_TYPE=Release
#ifdef DEBUG
#	CBOR_CONFIG = -DCMAKE_BUILD_TYPE=Debug
#endif

SGX_CBOR_CONFIG = $(CBOR_CONFIG) -DSGX_PROGRAM_SEARCH_PATH="$(EXT_BINUTILS_DIR)"

CHECK_SOURCE :=
NEED_PATCH := 
ifeq ("$(wildcard $(CBOR_SRC)/src/cbor.h)", "")
	CHECK_SOURCE := prepare_code
	NEED_PATCH := apply_patch
else ifeq ("$(wildcard $(SGX_CBOR_SRC)/src/cbor.h)", "")
	CHECK_SOURCE := checkout_branch
	NEED_PATCH := apply_patch
endif

.PHONY: all prepare_code apply_patch checkout_branch cbor_trusted cbor_untrusted

all: $(CHECK_SOURCE) $(NEED_PATCH) cbor_trusted cbor_untrusted
	@test -f $(RAW_LIBCBOR) && test -f $(SGX_LIBCBOR) && echo "build complete"

prepare_code:
ifeq ($(shell git rev-parse --is-inside-work-tree 2> /dev/null), true)
	git submodule update -f --init --recursive -- $(CBOR_SRC)
else
	rm -rf $(CBOR_SRC) && git clone -b v0.10.2 https://github.com/PJK/libcbor.git --depth 1 $(CBOR_SRC)
endif

checkout_branch:
	cd $(CBOR_SRC) && git checkout v0.10.2 && cd ..

apply_patch: $(CHECK_SOURCE)
	cp $(CBOR_SRC) $(SGX_CBOR_SRC) -r
	cd $(CBOR_SRC) && git apply ../raw_cbor.patch && cd ..
	cd $(SGX_CBOR_SRC) && git apply ../sgx_cbor.patch && cd ..

cbor_untrusted: $(NEED_PATCH)
	@echo "make and make install"
	@cd $(CBOR_SRC) && mkdir build && cd build && cmake ../ $(CBOR_CONFIG) && $(MAKE) && make install
	# in case of cbor lib name is installed as lib64 on CentOS
	if [ -d $(CBOR_LIB64) ]; then \
		mv $(CBOR_LIB64) $(CBOR_LIB); \
	fi

cbor_trusted: $(NEED_PATCH)
	@echo "make and make install"
	@cd $(SGX_CBOR_SRC) && mkdir build && cd build && cmake ../ $(SGX_CBOR_CONFIG) -DCMAKE_C_ENCLAVE_FLAGS="$(C_ENCLAVE_FLAGS)" && $(MAKE) && make install && cd ../..
	#in case of cbor lib is installed as lib64 on CentOS
	if [ -d $(SGX_CBOR_LIB64) ]; then \
		mv $(SGX_CBOR_LIB64) $(SGX_CBOR_LIB); \
	fi
	mv $(SGX_CBOR_LIB)/libcbor.a $(SGX_LIBCBOR)

.PHONY: clean
clean:
	rm -fr $(CBOR_SRC)/build $(SGX_CBOR_SRC)/build $(CBOR_DIR) $(SGX_CBOR_DIR)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
