#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE := HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1


mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJ_DIR := $(dir $(mkfile_path))
SGXSSL_DIR ?= $(PROJ_DIR)sgxssl
SGXSSL_PKG_PATH := $(SGXSSL_DIR)/Linux/package
SOCKET_DIR ?= $(PROJ_DIR)sgx_socket

#$(info "*******DEBUG MESSAGE: SGXSSL PATH SET TO***********")
#$(info "SGXSSL_DIR set to:$(SGXSSL_DIR)")

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

Urts_Library_Name := sgx_urts
U_TLS_Library_Name := sgx_utls

App_Include_Paths := -IInclude -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
endif

SGXSSL_U_Library_Name := sgx_usgxssl

SGXSSL_U_Link_Libraries := -L$(SGXSSL_PKG_PATH)/lib64 -Wl,--whole-archive -l$(SGXSSL_U_Library_Name) -Wl,--no-whole-archive
SGXTLS_U_Link_Libraries := -lsgx_utls

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) $(SGXSSL_U_Link_Libraries) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) $(SGXTLS_U_Link_Libraries) -lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto -lpthread 

######## Enclave Settings ########

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice

SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_SSL_Library_Name := sgx_tsgxssl_ssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto

SGX_TLS_Library_Name := sgx_ttls
SGX_TVL_Library_Name := sgx_dcap_tvl

Common_Enclave_Cpp_Files := $(wildcard common/*.cpp)
Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
Enclave_Include_Paths += -I$(SGXSSL_PKG_PATH)/include
Enclave_Include_Paths += -I$(SOCKET_DIR)/include

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif

Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(SGXSSL_PKG_PATH)/lib64 -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
	-l$(OpenSSL_SSL_Library_Name) -l$(OpenSSL_Crypto_Library_Name)

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie


# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library_Name) \
	-l$(SGX_TVL_Library_Name) -lsgx_ttls -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=$(shell pwd)/enclave.lds

ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else
	Build_Mode = HW_PRERELEASE
endif
