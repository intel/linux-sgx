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

TOP_DIR  = ../..
include $(TOP_DIR)/buildenv.mk

CERT_UTIL_DIR   := ../ttls
SGX_QV_PATH ?= ../../external/dcap_source/QuoteVerification
PREBUILD_OPENSSL_PATH ?= $(SGX_QV_PATH)/../prebuilt/openssl
CBOR_PATH ?= $(LINUX_EXTERNAL_DIR)/cbor
LIBCBOR_PATH := $(CBOR_PATH)/untrusted/lib
CBOR_INCLUDE := $(CBOR_PATH)/untrusted/include

INCLUDE += -I.
INCLUDE += -I$(COMMON_DIR)              \
           -I$(COMMON_DIR)/inc          \
           -I$(COMMON_DIR)/inc/internal \
           -I$(PREBUILD_OPENSSL_PATH)/inc \
           -I$(CBOR_PATH)/untrusted/include \
           -I$(CERT_UTIL_DIR) \
           -I$(SGX_QV_PATH)/QvE/Include \
           -I$(SGX_QV_PATH)/dcap_quoteverify/inc \
           -I$(SGX_QV_PATH)/../QuoteGeneration/quote_wrapper/common/inc \
           -I$(SGX_QV_PATH)/../QuoteGeneration/quote_wrapper/ql/inc \
		   -I$(SGX_QV_PATH)/../QuoteGeneration/pce_wrapper/inc


CXXFLAGS += $(COMMON_FLAGS) $(COMMON_LDFLAGS) -fPIC -Werror -Wno-unused-parameter -g


vpath %.cpp .. $(COMMON_DIR)/src $(CERT_UTIL_DIR)

SRC :=  utls.cpp

LIBCBOR := libcbor.a

HOST_CERT_SRC := $(CERT_UTIL_DIR)/cert_verifier.cpp

OBJ := $(SRC:.cpp=.o)

CERT_OBJ := $(HOST_CERT_SRC:.cpp=.o)

LIBNAME  = libsgx_utls.a

CBOR_HEADER := cbor.h

.PHONY: all cbor_untrusted
all: $(LIBNAME) | $(BUILD_DIR)
	$(CP) $(LIBNAME) $|

$(LIBNAME): $(OBJ) $(CERT_OBJ)
	$(AR) rs $@ $(OBJ) $(CERT_OBJ)
	$(MKDIR) $(BUILD_DIR)/.libcbor
	$(RM) $(BUILD_DIR)/.libcbor/* && cd $(BUILD_DIR)/.libcbor && $(AR) x $(LIBCBOR_PATH)/$(LIBCBOR)
	$(AR) rs $@ $(BUILD_DIR)/.libcbor/*.o
	@$(RM) -r $(BUILD_DIR)/.libcbor

$(OBJ): cbor_untrusted $(SRC)
	$(CXX) $(CXXFLAGS) -Wno-deprecated-declarations $(INCLUDE) -c $(SRC) -o $@

$(CERT_OBJ): $(HOST_CERT_SRC)
	$(CXX) $(CXXFLAGS) -Wno-deprecated-declarations $(INCLUDE) -c $< -o $@

$(HOST_CERT_SRC): cbor_untrusted

cbor_untrusted: 
	# before build utls, check cbor untrusted  
	@if [ ! -f $(CBOR_INCLUDE)/$(CBOR_HEADER) ] || [ ! -f $(LIBCBOR_PATH)/$(LIBCBOR) ]; then \
		$(MAKE) -C $(CBOR_PATH) cbor_untrusted; \
	fi

.PHONY: clean
clean:
	@$(RM) $(OBJ) $(CERT_OBJ)
	@$(RM) $(LIBNAME) $(BUILD_DIR)/$(LIBNAME)
	$(MAKE) -C $(CBOR_PATH) clean

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
