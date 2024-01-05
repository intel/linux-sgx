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

include ../../buildenv.mk

ECL_VER:= $(shell awk '$$2 ~ /ENCLAVE_COMMON_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(COMMON_DIR)/inc/internal/se_version.h)

ifndef DEBUG
CXXFLAGS += -DDISABLE_TRACE
CFLAGS += -DDISABLE_TRACE
endif

CXXFLAGS += -fPIC -Werror -g
CXXFLAGS += $(ADDED_INC)

CFLAGS += -fPIC -Werror -g
CFLAGS += $(ADDED_INC)

INC += -I$(SGX_HEADER_DIR)                \
       -I$(COMMON_DIR)/inc/internal       \
       -I$(COMMON_DIR)/inc/internal/linux \
       -I$(LINUX_PSW_DIR)/urts/           \
       -I$(LINUX_PSW_DIR)/urts/linux      \
       -I$(LINUX_PSW_DIR)/enclave_common

LDFLAGS := -lwrapper -ldl
LDFLAGS += $(COMMON_LDFLAGS) -Wl,--version-script=sgx_enclave_common.lds -Wl,--gc-sections

DIR1 := $(LINUX_PSW_DIR)/enclave_common
DIR2 := $(LINUX_PSW_DIR)/urts/linux

LIB += -L$(COMMON_DIR)/se_wrapper_psw

OBJ := sgx_enclave_common.o edmm_utility.o


vpath %.cpp $(DIR1):$(DIR2)

LIBWRAPPER                   := libwrapper.a
LIBSGX_ENCLAVE_COMMON        := libsgx_enclave_common.so
LIBSGX_ENCLAVE_COMMON_FULL   := $(LIBSGX_ENCLAVE_COMMON).$(call get_full_version,ENCLAVE_COMMON_VERSION)
LIBSGX_ENCLAVE_COMMON_MAJOR  := $(LIBSGX_ENCLAVE_COMMON).$(call get_major_version,ENCLAVE_COMMON_VERSION)
LIBSGX_ENCLAVE_COMMON_STATIC := libsgx_enclave_common.a

.PHONY: all
all: $(LIBSGX_ENCLAVE_COMMON) $(LIBSGX_ENCLAVE_COMMON_STATIC) | $(BUILD_DIR)
	@$(CP) $(LIBSGX_ENCLAVE_COMMON)        $|/$(LIBSGX_ENCLAVE_COMMON_FULL)
	@$(LN) $(LIBSGX_ENCLAVE_COMMON_FULL)   $|/$(LIBSGX_ENCLAVE_COMMON_MAJOR)
	@$(LN) $(LIBSGX_ENCLAVE_COMMON_MAJOR)  $|/$(LIBSGX_ENCLAVE_COMMON)
	@$(CP) $(LIBSGX_ENCLAVE_COMMON_STATIC) $|

$(LIBSGX_ENCLAVE_COMMON): $(OBJ) $(LIBWRAPPER)
	$(CXX) $(CXXFLAGS) -shared -Wl,-soname=$(LIBSGX_ENCLAVE_COMMON_MAJOR) $(LIB) -o $@ $(OBJ) $(LDFLAGS)

$(LIBSGX_ENCLAVE_COMMON_STATIC): $(OBJ) $(LIBWRAPPER)
	$(CP) $(COMMON_DIR)/se_wrapper_psw/libwrapper.a $@
	$(AR) rcs $@ $(OBJ)

$(OBJ): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(INC) $< -o $@

$(LIBWRAPPER):
	$(MAKE) -C $(COMMON_DIR)/se_wrapper_psw/

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean::
	@$(RM) *.o $(LIBSGX_ENCLAVE_COMMON) $(LIBSGX_ENCLAVE_COMMON_STATIC) \
		$(BUILD_DIR)/$(LIBSGX_ENCLAVE_COMMON_FULL)                  \
		$(BUILD_DIR)/$(LIBSGX_ENCLAVE_COMMON_MAJOR)                 \
		$(BUILD_DIR)/$(LIBSGX_ENCLAVE_COMMON)                       \
		$(BUILD_DIR)/$(LIBSGX_ENCLAVE_COMMON_STATIC)
	$(MAKE) -C $(COMMON_DIR)/se_wrapper_psw/                   clean
