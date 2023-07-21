#
# Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(patsubst %/,%,$(dir $(mkfile_path)))

include ../../buildenv.mk

LIB_NAME= libsgx_mbedcrypto.a
SRC_DIR = mbedtls_code

CFLAGS := -I$(COMMON_DIR)/inc/internal \
	-I$(COMMON_DIR)/inc          \
	-I$(COMMON_DIR)/inc/tlibc

CFLAGS += $(ENCLAVE_CFLAGS) $(SGX_COMMON_CFLAGS) -Werror -fno-exceptions -fPIC

.PHONY: all clean library/libmbedcrypto.a
all: library/libmbedcrypto.a sgx_mbedtls_utils.o | $(BUILD_DIR)
	@$(RM) -rf .libs && mkdir .libs
	@cd .libs && $(AR) x ../$(SRC_DIR)/build/library/libmbedcrypto.a
	@$(AR) rsD $(LIB_NAME) .libs/*.o sgx_mbedtls_utils.o
	@$(CP) $(LIB_NAME) $(BUILD_DIR)/

$(BUILD_DIR):
	@$(MKDIR) $@

library/libmbedcrypto.a:
ifeq ($(shell grep -c sgx mbedtls_code/library/rsa.c), 0)
	@echo "Apply patch for SGX..."
	@cd $(SRC_DIR) && git apply ../sgx_mbedtls.patch
	@echo "Done."
endif
	@rm -rf $(SRC_DIR)/build && mkdir $(SRC_DIR)/build
	@cd $(SRC_DIR)/build && cmake  -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} $(CFLAGS) -include$(current_dir)/bypass_to_sgxmbed.h " -DGEN_FILES=OFF -DCMAKE_C_COMPILER_WORKS=TRUE .. && make mbedcrypto

sgx_mbedtls_utils.o: sgx_mbedtls_utils.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

clean:
	@$(RM) -rf *.a *.o .libs $(BUILD_DIR)/$(LIB_NAME) $(SRC_DIR)/build
