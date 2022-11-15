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

include ../../buildenv.mk

ZLIB_DIR = zlib_code
LIBNAME = $(ZLIB_DIR)/final_tlibZ/build/libz.a
INCLUDEZLIB = $(ZLIB_DIR)

ZLIB_CONFIG = -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER_WORKS=TRUE -DCMAKE_CXX_COMPILER_WORKS=TRUE
ifdef DEBUG
	ZLIB_CONFIG = -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER_WORKS=TRUE -DCMAKE_CXX_COMPILER_WORKS=TRUE
	LIBNAME = $(ZLIB_DIR)/final_tlibZ/build/libz.a
endif
ENC_CXXFLAGS = $(patsubst -fpie, -fpic, $(ENCLAVE_CXXFLAGS))
ZLIB_CONFIG += -DCMAKE_CXX_FLAGS="$(ENC_CXXFLAGS)"
ZLIB_CONFIG += -DSGX_PROGRAM_SEARCH_PATH="$(EXT_BINUTILS_DIR)"

CHECK_SOURCE :=
ifeq ("$(wildcard $(ZLIB_DIR)/old)", "")
CHECK_SOURCE := zlib_code
endif

.PHONY: all
all: $(LIBNAME) $(BUILD_DIR)
	$(CP) $(LIBNAME) $(BUILD_DIR)/libsgx_z.a

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: zlib_code
zlib_code:
ifeq ($(shell git rev-parse --is-inside-work-tree), true)
	$(RM) -r $(ZLIB_DIR)/
	git submodule update -f --init $(ZLIB_DIR)
else
	$(RM) -r $(ZLIB_DIR)/
	git clone https://github.com/madler/zlib.git -b v1.2.13 --depth 1 $(ZLIB_DIR)
endif


$(LIBNAME): $(CHECK_SOURCE)
ifeq ("$(wildcard $(ZLIB_DIR)/zconf.h.output)", "")
	cd $(ZLIB_DIR) && git apply ../sgx_zlib.patch&& cd ..
endif
	$(MKDIR) zlib_code/final_tlibZ/build && cd zlib_code/final_tlibZ/build && cmake $(ZLIB_CONFIG) -DSGX=TRUE ../../ && make

.PHONY: clean
clean:
	$(RM) -rf zlib_code/final_tlibZ/build $(BUILD_DIR)/libsgx_z.a
	

.PHONY: rebuild
rebuild:
	 $(MAKE) clean
	 $(MAKE) all


