#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

IPP_CONFIG = -Bbuild -DCMAKE_VERBOSE_MAKEFILE=on 
# Ignore the CMAKE C/C++ compiler check to avoid conflicts with mitigation options
IPP_CONFIG += -DCMAKE_C_COMPILER_WORKS=TRUE -DCMAKE_CXX_COMPILER_WORKS=TRUE 
IPP_SOURCE = ipp-crypto
ARCH = intel64
IPP_CONFIG += -DARCH=$(ARCH)

ENC_FLAGS = $(patsubst -fpie, -fpic, $(ENCLAVE_CFLAGS))
# ipp-crypto requires system header files
ENC_CFLAGS = $(patsubst -nostdinc, , $(ENC_FLAGS))
ENC_CXXFLAGS = $(ENC_CFLAGS)

IPP_CONFIG += -DCMAKE_C_FLAGS="$(ENC_CFLAGS)"
IPP_CONFIG += -DCMAKE_CXX_FLAGS="$(ENC_CXXFLAGS)"
comma:= ,
ASM_FLAGS = $(subst -Wa$(comma),,$(MITIGATION_ASFLAGS))
ENC_ASM_FLAGS = $(patsubst -fno-plt, , $(ASM_FLAGS))

IPP_CONFIG += -DCMAKE_ENC_ASM_FLAGS="$(ENC_ASM_FLAGS)"

SUB_DIR = no_mitigation
ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
	SUB_DIR = cve_2020_0551_load
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
	SUB_DIR = cve_2020_0551_cf
endif
OUT_DIR = lib/linux/$(ARCH)/$(SUB_DIR)/

PATCH_LOG = $(shell cd ./$(IPP_SOURCE) && git log --oneline --grep='Add mitigation support to assembly code' | cut -d' ' -f 3)
CHECK_PATCHED :=
ifneq ($(PATCH_LOG), mitigation)
CHECK_PATCHED:= ipp_source
endif


.PHONY: all build_ipp
all: build_ipp
	# copy the built out lib, header files and license to the target folder
	$(MKDIR) $(OUT_DIR)
	$(CP) ipp-crypto/build/.build/RELEASE/lib/libippcp.a $(OUT_DIR)
	$(CP) ipp-crypto/include/* ./inc/
	patch ipp-crypto/include/ippcp.h -i ./inc/ippcp19u5.patch -o ./inc/ippcp.h
	$(MKDIR) license
	$(CP) ipp-crypto/LICENSE ./license/

build_ipp: $(CHECK_PATCHED)
	cd $(IPP_SOURCE) && cmake CMakeLists.txt $(IPP_CONFIG) && cd build && make ippcp_s

.PHONY: ipp_source
ipp_source:
## Need to enable below code when release
#ifeq ($(shell git rev-parse --is-inside-work-tree), true)
#	git submodule update -f --init --recursive --remote -- $(IPP_SOURCE)
#else
	$(RM) -rf $(IPP_SOURCE)
	git clone -b ipp-crypto_2019_update5  https://github.com/intel/ipp-crypto.git --depth 1 $(IPP_SOURCE)
#endif
	cd $(IPP_SOURCE) && git am ../0001-Add-mitigation-support-to-assembly-code.patch

.PHONY: clean
clean:
	$(RM) -rf ipp-crypto/build
