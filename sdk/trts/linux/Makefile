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

include ../../../buildenv.mk

CFLAGS += -Werror $(ENCLAVE_CFLAGS)          \
          -I$(LINUX_SDK_DIR)/trts            \
          -I$(COMMON_DIR)/inc                \
          -I$(COMMON_DIR)/inc/internal       \
          -I$(COMMON_DIR)/inc/internal/linux \
          -I$(LINUX_SDK_DIR)/tlibc           \
          -I$(LINUX_SDK_DIR)/simulation/assembly/

CXXFLAGS += -Werror $(ENCLAVE_CXXFLAGS)      \
          -I$(LINUX_SDK_DIR)/trts            \
          -I$(COMMON_DIR)/inc                \
          -I$(COMMON_DIR)/inc/internal/ 

TCFLAGS   += -nostdinc \
             -I$(COMMON_DIR)/inc/tlibc/

ifneq ($(MITIGATION-CVE-2020-0551), LOAD)
ifneq ($(MITIGATION-CVE-2020-0551), CF)
# Enable below flag to treat warning as error for assembly code
# It doesn't work for mitigation mode.
        TCFLAGS += -Wa,--fatal-warnings
endif
endif

LDCFLAGS  := -shared -nostdlib -nodefaultlibs -nostartfiles

OSSL_FIPS_SRC := ossl_fips.c
OSSL_FIPS_OBJ := $(OSSL_FIPS_SRC:.c=.o)

CPP_SRCS  := $(filter-out ../trts_emm_sim.cpp, $(wildcard ../*.cpp))
C_SRCS    := $(wildcard *.c) $(wildcard ../*.c)
C_SRCS    := $(filter-out $(OSSL_FIPS_SRC), $(C_SRCS))
ASM_SRCS  := $(wildcard *.S) \
             $(COMMON_DIR)/src/linux/xsave_gnu.S
OBJS      := $(CPP_SRCS:.cpp=.o)
OBJS      += $(C_SRCS:.c=.o)
OBJS      += $(ASM_SRCS:.S=.o)
OBJS      := $(sort $(OBJS))

LIBTRTS = libsgx_trts.a
LIBSGX_MM_PATH = $(LINUX_EXTERNAL_DIR)/sgx-emm
LIBSGX_MM = libsgx_mm.a
LIBOSSLFIPS = libsgx_ossl_fips.a

.PHONY: all
all: $(LIBTRTS) $(LIBOSSLFIPS) | $(BUILD_DIR)
	$(CP) $(LIBTRTS) $(LIBOSSLFIPS) $|

$(LIBSGX_MM):
	$(MAKE) -C $(LIBSGX_MM_PATH)

$(LIBTRTS): $(OBJS) $(LIBSGX_MM)
	$(AR) rsD $@ $(OBJS) 
	$(MKDIR) $(BUILD_DIR)/.libsgx_mm
	$(RM) $(BUILD_DIR)/.libsgx_mm/* && cd $(BUILD_DIR)/.libsgx_mm && $(AR) x $(LIBSGX_MM_PATH)/libsgx_mm.a
	$(AR) rsD $@ $(BUILD_DIR)/.libsgx_mm/*.o
	@$(RM) -rf $(BUILD_DIR)/.libsgx_mm

$(LIBOSSLFIPS): $(OSSL_FIPS_OBJ)
	$(AR) rsD $@ $(OSSL_FIPS_OBJ)

%.o: %.S
	echo $(ASM_SRCS)
	$(CC) $(CFLAGS) $(TCFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(TCFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(TCFLAGS) -c $< -o $@

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) $(OBJS) $(OSSL_FIPS_OBJ) $(LIBTRTS) $(BUILD_DIR)/$(LIBTRTS) $(BUILD_DIR)/$(LIBOSSLFIPS)
	@$(MAKE) -C $(LIBSGX_MM_PATH) clean

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all

