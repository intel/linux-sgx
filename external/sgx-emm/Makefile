# Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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

include ../../buildenv.mk

EMM_DIR = emm_src

CPPFLAGS += -I$(EMM_DIR)/include      \
            -I$(COMMON_DIR)/inc/tlibc \
            -Wno-missing-braces       \
            -Wno-unused-parameter

C_Files := $(EMM_DIR)/bit_array.c   \
           $(EMM_DIR)/ema.c         \
           $(EMM_DIR)/emalloc.c     \
           $(EMM_DIR)/emm_private.c \
           $(EMM_DIR)/sgx_mm.c

OBJS := $(C_Files:.c=.o)
OBJS := $(sort $(OBJS))

LIB_NAME := libsgx_mm.a

CHECK_SOURCE :=
ifeq ("$(wildcard $(EMM_DIR)/sgx_mm.c)", "")
CHECK_SOURCE := emm_code
endif

.PHONY: all clean emm_code

all: $(LIB_NAME) | $(BUILD_DIR)
	$(CP) $(LIB_NAME) $|

$(LIB_NAME): $(CHECK_SOURCE) $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(OBJS): %.o: %.c
	$(CC) -c $(COMMON_FLAGS) $(ENCLAVE_CFLAGS) $(CPPFLAGS) $< -o $@

$(BUILD_DIR):
	@$(MKDIR) $@

emm_code:
#ifeq ($(shell git rev-parse --is-inside-work-tree 2> /dev/null), true)
#	git submodule update -f --init --recursive -- $(EMM_DIR)
#else
	$(RM) -rf $(EMM_DIR)
	git clone -b sgx-emm-1.0.2 https://github.com/intel/sgx-emm.git --depth 1 $(EMM_DIR)
#endif

clean:
	@$(RM) $(LIB_NAME) $(OBJS) $(BUILD_DIR)/$(LIB_NAME) *.bak *~

