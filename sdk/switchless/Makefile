#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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

# SL = Switch-Less
SL_DIR := $(LINUX_SDK_DIR)/switchless

# common switchless files from $(COMMON_DIR)/src
COMMON_SL_SRC := sl_fcall_mngr_common.c sl_once_common.c sl_siglines_common.c sl_memlog_common.c
COMMON_SL_OBJ := $(COMMON_SL_SRC:.c=.o)
vpath %.c $(COMMON_DIR)/src

# Files that do NOT match *_untrusted.c or *_untrusted.S are trusted components
C_SRCS_T := $(sort $(filter-out $(C_SRCS_U), $(wildcard $(SL_DIR)/src/*.c)))
C_OBJS_T := $(C_SRCS_T:.c=.o)
C_OBJS_T += $(COMMON_SL_OBJ)
S_SRCS_T := $(sort $(filter-out $(S_SRCS_U), $(wildcard $(SL_DIR)/src/*.S)))
S_OBJS_T := $(S_SRCS_T:.S=.o)
ALL_OBJS_T := $(C_OBJS_T) $(S_OBJS_T)


# Compiler flags
CFLAGS_COMMON := $(CFLAGS)
CFLAGS_COMMON += -std=c11 -D_GNU_SOURCE
CFLAGS_COMMON += -Werror -Wno-redundant-decls
CFLAGS_COMMON += -I$(COMMON_DIR)/inc -I$(COMMON_DIR)/inc/internal
CFLAGS_COMMON += -DSL_DEBUG

CFLAGS_T := $(CFLAGS_COMMON)
CFLAGS_T += $(ENCLAVE_CFLAGS)
CFLAGS_T += -DSL_INSIDE_ENCLAVE
#CFLAGS_T += -DSL_NO_PREEMPTION
CFLAGS_T += -I$(COMMON_DIR)/inc/internal \
          	-I$(COMMON_DIR)/inc/tlibc

# Primary build targets
LIB_T := libsgx_tswitchless.a

GREEN :=\033[1;32m
NC :=\033[0m


.PHONY: all benchmark build_src build_benchmark clean
all: build_src

benchmark: build_benchmark
	@$(MAKE) --no-print-directory -C benchmark run

build_src: $(LIB_T)

build_benchmark: build_src
	@$(MAKE) --no-print-directory -C benchmark

$(LIB_T): $(ALL_OBJS_T)
	@$(AR) rcs $@ $^
	@$(CP) $(LIB_T) $(BUILD_DIR)/
	@echo "$(GREEN)LINK => $@$(NC)"

$(C_OBJS_T): %.o: %.c
	@$(CC) $(CFLAGS_T) -c $< -o $@
	@echo "CC <= $@"

$(S_OBJS_T): %.o: %.S
	@$(CC) $(CFLAGS_T) -c $< -o $@
	@echo "AS <= $@"

clean:
	@$(RM) -f $(LIB_T) $(ALL_OBJS_T) $(BUILD_DIR)/$(LIB_T)

