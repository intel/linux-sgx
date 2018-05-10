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

# PCL library makefile

include ../../buildenv.mk

ifndef $(VERBOSE)
	VERBOSE	:= @
endif


ifeq ($(ARCH), x86)
	$(error x86 build is not supported, only x64!!)
endif

# output dir for simulation build objects
SIM_DIR             := simulation/
SIM_OBJ_DIR         := $(SIM_DIR)


PCL_SIM_LIB         := libsgx_pclsim.a
PCL_LIB             := libsgx_pcl.a

# source files
PCL_ASM_FILES       := crypto/pcl_vpaes-x86_64.s \
                       crypto/pcl_ghash-x86_64.s

PCL_CPP_FILES       := pcl_entry.cpp                 \
                       pcl_mem.cpp                   \
                       crypto/pcl_crypto.cpp         \
                       unseal/pcl_tSeal.cpp          \
                       unseal/pcl_sgx_get_key.cpp    \
                       unseal/pcl_tSeal_util.cpp     \
                       unseal/pcl_tSeal_internal.cpp

PCL_C_FILES        := crypto/pcl_sha256.c    \
                      crypto/pcl_gcm128.c 

# files for simulation mode
PCL_SIM_C_FILES		:= $(PCL_C_FILES) crypto/pcl_cmac.c
PCL_SIM_CPP_FILES	:= $(PCL_CPP_FILES) unseal/sim/pcl_deriv.cpp unseal/sim/pcl_t_instructions.cpp

# object files
PCL_CPP_OBJECTS			:= $(PCL_CPP_FILES:%.cpp=%.o)
PCL_C_OBJECTS			:= $(PCL_C_FILES:%.c=%.o)
PCL_ASM_OBJECTS			:= $(PCL_ASM_FILES:%.s=%.o)

# simulation objects
PCL_SIM_CPP_OBJECTS		:= $(PCL_SIM_CPP_FILES:%.cpp=$(SIM_OBJ_DIR)%.o)
PCL_SIM_C_OBJECTS		:= $(PCL_SIM_C_FILES:%.c=$(SIM_OBJ_DIR)%.o)

# build flags
PCL_INCLUDE_PATH	:= -I$(COMMON_DIR)/inc \
                       -I$(COMMON_DIR)/inc/tlibc \
                       -I$(COMMON_DIR)/inc/internal \
                       -I./crypto \
                       -I./unseal \
                       -I/usr/include/x86_64-linux-gnu \
                       -I/usr/include \
                       -I./ 

TCFLAGS := $(filter-out -ffunction-sections -fdata-sections, $(CFLAGS))
TCXXFLAGS := $(filter-out -ffunction-sections -fdata-sections, $(CXXFLAGS))
PCL_LIB_C_FLAGS := $(TCFLAGS) $(ENCLAVE_CFLAGS) $(PCL_INCLUDE_PATH)
PCL_LIB_CPP_FLAGS := $(TCXXFLAGS) $(ENCLAVE_CXXFLAGS) $(PCL_INCLUDE_PATH)


PCL_SIM_LIB_C_FLAGS := $(TCFLAGS) $(ENCLAVE_CFLAGS) -DSE_SIM=1 $(PCL_INCLUDE_PATH) -I$(LINUX_SDK_DIR)/simulation/tinst
PCL_SIM_LIB_CPP_FLAGS := $(TCXXFLAGS) $(ENCLAVE_CXXFLAGS) -DSE_SIM=1 $(PCL_INCLUDE_PATH) -I$(LINUX_SDK_DIR)/simulation/tinst


# targets
.PHONY: all

all: | $(BUILD_DIR) 
	$(VERBOSE)$(MAKE) $(PCL_LIB)
	$(VERBOSE)$(MAKE) $(PCL_SIM_LIB)
	$(VERBOSE)$(CP) $(PCL_LIB) $|	
	$(VERBOSE)$(CP) $(PCL_SIM_LIB) $|	

$(BUILD_DIR):
	$(VERBOSE)$(MKDIR) $@

.PHONY: $(PCL_LIB)
$(PCL_LIB):$(PCL_CPP_OBJECTS) $(PCL_ASM_OBJECTS) $(PCL_C_OBJECTS)
	@echo "library build with DEBUG =" $(DEBUG)
	$(VERBOSE)$(AR) -rc $@ $^
	@echo "AR   <=  $@"

    
.PHONY: $(PCL_SIM_LIB)
$(PCL_SIM_LIB):$(PCL_SIM_CPP_OBJECTS) $(PCL_ASM_OBJECTS) $(PCL_SIM_C_OBJECTS)
	@echo "library build with DEBUG =" $(DEBUG)
	$(VERBOSE)$(AR) -rc $@ $^
	@echo "AR   <=  $@"


%.o: %.s
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_LIB_C_FLAGS) -c $< -o $@ 
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

%.o: %.c
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_LIB_C_FLAGS) -c $< -o $@
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

%.o: %.cpp
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_LIB_CPP_FLAGS) -c $< -o $@
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

# Simulation objects
$(SIM_OBJ_DIR)%.o: %.s
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_SIM_LIB_C_FLAGS) -c $< -o $@ 
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

$(SIM_OBJ_DIR)%.o: %.c
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_SIM_LIB_C_FLAGS) -c $< -o $@
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

$(SIM_OBJ_DIR)%.o: %.cpp
	$(VERBOSE)mkdir -p $(@D)
	$(VERBOSE)$(CXX) $(PCL_SIM_LIB_CPP_FLAGS) -c $< -o $@
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .text=$(NIPX)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .data=$(NIPD)
	$(VERBOSE)$(OBJCOPY) $@ --rename-section .rodata=$(NIPRODT)
	@echo "CXX  <=  $<"

.PHONY: clean
clean:
	$(VERBOSE)$(RM) $(PCL_LIB) $(PCL_SIM_LIB) $(PCL_CPP_OBJECTS) $(PCL_ASM_OBJECTS) $(PCL_C_OBJECTS) $(PCL_SIM_CPP_OBJECTS) $(PCL_SIM_C_OBJECTS)
	$(VERBOSE)rm -rf $(SIM_DIR) $(BUILD_DIR)/$(PCL_LIB) $(BUILD_DIR)/$(PCL_SIM_LIB)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
