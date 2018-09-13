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

include ../../../buildenv.mk

ifndef DEBUG
CXXFLAGS += -DDISABLE_TRACE
CFLAGS += -DDISABLE_TRACE
endif

CXXFLAGS += -fPIC -Werror -g
CXXFLAGS += $(ADDED_INC)

CFLAGS += -fPIC -Werror -g
CFLAGS += $(ADDED_INC)

VTUNE_DIR = $(LINUX_EXTERNAL_DIR)/vtune/linux

INC += -I$(COMMON_DIR)/inc                \
       -I$(COMMON_DIR)/inc/internal       \
       -I$(COMMON_DIR)/inc/internal/linux \
       -I$(LINUX_PSW_DIR)/enclave_common  \
       -I$(LINUX_PSW_DIR)/urts/           \
       -I$(LINUX_PSW_DIR)/urts/linux      \
       -I$(LINUX_PSW_DIR)/urts/parser     \
       -I$(VTUNE_DIR)/include \
       -I$(VTUNE_DIR)/sdk/src/ittnotify 

LDFLAGS := -lwrapper
LDFLAGS += $(COMMON_LDFLAGS) -Wl,-Bdynamic -lsgx_enclave_common
LDFLAGS += -L$(VTUNE_DIR)/sdk/src/ittnotify -littnotify -ldl
LDFLAGS += -Wl,--version-script=urts.lds -Wl,--gc-sections

DIR1 := $(LINUX_PSW_DIR)/urts/linux
DIR2 := $(LINUX_PSW_DIR)/urts
DIR3 := $(LINUX_PSW_DIR)/urts/parser
DIR4 := $(LINUX_PSW_DIR)/urts/parser/linux
DIR5 := $(LINUX_PSW_DIR)/../common/src/linux

LIB += -L$(COMMON_DIR)/se_wrapper \
       -L$(BUILD_DIR)

OBJ1 := loader.o          \
        node.o            \
        se_detect.o       \
        enclave.o         \
        tcs.o             \
        enclave_mutex.o   \
        routine.o         \
        urts_xsave.o      \
        se_ocalls.o       \
        cpu_features.o    \
        launch_checker.o  \
        urts_version.o    \
        enclave_creator_hw_com.o 

OBJ2 := urts.o               \
        enclave_creator_hw.o \
        misc.o               \
        sig_handler.o        \
        debugger_support.o   \
        get_thread_id.o      \
        prd_css_util.o       \
        urts_emodpr.o        \
        urts_trim.o          \
        edmm_utility.o

OBJ3 := enter_enclave.o \
        xsave_gnu.o

OBJ4 := section.o \
        elfparser.o

OBJ5 := urts_internal.o

CPP_OBJ := $(OBJ1) $(OBJ2) $(OBJ4) $(OBJ5)
URTS_OBJ     := $(OBJ3) $(OBJ1) $(OBJ2) $(OBJ4)
INTERNAL_OBJ := $(OBJ3) $(CPP_OBJ)


vpath %.cpp $(DIR1):$(DIR2):$(DIR3):$(DIR4)
vpath %.S   $(DIR1):$(DIR5)

LIBWRAPPER            := libwrapper.a
LIBSGX_ENCLAVE_COMMON := libsgx_enclave_common.a
LIBURTS               := libsgx_urts.so
LIBURTS_INTERNAL      := liburts_internal.a
LIBURTS_DEBUG	      := libsgx_urts.so.debug

# untrusted switchless settings
USWITCHLESS_NAME := uswitchless
USWITCHLESS_DIR  := $(LINUX_PSW_DIR)/$(USWITCHLESS_NAME)
LIBUSWITCHLESS   := $(USWITCHLESS_DIR)/lib$(USWITCHLESS_NAME).a
LDFLAGS          += -L$(USWITCHLESS_DIR) -l$(USWITCHLESS_NAME)

.PHONY: all
all: $(LIBURTS) $(LIBURTS_INTERNAL) $(LIBURTS_DEBUG) | $(BUILD_DIR)
	@$(CP) $(LIBURTS)          $|
	@$(CP) $(LIBURTS_INTERNAL) $|
ifndef DEBUG
	@$(CP) $(LIBURTS_DEBUG)    $|
endif

$(LIBURTS_INTERNAL): $(INTERNAL_OBJ) $(LIBWRAPPER) $(LIBSGX_ENCLAVE_COMMON) $(LIBUSWITCHLESS)
	$(CP) $(COMMON_DIR)/se_wrapper/libwrapper.a $@
	$(MKDIR) ./.switchless_tmp
	$(RM) ./.switchless_tmp/*
	cd ./.switchless_tmp && \
	$(AR) x $(LIBUSWITCHLESS)
	@$(MKDIR) $(BUILD_DIR)/.sgx_enclave_common
	@$(RM) -f $(BUILD_DIR)/.sgx_enclave_common/*
	cd $(BUILD_DIR)/.sgx_enclave_common && $(AR) x $(BUILD_DIR)/$(LIBSGX_ENCLAVE_COMMON)
	$(AR) rcs $@ $(INTERNAL_OBJ) ./.switchless_tmp/*.o $(BUILD_DIR)/.sgx_enclave_common/*.o
	@$(RM) -rf ./.switchless_tmp
	@$(RM) -rf $(BUILD_DIR)/.sgx_enclave_common

$(LIBURTS): $(URTS_OBJ) $(LIBWRAPPER) $(LIBSGX_ENCLAVE_COMMON) $(LIBUSWITCHLESS) ittnotify
	$(CXX) $(CXXFLAGS) -shared -Wl,-soname=$@ $(LIB) -o $@  $(URTS_OBJ) $(LDFLAGS)

$(LIBURTS_DEBUG): $(LIBURTS)
ifndef DEBUG
	$(CP) $(LIBURTS) $(LIBURTS).orig
	$(OBJCOPY) --only-keep-debug $(LIBURTS) $(LIBURTS_DEBUG)
	$(STRIP) -g $(LIBURTS)
	$(OBJCOPY) --add-gnu-debuglink=$(LIBURTS_DEBUG) $(LIBURTS)
endif

$(CPP_OBJ): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(INC) $< -o $@

$(OBJ3): %.o: %.S
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(LIBWRAPPER):
	$(MAKE) -C $(COMMON_DIR)/se_wrapper/

$(LIBSGX_ENCLAVE_COMMON):
	$(MAKE) -C $(LINUX_PSW_DIR)/enclave_common/

$(LIBUSWITCHLESS):
	$(MAKE) -C $(LINUX_PSW_DIR)/uswitchless/

.PHONY: ittnotify
ittnotify:
	$(MAKE) -C $(VTUNE_DIR)/sdk/src/ittnotify

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean::
	@$(RM) *.o $(LIBURTS) $(LIBURTS_INTERNAL) $(LIBURTS_DEBUG)
	@$(RM) $(BUILD_DIR)/$(LIBURTS) $(BUILD_DIR)/$(LIBURTS_INTERNAL)
	@$(RM) $(LIBURTS).orig $(BUILD_DIR)/$(LIBURTS_DEBUG)
	$(MAKE) -C $(COMMON_DIR)/se_wrapper/                   clean
	$(MAKE) -C $(LINUX_PSW_DIR)/enclave_common/            clean
	$(MAKE) -C $(LINUX_PSW_DIR)/uswitchless/               clean
	$(MAKE) -C $(VTUNE_DIR)/sdk/src/ittnotify              clean
