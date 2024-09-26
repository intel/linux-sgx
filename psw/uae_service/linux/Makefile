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

TOP_DIR  = ../../..
include $(TOP_DIR)/buildenv.mk

get_version_name = $(addsuffix _VERSION,$(shell echo $(subst libsgx_,,$(basename $1)) | tr a-z A-Z))

IPC_COMMON_DIR        := $(TOP_DIR)/psw/ae/aesm_service/source/core/ipc
IPC_COMMON_SRC_DIR    := $(IPC_COMMON_DIR)
IPC_COMMON_INC_DIR    := $(IPC_COMMON_DIR)
IPC_COMMON_PROTO_DIR  := $(IPC_COMMON_DIR)
UAE_WRAPPER_DIR        := ../uae_wrapper
UAE_SRC_DIR    := $(UAE_WRAPPER_DIR)/src
UAE_INC_DIR    := $(UAE_WRAPPER_DIR)/inc
AE_COMMON_DIR    := $(LINUX_PSW_DIR)/ae/common

INCLUDE += -I.
INCLUDE += -I$(COMMON_DIR)              \
           -I$(COMMON_DIR)/inc          \
           -I$(COMMON_DIR)/inc/internal \

INCLUDE += -I$(LINUX_PSW_DIR)/ae/common         \
           -I$(LINUX_PSW_DIR)/ae/inc            \
           -I$(LINUX_PSW_DIR)/ae/inc/internal   \
           -I$(SGX_HEADER_DIR)

INCLUDE += -I$(LINUX_EXTERNAL_DIR)/epid-sdk          \
           -I$(IPC_COMMON_INC_DIR)                   \
           -I$(UAE_INC_DIR)                          \
           -I$(IPC_COMMON_PROTO_DIR)                 \
           -I$(LINUX_PSW_DIR)/ae/aesm_service/source \
           -I$(LINUX_PSW_DIR)/ae/aesm_service/source/common

CXXFLAGS += -fPIC -Werror -Wno-unused-parameter -g -DPROTOBUF_INLINE_NOT_IN_HEADERS=0

EXTERNAL_LIB += -lprotobuf

vpath %.cpp .. $(COMMON_DIR)/src  $(IPC_COMMON_SRC_DIR) $(IPC_COMMON_PROTO_DIR) $(UAE_SRC_DIR) $(AE_COMMON_DIR)
vpath %.c   $(COMMON_DIR)/src

C_SRC   := se_trace.c

IPC_SRC  :=  AEGetQuoteResponse.cpp \
             AEInitQuoteRequest.cpp \
             AEInitQuoteResponse.cpp \
             AEReportAttestationRequest.cpp \
             AEReportAttestationResponse.cpp \
             AECheckUpdateStatusRequest.cpp \
             AECheckUpdateStatusResponse.cpp \
             ProtobufSerializer.cpp \
             AEGetLaunchTokenRequest.cpp  \
             AEGetWhiteListSizeRequest.cpp \
             AEGetWhiteListSizeResponse.cpp \
             AEGetWhiteListRequest.cpp \
             AEGetWhiteListResponse.cpp \
             AESGXGetExtendedEpidGroupIdRequest.cpp \
             AESGXGetExtendedEpidGroupIdResponse.cpp \
             AESGXSwitchExtendedEpidGroupRequest.cpp \
             AESGXSwitchExtendedEpidGroupResponse.cpp \
             AESGXRegisterRequest.cpp \
             AESGXRegisterResponse.cpp \
             SocketTransporter.cpp \
             AEGetLaunchTokenResponse.cpp  \
             UnixCommunicationSocket.cpp \
             AEGetQuoteRequest.cpp \
             UnixSocketFactory.cpp \
             NonBlockingUnixCommunicationSocket.cpp \
             NonBlockingUnixSocketFactory.cpp \
             AESelectAttKeyIDRequest.cpp \
             AESelectAttKeyIDResponse.cpp \
             AEInitQuoteExRequest.cpp \
             AEInitQuoteExResponse.cpp \
             AEGetQuoteExRequest.cpp \
             AEGetQuoteExResponse.cpp \
             AEGetQuoteSizeExRequest.cpp \
             AEGetQuoteSizeExResponse.cpp \
             AEGetSupportedAttKeyIDNumRequest.cpp \
             AEGetSupportedAttKeyIDNumResponse.cpp \
             AEGetSupportedAttKeyIDsRequest.cpp \
             AEGetSupportedAttKeyIDsResponse.cpp

PROTOBUF_SRC  := messages.pb.cc

SRC :=       AEServicesImpl.cpp \
             AEServicesProvider.cpp \
             uae_api.cpp \
             se_sig_rl.cpp \
             sgx_uae_service.cpp \
             uae_service_assert.cpp

LEGACY_SRC := legacy_uae_service.cpp \
              uae_service_version.cpp

OBJ := $(C_SRC:.c=.o) $(SRC:.cpp=.o) $(IPC_SRC:.cpp=.o) $(PROTOBUF_SRC:.cc=.o)

LEGACY_OBJ := $(LEGACY_SRC:.cpp=.o)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)

LIBNAME := libsgx_epid.so libsgx_launch.so libsgx_quote_ex.so
LEGACY_LIBNAME := libsgx_uae_service.so

.PHONY: all
all:  install_lib

.PHONY: install_lib
install_lib: $(LIBNAME) $(LEGACY_LIBNAME) | $(BUILD_DIR)
	@$(foreach lib,$(LIBNAME),$(CP) $(lib) $|/$(lib).$(call get_full_version,$(call get_version_name,$(lib)));)
	@$(foreach lib,$(LIBNAME),$(LN) $(lib).$(call get_full_version,$(call get_version_name,$(lib))) $|/$(lib).$(call get_major_version,$(call get_version_name,$(lib)));)
	@$(foreach lib,$(LIBNAME),$(LN) $(lib).$(call get_major_version,$(call get_version_name,$(lib))) $|/$(lib);)
	@$(CP) $(LEGACY_LIBNAME) $|

libsgx_%.so: $(OBJ) %_version.o
	$(CXX) $(CXXFLAGS) $^ -shared $(LDUFLAGS) -Wl,--version-script=$(@:.so=.lds) -Wl,--gc-sections $(EXTERNAL_LIB) -Wl,-soname=$@.$(call get_major_version,$(call get_version_name,$@)) -o $@

$(LEGACY_LIBNAME): $(LEGACY_OBJ)
	$(CXX) $(CXXFLAGS) $^ -shared $(LDUFLAGS) -ldl -Wl,--version-script=uae_service.lds -Wl,--gc-sections -Wl,-soname=$@ -o $@

$(IPC_SRC:.cpp=.o) : $(IPC_COMMON_PROTO_DIR)/messages.pb.cc
AEServicesImpl.o : $(IPC_COMMON_PROTO_DIR)/messages.pb.cc

messages.pb.o : $(IPC_COMMON_PROTO_DIR)/messages.pb.cc
	$(CXX) $(filter-out -Wshadow -Wredundant-decls, $(CXXFLAGS)) -Wno-array-bounds -Wno-conversion -c $< -o $@
%.o :%.cpp
	$(CXX) $(CXXFLAGS) -Wno-deprecated-declarations $(INCLUDE) -c $< -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -Werror -fPIC -c $< -o $@

$(BUILD_DIR):
	@$(MKDIR) $@

$(IPC_COMMON_PROTO_DIR)/messages.pb.cc: $(IPC_COMMON_PROTO_DIR)/messages.proto
	$(MAKE) -C $(IPC_COMMON_PROTO_DIR)

.PHONY: clean
clean:
	$(MAKE) -C $(IPC_COMMON_PROTO_DIR) clean
	@$(RM) $(OBJ) $(LEGACY_OBJ)
	@$(RM) $(LIBNAME) $(addsuffix *,$(addprefix $(BUILD_DIR)/,$(LIBNAME)))
	@$(RM) $(LEGACY_LIBNAME) $(BUILD_DIR)/$(LEGACY_LIBNAME)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
