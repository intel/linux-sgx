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

TOP_DIR  = ../../../..
include $(TOP_DIR)/buildenv.mk

LAUNCH_VERSION:= $(shell awk '$$2 ~ /LAUNCH_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(COMMON_DIR)/inc/internal/se_version.h)
PLATFORM_VERSION:= $(shell awk '$$2 ~ /PLATFORM_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(COMMON_DIR)/inc/internal/se_version.h)
EPID_VERSION:= $(shell awk '$$2 ~ /EPID_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(COMMON_DIR)/inc/internal/se_version.h)
QUOTE_EX_VERSION:= $(shell awk '$$2 ~ /QUOTE_EX_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(COMMON_DIR)/inc/internal/se_version.h)

INCLUDES := -I..                                            \
            -I$(COMMON_DIR)/inc                             \
            -I$(COMMON_DIR)/inc/internal                    \
            -I$(LINUX_SDK_DIR)/tseal                        \
            -I$(LINUX_SDK_DIR)/simulation/tinst             \
            -I$(LINUX_SDK_DIR)/simulation/urtssim           \
            -I$(LINUX_EXTERNAL_DIR)/epid-sdk                \
            -I$(LINUX_EXTERNAL_DIR)/rdrand/                 \
            -I$(LINUX_PSW_DIR)/ae/inc                       \
            -I$(LINUX_PSW_DIR)/ae/inc/internal              \
            -I$(LINUX_PSW_DIR)/ae/common 

CXXFLAGS += -Wall -fPIC $(INCLUDES) -Werror -g
CFLAGS := $(filter-out -fPIC -Werror, $(CFLAGS)) -Wall $(INCLUDES)

RDRAND_LIBDIR := $(LINUX_EXTERNAL_DIR)/rdrand/src
RDRAND_MAKEFILE := $(RDRAND_LIBDIR)/Makefile

EXTERNAL_LIB += -L$(RDRAND_LIBDIR) -lrdrand
EXTERNAL_LIB += -L$(RDRAND_LIBDIR) -lrt
EXTERNAL_LIB += -ldl -lcrypto

vpath %.cpp $(LINUX_PSW_DIR)/ae/common \
            $(LINUX_SDK_DIR)/simulation/urtssim \
            $(COMMON_DIR)/src

vpath %.c   $(COMMON_DIR)/src

CPP_SRC := $(wildcard *.cpp ../*.cpp) se_sig_rl.cpp cpusvn_util.cpp sgx_read_rand.cpp 
CPP_SRC += crypto_evp_digest.cpp crypto_cmac_128.cpp
C_SRC   := se_trace.c se_thread.c

OBJ := $(sort $(CPP_SRC:.cpp=.o)) \
       $(C_SRC:.c=.o)

LIBNAME  = libsgx_epid_sim.so libsgx_launch_sim.so libsgx_quote_ex_sim.so libsgx_uae_service_sim.so
ifndef DEBUG
LIBNAME_DEBUG  =  $(LIBNAME:.so=.so.debug)
endif
LIBUAE_SERVICE_DEPLOY := $(LIBNAME:_sim.so=_deploy.so)

.PHONY: all
all: $(LIBNAME) $(LIBNAME_DEBUG) $(LIBUAE_SERVICE_DEPLOY) $(LEGACY_LIBNAME) $(LEGACY_LIBNAME_DEBUG) $(LEGACY_LIBUAE_SERVICE_DEPLOY) | $(BUILD_DIR)
	@$(foreach lib,$(LIBNAME),$(CP) $(lib) $|;)
	@$(foreach lib,$(LIBUAE_SERVICE_DEPLOY),$(CP) $(lib) $|;)
ifndef DEBUG
	@$(foreach lib,$(LIBNAME_DEBUG),$(CP) $(lib) $|;)
endif

libsgx_%_sim.so: $(OBJ) -lrdrand
	$(CXX) $(CXXFLAGS) $^ -shared $(LDUFLAGS) -Wl,--version-script=$(@:_sim.so=.lds) -Wl,--gc-sections $(EXTERNAL_LIB) -o $@
%.so.debug: %.so
ifndef DEBUG
	((test -f $@) ||( \
	$(CP) $< $<.orig &&\
	$(OBJCOPY) --only-keep-debug $< $@ &&\
	$(STRIP) -g $< &&\
	$(OBJCOPY) --add-gnu-debuglink=$@ $< ))
endif

%.o: %.c
	$(CC) $(CFLAGS) -Werror -fPIC -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

-lrdrand: $(RDRAND_MAKEFILE)
	$(MAKE) -C $(RDRAND_LIBDIR)


$(RDRAND_MAKEFILE):
ifeq ($(ARCH), x86)
	@cd $(RDRAND_LIBDIR);./configure
else
	@cd $(RDRAND_LIBDIR);./configure CFLAGS=-fPIC
endif

libsgx_%_deploy.so: ../libsgx_%_deploy.c
	$(CC) -fPIC -shared -Wl,-soname=$(@:_deploy.so=.so.$(call SPLIT_VERSION,$($(shell echo $(@:libsgx_%_deploy.so=%_version)|tr a-z A-Z)),1)) $< -o $@

libsgx_uae_service_deploy.so: $(wildcard ../*_deploy.c)
	$(CC) -fPIC -shared -Wl,-soname=$(@:_deploy.so=.so) $^ -o $@

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) *.o
	@$(RM) ../*.o *.orig
	@$(RM) $(LIBNAME) $(addprefix $(BUILD_DIR)/,$(LIBNAME))
	@$(RM) $(LIBNAME_DEBUG) $(addprefix $(BUILD_DIR)/,$(LIBNAME_DEBUG))
	@$(RM) $(LIBUAE_SERVICE_DEPLOY)  $(addprefix $(BUILD_DIR)/,$(LIBUAE_SERVICE_DEPLOY))
ifeq ($(RDRAND_MAKEFILE), $(wildcard $(RDRAND_MAKEFILE)))
	@$(MAKE) distclean -C $(RDRAND_LIBDIR)
endif

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
