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

include scripts/installConfig

SOURCE_FOLDER=package
SOURCE_INSTALL_PATH=$(shell readlink -m $(DESTDIR)/$(ECL_PKG_PATH)/$(ECL_PKG_NAME))

LIBRARY_INSTALL_PATH=$(SOURCE_INSTALL_PATH)/$(LIB_DIR)
USR_LIB_PATH=$(addsuffix /$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2> /dev/null), $(addprefix $(DESTDIR)/usr/, $(notdir $(shell gcc -print-multi-os-directory))))

VAR_OPT_PATH=$(shell readlink -m $(DESTDIR)/var/opt/aesmd)
VAR_RUN_PATH=$(shell readlink -m $(DESTDIR)/var/run/aesmd)

ETC_PATH=$(shell readlink -m $(DESTDIR)/etc)

AESMD_CONF_NAME=$(if $(wildcard /run/systemd/system/.*),aesmd.service,$(if $(wildcard /etc/init/.*),aesmd.conf,))
AESMD_CONF_DEL=$(if $(wildcard /run/systemd/system/.*),aesmd.conf,$(if $(wildcard /etc/init/.*),aesmd.service,))
AESMD_CONF_PATH=$(shell readlink -m $(DESTDIR)/$(if $(wildcard /run/systemd/system/.*),$(if $(wildcard /lib/systemd/system/.*),/lib/systemd/system,/usr/lib/systemd/system),$(if $(wildcard /etc/init/.*),/etc/init/,)))

ifeq ($(AESMD_CONF_NAME),)
$(error "Unsupported platform - neither systemctl nor initctl is found.")
endif

SPLIT_VERSION=$(word $2,$(subst ., ,$1))

ECL_VER=1.0.0
URTS_VER=1.0.0
UAE_VER=1.0.0
LCH_VER=1.0.0
PLF_VER=1.0.0
EPID_VER=1.0.0
QEX_VER=1.0.0

default:

install: install_source install_library install_configuration

install_source:
	install -d $(SOURCE_INSTALL_PATH)
	cp -r $(SOURCE_FOLDER)/* $(SOURCE_INSTALL_PATH)

install_library:
	install -d $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_uae_service.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_urts.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_enclave_common.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_launch.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_platform.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_epid.so $(USR_LIB_PATH)
	mv $(LIBRARY_INSTALL_PATH)/libsgx_quote_ex.so $(USR_LIB_PATH)
	rmdir $(LIBRARY_INSTALL_PATH)
	cd $(USR_LIB_PATH) && \
	mv libsgx_uae_service.so libsgx_uae_service.so.$(UAE_VER) && \
	ln -fs libsgx_uae_service.so.$(UAE_VER) libsgx_uae_service.so.$(shell echo $(UAE_VER) |awk -F. '{print $$1}') && \
	ln -fs libsgx_uae_service.so.$(shell echo $(UAE_VER) |awk -F. '{print $$1}') libsgx_uae_service.so && \
	mv libsgx_urts.so libsgx_urts.so.$(URTS_VER) && \
	ln -fs libsgx_urts.so.$(URTS_VER) libsgx_urts.so.$(shell echo $(URTS_VER) |awk -F. '{print $$1}') && \
	ln -fs libsgx_urts.so.$(shell echo $(URTS_VER) |awk -F. '{print $$1}') libsgx_urts.so && \
	mv libsgx_enclave_common.so libsgx_enclave_common.so.$(ECL_VER) && \
	ln -fs libsgx_enclave_common.so.$(ECL_VER) libsgx_enclave_common.so.$(call SPLIT_VERSION,$(ECL_VER),1) && \
	mv libsgx_launch.so libsgx_launch.so.$(LCH_VER) && \
	ln -fs libsgx_launch.so.$(LCH_VER) libsgx_launch.so.$(call SPLIT_VERSION,$(LCH_VER),1) && \
	mv libsgx_platform.so libsgx_platform.so.$(PLF_VER) && \
	ln -fs libsgx_platform.so.$(PLF_VER) libsgx_platform.so.$(call SPLIT_VERSION,$(PLF_VER),1) && \
	mv libsgx_epid.so libsgx_epid.so.$(EPID_VER) && \
	ln -fs libsgx_epid.so.$(EPID_VER) libsgx_epid.so.$(call SPLIT_VERSION,$(EPID_VER),1) && \
	mv libsgx_quote_ex.so libsgx_quote_ex.so.$(QEX_VER) && \
	ln -fs libsgx_quote_ex.so.$(QEX_VER) libsgx_quote_ex.so.$(call SPLIT_VERSION,$(QEX_VER),1)

install_configuration:
	install -d $(VAR_OPT_PATH)
	cp -fr $(SOURCE_INSTALL_PATH)/aesm/data $(VAR_OPT_PATH)
	rm -fr $(SOURCE_INSTALL_PATH)/aesm/data
ifeq ($(shell grep '^ID=clear-linux-os' /usr/lib/os-release 2> /dev/null),)
	install -d $(ETC_PATH)
	install $(SOURCE_INSTALL_PATH)/aesm/conf/* $(ETC_PATH)
	rm -fr $(SOURCE_INSTALL_PATH)/aesm/conf
else
	mv $(SOURCE_INSTALL_PATH)/aesm/conf/aesmd.conf $(SOURCE_INSTALL_PATH)/aesm/conf/aesmd.conf.sample
endif
	install -d $(VAR_RUN_PATH)
	install -d $(AESMD_CONF_PATH)
	sed -e "s:@aesm_folder@:$(ECL_PKG_PATH)/$(ECL_PKG_NAME)/aesm:" $(SOURCE_INSTALL_PATH)/aesm/$(AESMD_CONF_NAME) > $(AESMD_CONF_PATH)/$(AESMD_CONF_NAME)
	rm -f $(SOURCE_INSTALL_PATH)/aesm/$(AESMD_CONF_NAME)
	rm -f $(SOURCE_INSTALL_PATH)/aesm/$(AESMD_CONF_DEL)
	
