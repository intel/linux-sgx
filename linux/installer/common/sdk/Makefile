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
SCRIPTS_FOLDER=scripts

SOURCE_PATH=$(shell readlink -m /$(SGX_PACKAGES_PATH)/$(SDK_PKG_NAME))
SOURCE_INSTALL_PATH=$(shell readlink -m $(DESTDIR)/$(SOURCE_PATH))
SCRIPTS_INSTALL_PATH=$(SOURCE_INSTALL_PATH)/$(SCRIPTS_FOLDER)
SDK_LIB_PATH=$(SOURCE_PATH)/$(LIB_DIR)
SDK_LIB_INSTALL_PATH=$(shell readlink -m $(DESTDIR)/$(SDK_LIB_PATH))
USR_LIB_PATH=$(shell readlink -m /usr/$(or $(notdir $(shell gcc -print-multi-os-directory 2> /dev/null)),$(if $(wildcard /usr/lib64/.*),lib64),lib)/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2> /dev/null))
USR_LIB_INSTALL_PATH=$(shell readlink -m $(DESTDIR)/$(USR_LIB_PATH))
USR_BIN_INSTALL_PATH=$(shell readlink -m $(DESTDIR)/usr/bin)

default:

install: install_source install_script install_gdb install_library install_pkgconfig update_pkgconfig

install_source: #for all format
	install -d $(SOURCE_INSTALL_PATH)
	cp -r $(SOURCE_FOLDER)/* $(SOURCE_INSTALL_PATH)

install_script: #for bin format
ifeq ($(INSTALLER_FORMAT),BIN)
	install -d $(SCRIPTS_INSTALL_PATH)
	install $(SCRIPTS_FOLDER)/* $(SCRIPTS_INSTALL_PATH)
endif

install_gdb:
	@sed -i "s#@SDK_LIB_PATH@#$(SDK_LIB_PATH)#" $(SOURCE_INSTALL_PATH)/bin/sgx-gdb
	chmod +x $(SOURCE_INSTALL_PATH)/bin/sgx-gdb
ifneq ($(INSTALLER_FORMAT),BIN)
	install -d $(USR_BIN_INSTALL_PATH)
	mv $(SOURCE_INSTALL_PATH)/bin/sgx-gdb $(USR_BIN_INSTALL_PATH)
endif

install_library: #for deb & rpm format
ifneq ($(INSTALLER_FORMAT),BIN)
	install -d $(USR_LIB_INSTALL_PATH)
	mv $(SDK_LIB_INSTALL_PATH)/libsgx_uae_service_sim.so $(USR_LIB_INSTALL_PATH)
	mv $(SDK_LIB_INSTALL_PATH)/libsgx_urts_sim.so $(USR_LIB_INSTALL_PATH)
endif

install_pkgconfig: #for deb & rpm format
ifneq ($(INSTALLER_FORMAT),BIN)
	install -d $(USR_LIB_INSTALL_PATH)/pkgconfig
	mv $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_uae_service_sim.pc $(USR_LIB_INSTALL_PATH)/pkgconfig
	mv $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_urts_sim.pc $(USR_LIB_INSTALL_PATH)/pkgconfig
	mv $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_uae_service.pc $(USR_LIB_INSTALL_PATH)/pkgconfig
	mv $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_urts.pc $(USR_LIB_INSTALL_PATH)/pkgconfig
	@sed -i "s#\(libdir=\).*#\1$(USR_LIB_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_uae_service_sim.pc
	@sed -i "s#\(libdir=\).*#\1$(USR_LIB_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_urts_sim.pc
	rm -fr $(SOURCE_INSTALL_PATH)/pkgconfig
endif

update_pkgconfig: #for bin format
ifeq ($(INSTALLER_FORMAT),BIN)
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_INSTALL_PATH)#" $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_uae_service_sim.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_INSTALL_PATH)#" $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_urts_sim.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_INSTALL_PATH)#" $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_uae_service.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_INSTALL_PATH)#" $(SOURCE_INSTALL_PATH)/pkgconfig/libsgx_urts.pc
else
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_uae_service_sim.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_urts_sim.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_uae_service.pc
	@sed -i "s#\(prefix=\).*#\1$(SOURCE_PATH)#" $(USR_LIB_INSTALL_PATH)/pkgconfig/libsgx_urts.pc
endif