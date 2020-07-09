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

include installConfig

PACKAGE_ROOT_FOLDER=pkgroot
PACKAGES=$(notdir $(wildcard $(PACKAGE_ROOT_FOLDER)/*))

VAR_OPT_PATH=/var/opt/aesmd
USR_LIB_PATH=/usr/$(notdir $(shell gcc -print-multi-os-directory))/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2> /dev/null)

AESMD_CONF_NAME=$(if $(wildcard /run/systemd/system/.*),aesmd.service,$(if $(wildcard /etc/init/.*),aesmd.conf,))
AESMD_CONF_DEL=$(if $(wildcard /run/systemd/system/.*),aesmd.conf,$(if $(wildcard /etc/init/.*),aesmd.service,))
AESMD_CONF_PATH=$(if $(wildcard /run/systemd/system/.*),$(if $(wildcard /lib/systemd/system/.*),/lib/systemd/system,/usr/lib/systemd/system),$(if $(wildcard /etc/init/.*),/etc/init/))

ifeq ($(AESMD_CONF_NAME),)
ifneq ($(shell awk -F/ '$$2 == "docker"' /proc/self/cgroup),)
AESMD_CONF_NAME=aesmd.service
AESMD_CONF_DEL=aesmd.conf
AESMD_CONF_PATH=/lib/systemd/system
$(warning "You may need to start aesmd manually after it's installed!")
else
$(error "Unsupported platform - neither systemctl nor initctl is found!")
endif
endif

default:

install: $(PACKAGES)
	install -d $(shell readlink -m $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(VAR_OPT_PATH))
	install -d $(shell readlink -m $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESMD_CONF_PATH))
	sed -e "s:@aesm_folder@:$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm:" \
		$(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/$(AESMD_CONF_NAME) \
		> $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESMD_CONF_PATH)/$(AESMD_CONF_NAME)
	rm -f $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/$(AESMD_CONF_NAME)
	rm -f $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/$(AESMD_CONF_DEL)
	$(if $(shell grep '^ID=clear-linux-os' /usr/lib/os-release 2> /dev/null), \
		$(if $(wildcard $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf/aesmd.conf), \
			mv $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf/aesmd.conf \
				$(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf/aesmd.conf.sample), \
		$(if $(wildcard $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf/.*), \
			install -d $(shell readlink -m $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(ETC_DIR)) && \
			cp -fr $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf/* \
				$(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(ETC_DIR) && \
			rm -fr $(DESTDIR)/$(AESM_SERVICE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/conf))
	cd $(shell readlink -m $(DESTDIR)/$(AESM_ECDSA_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm) && \
	ln -fs $(shell readlink -m $(USR_LIB_PATH)/libsgx_qe3.signed.so) && \
	cd $(shell readlink -m $(DESTDIR)/$(AESM_PCE_PACKAGE_NAME)/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm) && \
	ln -fs $(shell readlink -m $(USR_LIB_PATH)/libsgx_pce.signed.so) && \
	ln -fs liburts_internal.so libsgx_urts.so
	
$(PACKAGES):
	install -d $(shell readlink -m $(DESTDIR)/$@)
	$(if $(wildcard $(PACKAGE_ROOT_FOLDER)/$@/$(LIB_DIR)/.*), \
		install -d $(shell readlink -m $(DESTDIR)/$@/$(USR_LIB_PATH)) && \
		install $(PACKAGE_ROOT_FOLDER)/$@/$(LIB_DIR)/* $(DESTDIR)/$@/$(USR_LIB_PATH), \
		install -d $(shell readlink -m $(DESTDIR)/$@/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)) && \
		cp -r $(PACKAGE_ROOT_FOLDER)/$@/* $(DESTDIR)/$@/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)) 
	$(if $(wildcard $(PACKAGE_ROOT_FOLDER)/$@/aesm/data/.*), \
		install -d $(shell readlink -m $(DESTDIR)/$@/$(VAR_OPT_PATH)) && \
		cp -fr $(DESTDIR)/$@/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/data \
			$(DESTDIR)/$@/$(VAR_OPT_PATH) && \
		rm -fr $(DESTDIR)/$@/$(AESM_SERVICE_PACKAGE_PATH)/$(AESM_SERVICE_PACKAGE_NAME)/aesm/data)
