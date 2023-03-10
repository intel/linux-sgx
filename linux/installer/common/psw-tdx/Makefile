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

include installConfig

ACQUIRE_PSW_VERSION = $(shell awk  \
                     '$$2 ~ /$1/ { print substr($$3, 2, length($$3) - 2); }' \
                     $(SRCDIR)/common/inc/internal/se_version.h)

ACQUIRE_DCAP_VERSION = $(shell awk  \
                      '$$2 ~ /$1/ { print substr($$3, 2, length($$3) - 2); }' \
                      $(SRCDIR)/external/dcap_source/QuoteGeneration/common/inc/internal/se_version.h)

PCE_FULL_VER:= $(call ACQUIRE_PSW_VERSION,PCE_VERSION)
PCE_MAJOR_VER:=$(word 1,$(subst ., ,$(PCE_FULL_VER)))
IDE_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,IDE_VERSION)
IDE_MAJOR_VER:=$(word 1,$(subst ., ,$(IDE_FULL_VER)))
TDQE_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,TDQE_VERSION)
TDQE_MAJOR_VER:=$(word 1,$(subst ., ,$(TDQE_FULL_VER)))
QVE_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,QVE_VERSION)
QVE_MAJOR_VER:=$(word 1,$(subst ., ,$(QVE_FULL_VER)))
URTS_FULL_VER:= $(call ACQUIRE_PSW_VERSION,URTS_VERSION)
URTS_MAJOR_VER:=$(word 1,$(subst ., ,$(URTS_FULL_VER)))
ECL_FULL_VER:= $(call ACQUIRE_PSW_VERSION,ENCLAVE_COMMON_VERSION)
ECL_MAJOR_VER:=$(word 1,$(subst ., ,$(ECL_FULL_VER)))
QPL_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,DEFAULT_QPL_VERSION)
QPL_MAJOR_VER:=$(word 1,$(subst ., ,$(QPL_FULL_VER)))
QCNL_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,DEFAULT_QPL_VERSION)
QCNL_MAJOR_VER:=$(word 1,$(subst ., ,$(QCNL_FULL_VER)))
QVL_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,QUOTE_VERIFIER_VERSION)
QVL_MAJOR_VER:=$(word 1,$(subst ., ,$(QVL_FULL_VER)))
PCE_LOGIC_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,PCE_WRAPPER_VERSION)
PCE_LOGIC_MAJOR_VER:=$(word 1,$(subst ., ,$(PCE_LOGIC_FULL_VER)))
TDX_LOGIC_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,TDQE_WRAPPER_VERSION)
TDX_LOGIC_MAJOR_VER:=$(word 1,$(subst ., ,$(TDX_LOGIC_FULL_VER)))
RAN_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,STRFILEVER)
RAN_MAJOR_VER:=$(word 1,$(subst ., ,$(RAN_FULL_VER)))
RAU_FULL_VER:= $(call ACQUIRE_DCAP_VERSION,STRFILEVER)
RAU_MAJOR_VER:=$(word 1,$(subst ., ,$(RAU_FULL_VER)))

CUR_PATH:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))
BOM_PATH:=$(CUR_PATH)/BOM_install
GEN_SCRIPT:=$(realpath $(CUR_PATH)/../gen_source/copy_source.py)

PACKAGE_ROOT_PATH:=$(SRCDIR)/build/pkgroot

USR_LIB_PATH:=/usr/$(notdir $(shell gcc -print-multi-os-directory))/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2> /dev/null)
USR_INC_PATH=/usr/$(INC_DIR)

# Support systemd by default(for Fedora build environment)
QGSD_CONF=qgsd.service
QGSD_CONF_DEL=qgsd.conf
QGSD_CONF_PATH=$(if $(wildcard /lib/systemd/system/.),/lib/systemd/system,/usr/lib/systemd/system)

PCCS_CONF=pccs.service
PCCS_CONF_PATH=$(if $(wildcard /lib/systemd/system/.),/lib/systemd/system,/usr/lib/systemd/system)

RAD_CONF=mpa_registration_tool.service
RAD_CONF_DEL=mpa_registration_tool.conf
RAD_CONF_PATH=$(if $(wildcard /lib/systemd/system/.),/lib/systemd/system,/usr/lib/systemd/system)

TEST_COPYABLE = \( -d $1 -a -n "$$(shell ls -A $1 2> /dev/null)" \)

define PRE_INSTALL_TEMPLATE
pre_$(1): | $(PACKAGE_ROOT_PATH)
	python $(GEN_SCRIPT) --bom-file $(BOM_PATH)/$(1).txt \
			--src-path $(SRCDIR) --dst-path $$|/$(1)
endef

define INSTALL_AESM_SERVICE_TEMPLATE
$(1): pre_$(1) | $(PACKAGE_ROOT_PATH)
	install -d $$(shell readlink -m $(DESTDIR)/$$@)
	test $(call TEST_COPYABLE,$$|/$$@/$(LIB_DIR)) && (                 \
	install -d $$(shell readlink -m $(DESTDIR)/$$@/$(USR_LIB_PATH)) && \
	install $$|/$$@/$(LIB_DIR)/* $(DESTDIR)/$$@/$(USR_LIB_PATH)     && \
	rm -fr $$|/$$@/$(LIB_DIR) ) ||:
	test $(call TEST_COPYABLE,$$|/$$@/$(ETC_DIR)) && (            \
	install -d $$(shell readlink -m $(DESTDIR)/$$@/$(ETC_DIR)) && \
	cp -fr $$|/$$@/$(ETC_DIR)/* $(DESTDIR)/$$@/$(ETC_DIR)      && \
	rm -fr $$|/$$@/$(ETC_DIR) ) ||:

post_$(1): $(1) | $(PACKAGE_ROOT_PATH)
	test $(call TEST_COPYABLE,$$|/$$<) && (                                                   \
	install -d $$(shell readlink -m $(DESTDIR)/$$</$(SGX_INSTALL_PATH)/$(TDX_QGS_PACKAGE)) && \
	cp -fr $$|/$$</* $(DESTDIR)/$$</$(SGX_INSTALL_PATH)/$(TDX_QGS_PACKAGE) ) ||:
endef

define INSTALL_DEV_LIB_TEMPLATE
$(1): pre_$(1) | $(PACKAGE_ROOT_PATH)
	install -d $$(shell readlink -m $(DESTDIR)/$$@)
	test $(call TEST_COPYABLE,$$|/$$@/$(LIB_DIR)) && (                 \
	install -d $$(shell readlink -m $(DESTDIR)/$$@/$(USR_LIB_PATH)) && \
	install $$|/$$@/$(LIB_DIR)/*.so $(DESTDIR)/$$@/$(USR_LIB_PATH)  && \
	rm -fr $$|/$$@/$(LIB_DIR) ) ||:
	test $(call TEST_COPYABLE,$$|/$$@/$(INC_DIR)) && (                 \
	install -d $$(shell readlink -m $(DESTDIR)/$$@/$(USR_INC_PATH)) && \
	install -d $$(shell readlink -m $(DESTDIR)/$$@/$(USR_LIB_PATH)) && \
	cp -fr $$|/$$@/$(INC_DIR)/* $(DESTDIR)/$$@/$(USR_INC_PATH)      && \
	rm -fr $$|/$$@/$(INC_DIR) ) ||:

post_$(1): $(1) | $(PACKAGE_ROOT_PATH)
	test $(call TEST_COPYABLE,$$|/$$<) && ( \
	cp -fr $$|/$$</* $(DESTDIR)/$$< ) ||:
endef

TDX_QGS_PKGS:= $(TDX_QGS_PACKAGE)

AE_PKGS:= $(AE_IDE_PACKAGE)                  \
          $(AE_PCE_PACKAGE)                  \
          $(AE_TDQE_PACKAGE)                 \
          $(AE_QVE_PACKAGE)

DEV_LIB_PKGS:= $(ENCLAVE_COMMON_PACKAGE)     \
               $(ENCLAVE_COMMON_DEV_PACKAGE) \
               $(URTS_PACKAGE)               \
               $(SGX_HEADERS_PACKAGE)        \
               $(TDX_LOGIC_PACKAGE)          \
               $(TDX_LOGIC_DEV_PACKAGE)      \
               $(PCE_LOGIC_PACKAGE)          \
               $(DCAP_QPL_PACKAGE)           \
               $(DCAP_QPL_DEV_PACKAGE)       \
               $(DCAP_QVL_PACKAGE)           \
               $(DCAP_QVL_DEV_PACKAGE)       \
               $(TDX_ATTEST_PACKAGE)         \
               $(TDX_ATTEST_DEV_PACKAGE)     \
               $(RA_NETWORK_PACKAGE)         \
               $(RA_NETWORK_DEV_PACKAGE)     \
               $(RA_UEFI_PACKAGE)            \
               $(RA_UEFI_DEV_PACKAGE)

ALL_PKGS:= $(TDX_QGS_PKGS) $(AE_PKGS) $(DEV_LIB_PKGS)

$(foreach PKG,$(TDX_QGS_PKGS) $(AE_PKGS),$(eval $(call INSTALL_AESM_SERVICE_TEMPLATE,$(PKG))))
$(foreach PKG,$(DEV_LIB_PKGS),$(eval $(call INSTALL_DEV_LIB_TEMPLATE,$(PKG))))
$(foreach PKG,$(ALL_PKGS) $(DCAP_PCCS_PACKAGE) $(RA_SERVICE_PACKAGE) $(PCK_ID_RETRIEVAL_TOOL_PACKAGE),$(eval $(call PRE_INSTALL_TEMPLATE,$(PKG))))

PHONY+=$(ALL_PKGS)
PHONY+=$(foreach PKG,$(ALL_PKGS),pre_$(PKG))
PHONY+=$(foreach PKG,$(ALL_PKGS),post_$(PKG))

PHONY+=install_$(TDX_QGS_PACKAGE)
install_$(TDX_QGS_PACKAGE): $(foreach PKG,$(TDX_QGS_PKGS),post_$(PKG))
	install -d $(shell readlink -m $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(QGSD_CONF_PATH))
	sed -e "s:@qgs_folder@:$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE):"                       \
		$(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/$(QGSD_CONF) \
		> $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(QGSD_CONF_PATH)/$(QGSD_CONF)
	rm -f $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/$(QGSD_CONF)
	rm -f $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/$(QGSD_CONF_DEL)
	$(if $(shell grep '^ID=clear-linux-os' /usr/lib/os-release 2> /dev/null),                                       \
		$(if $(wildcard $(DESTDIR)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/conf/$(QGSD_CONF)),                   \
			mv $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/conf/$(QGSD_CONF)           \
				$(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/conf/$(QGSD_CONF).sample), \
		$(if $(wildcard $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(TDX_QGS_PACKAGE_PATH)/$(TDX_QGS_PACKAGE)/conf/.*),          \
			install -d $(shell readlink -m $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(ETC_DIR)) &&                             \
			cp -fr $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(SGX_INSTALL_PATH)/$(TDX_QGS_PACKAGE)/conf/*                      \
				$(DESTDIR)/$(TDX_QGS_PACKAGE)/$(ETC_DIR) &&                                                         \
		rm -fr $(DESTDIR)/$(TDX_QGS_PACKAGE)/$(SGX_INSTALL_PATH)/$(TDX_QGS_PACKAGE)/conf))

PHONY+=install_$(DCAP_PCCS_PACKAGE)
install_$(DCAP_PCCS_PACKAGE): pre_$(DCAP_PCCS_PACKAGE) | $(PACKAGE_ROOT_PATH)
	install -d $(shell readlink -m $(DESTDIR)/$(DCAP_PCCS_PACKAGE)/$(PCCS_CONF_PATH))                        && \
	cp -f $|/$(DCAP_PCCS_PACKAGE)/$(PCCS_CONF) $(DESTDIR)/$(DCAP_PCCS_PACKAGE)/$(PCCS_CONF_PATH)             && \
	rm -f $|/$(DCAP_PCCS_PACKAGE)/$(PCCS_CONF)
	install -d $(shell readlink -m $(DESTDIR)/$(DCAP_PCCS_PACKAGE)/$(SGX_INSTALL_PATH)/$(DCAP_PCCS_PACKAGE)) && \
	cp -fr $|/$(DCAP_PCCS_PACKAGE)/* $(DESTDIR)/$(DCAP_PCCS_PACKAGE)/$(SGX_INSTALL_PATH)/$(DCAP_PCCS_PACKAGE)

PHONY+=$(RA_SERVICE_PACKAGE)
$(RA_SERVICE_PACKAGE): pre_$(RA_SERVICE_PACKAGE) | $(PACKAGE_ROOT_PATH)
	install -d $(shell readlink -m $(DESTDIR)/$@/$(SGX_INSTALL_PATH)/$@) && \
	cp -fr $|/$@/* $(DESTDIR)/$@/$(SGX_INSTALL_PATH)/$@

PHONY+=install_$(RA_SERVICE_PACKAGE)
install_$(RA_SERVICE_PACKAGE): $(RA_SERVICE_PACKAGE)
	install -d $(shell readlink -m $(DESTDIR)/$</$(RAD_CONF_PATH))
	sed -e "s:@mpa_folder@:$(SGX_INSTALL_PATH)/$</:"                \
		 $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</$(RAD_CONF)           \
		 > $(DESTDIR)/$</$(RAD_CONF_PATH)/$(RAD_CONF)
	rm -f $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</$(RAD_CONF)
	rm -f $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</$(RAD_CONF_DEL)
	$(if $(wildcard $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</conf/*),   \
		install -d $(shell readlink -m $(DESTDIR)/$</$(ETC_DIR)) && \
		cp -fr $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</conf/*          \
			$(DESTDIR)/$</$(ETC_DIR)                         && \
		rm -fr $(DESTDIR)/$</$(SGX_INSTALL_PATH)/$</conf)

PHONY+=install_$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)
install_$(PCK_ID_RETRIEVAL_TOOL_PACKAGE): pre_$(PCK_ID_RETRIEVAL_TOOL_PACKAGE) | $(PACKAGE_ROOT_PATH)
	install -d $(shell readlink -m $(DESTDIR)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)/$(SGX_INSTALL_PATH)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)) && \
	cp -fr $|/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)/* $(DESTDIR)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)/$(SGX_INSTALL_PATH)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)
	cd $(shell readlink -m $(DESTDIR)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE)/$(SGX_INSTALL_PATH)/$(PCK_ID_RETRIEVAL_TOOL_PACKAGE))         && \
	ln -fs $(shell readlink -m $(USR_LIB_PATH)/libsgx_id_enclave.signed.so.$(IDE_MAJOR_VER))                                         && \
	ln -fs $(shell readlink -m $(USR_LIB_PATH)/libsgx_pce.signed.so.$(PCE_MAJOR_VER))

PHONY+=install_ae
install_ae: $(foreach PKG,$(AE_PKGS),post_$(PKG))
	cd $(shell readlink -m $(DESTDIR)/$(AE_PCE_PACKAGE)/$(USR_LIB_PATH))                                   && \
	mv libsgx_pce.signed.so libsgx_pce.signed.so.$(PCE_FULL_VER)                                           && \
	ln -fs libsgx_pce.signed.so.$(PCE_FULL_VER) libsgx_pce.signed.so.$(PCE_MAJOR_VER)                      && \
	ln -fs libsgx_pce.signed.so.$(PCE_MAJOR_VER) libsgx_pce.signed.so
	cd $(shell readlink -m $(DESTDIR)/$(AE_TDQE_PACKAGE)/$(USR_LIB_PATH))                                  && \
	mv libsgx_tdqe.signed.so libsgx_tdqe.signed.so.$(TDQE_FULL_VER)                                        && \
	ln -fs libsgx_tdqe.signed.so.$(TDQE_FULL_VER) libsgx_tdqe.signed.so.$(TDQE_MAJOR_VER)                  && \
	ln -fs libsgx_tdqe.signed.so.$(TDQE_MAJOR_VER) libsgx_tdqe.signed.so
	cd $(shell readlink -m $(DESTDIR)/$(AE_QVE_PACKAGE)/$(USR_LIB_PATH))                                   && \
	mv libsgx_qve.signed.so libsgx_qve.signed.so.$(QVE_FULL_VER)                                           && \
	ln -fs libsgx_qve.signed.so.$(QVE_FULL_VER) libsgx_qve.signed.so.$(QVE_MAJOR_VER)                      && \
	ln -fs libsgx_qve.signed.so.$(QVE_MAJOR_VER) libsgx_qve.signed.so
	cd $(shell readlink -m $(DESTDIR)/$(AE_IDE_PACKAGE)/$(USR_LIB_PATH))                                   && \
	mv libsgx_id_enclave.signed.so libsgx_id_enclave.signed.so.$(IDE_FULL_VER)                             && \
	ln -fs libsgx_id_enclave.signed.so.$(IDE_FULL_VER) libsgx_id_enclave.signed.so.$(IDE_MAJOR_VER)

PHONY+=install_dev_lib
install_dev_lib: $(foreach PKG,$(DEV_LIB_PKGS),post_$(PKG))
	rm -fr $(shell readlink -m $(DESTDIR)/$(SGX_HEADERS_PACKAGE)/$(USR_LIB_PATH))
	cd $(shell readlink -m $(DESTDIR)/$(ENCLAVE_COMMON_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libsgx_enclave_common.so libsgx_enclave_common.so.$(ECL_FULL_VER)             && \
	ln -fs libsgx_enclave_common.so.$(ECL_FULL_VER) libsgx_enclave_common.so.$(ECL_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(ENCLAVE_COMMON_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libsgx_enclave_common.so.$(ECL_MAJOR_VER) libsgx_enclave_common.so
	cd $(shell readlink -m $(DESTDIR)/$(URTS_PACKAGE)/$(USR_LIB_PATH))      && \
	mv libsgx_urts.so libsgx_urts.so.$(URTS_FULL_VER)                       && \
	ln -fs libsgx_urts.so.$(URTS_FULL_VER) libsgx_urts.so.$(URTS_MAJOR_VER) && \
	ln -fs libsgx_urts.so.$(URTS_MAJOR_VER) libsgx_urts.so
	cd $(shell readlink -m $(DESTDIR)/$(DCAP_QPL_PACKAGE)/$(USR_LIB_PATH))            && \
	mv libdcap_quoteprov.so libdcap_quoteprov.so.$(QPL_FULL_VER)                      && \
	ln -fs libdcap_quoteprov.so.$(QPL_FULL_VER) libdcap_quoteprov.so.$(QPL_MAJOR_VER) && \
	mv libsgx_default_qcnl_wrapper.so libsgx_default_qcnl_wrapper.so.$(QCNL_FULL_VER) && \
	ln -fs libsgx_default_qcnl_wrapper.so.$(QCNL_FULL_VER) libsgx_default_qcnl_wrapper.so.$(QCNL_MAJOR_VER)
	install -d $(shell readlink -m $(DESTDIR)/$(DCAP_QPL_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	cd $(shell readlink -m $(DESTDIR)/$(DCAP_QPL_DEV_PACKAGE)/$(USR_LIB_PATH))         && \
	ln -fs libdcap_quoteprov.so.$(QCNL_MAJOR_VER) libdcap_quoteprov.so                 && \
	ln -fs libsgx_default_qcnl_wrapper.so.$(QCNL_MAJOR_VER) libsgx_default_qcnl_wrapper.so
	cd $(shell readlink -m $(DESTDIR)/$(DCAP_QVL_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libsgx_dcap_quoteverify.so libsgx_dcap_quoteverify.so.$(QVL_FULL_VER)   && \
	ln -fs libsgx_dcap_quoteverify.so.$(QVL_FULL_VER) libsgx_dcap_quoteverify.so.$(QVL_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(DCAP_QVL_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libsgx_dcap_quoteverify.so.$(QVL_MAJOR_VER) libsgx_dcap_quoteverify.so
	cd $(shell readlink -m $(DESTDIR)/$(RA_NETWORK_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libmpa_network.so libmpa_network.so.$(RAN_FULL_VER)                       && \
	ln -fs libmpa_network.so.$(RAN_FULL_VER) libmpa_network.so.$(RAN_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(RA_NETWORK_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libmpa_network.so.$(RAN_MAJOR_VER) libmpa_network.so
	cd $(shell readlink -m $(DESTDIR)/$(RA_UEFI_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libmpa_uefi.so libmpa_uefi.so.$(RAU_FULL_VER)                          && \
	ln -fs libmpa_uefi.so.$(RAU_FULL_VER) libmpa_uefi.so.$(RAU_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(RA_UEFI_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libmpa_uefi.so.$(RAU_MAJOR_VER) libmpa_uefi.so
	cd $(shell readlink -m $(DESTDIR)/$(TDX_LOGIC_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libsgx_tdx_logic.so libsgx_tdx_logic.so.$(TDX_LOGIC_FULL_VER)            && \
	ln -fs libsgx_tdx_logic.so.$(TDX_LOGIC_FULL_VER) libsgx_tdx_logic.so.$(TDX_LOGIC_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(TDX_LOGIC_DEV_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libsgx_tdx_logic.so.$(TDX_LOGIC_MAJOR_VER) libsgx_tdx_logic.so
	cd $(shell readlink -m $(DESTDIR)/$(PCE_LOGIC_PACKAGE)/$(USR_LIB_PATH))     && \
	mv libsgx_pce_logic.so libsgx_pce_logic.so.$(PCE_LOGIC_FULL_VER)            && \
	ln -fs libsgx_pce_logic.so.$(PCE_LOGIC_FULL_VER) libsgx_pce_logic.so.$(RAN_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(PCE_LOGIC_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libsgx_pce_logic.so.$(PCE_LOGIC_MAJOR_VER) libsgx_pce_logic.so
	cd $(shell readlink -m $(DESTDIR)/$(TDX_ATTEST_PACKAGE)/$(USR_LIB_PATH))      && \
	mv libtdx_attest.so libtdx_attest.so.$(RAN_FULL_VER)                          && \
	ln -fs libtdx_attest.so.$(RAN_FULL_VER) libtdx_attest.so.$(RAN_MAJOR_VER)
	cd $(shell readlink -m $(DESTDIR)/$(TDX_ATTEST_PACKAGE)/$(USR_LIB_PATH)) && \
	ln -fs libtdx_attest.so.$(RAN_MAJOR_VER) libtdx_attest.so

PHONY+=install
install: install_$(TDX_QGS_PACKAGE)          \
	install_$(DCAP_PCCS_PACKAGE)             \
	install_$(RA_SERVICE_PACKAGE)            \
	install_$(PCK_ID_RETRIEVAL_TOOL_PACKAGE) \
	install_ae                               \
	install_dev_lib
	rm -fr $(PACKAGE_ROOT_PATH)
	mkdir -p $(DESTDIR)/license
	cp $(SRCDIR)/License.txt $(DESTDIR)/license

$(PACKAGE_ROOT_PATH):
	mkdir -p $@

.PHONY: $(PHONY)
.DEFAULT: install
