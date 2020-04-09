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

DCAP_VER?= 1.6
DCAP_DOWNLOAD_BASE ?= https://github.com/intel/SGXDataCenterAttestationPrimitives/archive

CHECK_OPT :=
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration)", "")
CHECK_OPT := dcap_source
endif

include buildenv.mk
.PHONY: all dcap_source psw sdk clean rebuild sdk_install_pkg psw_install_pkg
.NOTPARALLEL: dcap_source sdk psw

all: tips

tips:
	@echo "Tips:"
	@echo "     This \"make\" command will show tips only and make nothing."
	@echo "     1. If you want to build Intel(R) SGX SDK with default configuration, please take the following steps:"
	@echo "        1) ensure that you have installed required tools described in README.md in same directory"
	@echo "        2) enter the command: \"make sdk\""
	@echo "     2. If you want to build Intel(R) SGX PSW with default configuration, please take the following steps:"
	@echo "        1) ensure that you have installed additional required tools decribed in README.md in same directory"
	@echo "        2) ensure that you have installed latest Intel(R) SGX SDK Installer which could be downloaded from: https://software.intel.com/en-us/sgx-sdk/download" and followed Installation Guide in the same page to finish installation.
	@echo "        3) enter the commmand: \"make psw\""
	@echo "     3. If you want to build other targets, please also follow README.md in same directory"

dcap_source:
ifeq ($(shell git rev-parse --is-inside-work-tree), true)
	git submodule update --init --recursive
else
	curl --output dcap_source.tar.gz -L --tlsv1 ${DCAP_DOWNLOAD_BASE}/DCAP_${DCAP_VER}.tar.gz
	tar xvzf dcap_source.tar.gz
	$(RM) dcap_source.tar.gz
	$(RM) -rf external/dcap_source
	mv SGXDataCenterAttestationPrimitives-DCAP_${DCAP_VER} external/dcap_source
endif

psw: $(CHECK_OPT)
	$(MAKE) -C psw/ USE_OPT_LIBS=$(USE_OPT_LIBS)

sdk_no_mitigation: 
	$(MAKE) -C sdk/ USE_OPT_LIBS=$(USE_OPT_LIBS)

sdk:
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE) MITIGATION-CVE-2020-0551=LOAD
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE) MITIGATION-CVE-2020-0551=CF
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE)

# Generate SE SDK Install package
sdk_install_pkg_no_mitigation: sdk_no_mitigation
	./linux/installer/bin/build-installpkg.sh sdk

sdk_install_pkg: sdk
	./linux/installer/bin/build-installpkg.sh sdk cve-2020-0551

psw_install_pkg: psw
	./linux/installer/bin/build-installpkg.sh psw

.PHONY: deb_libsgx_ae_qe3
deb_libsgx_ae_qe3:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ae_qe3_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-qe3/libsgx-ae-qe3*.deb ./linux/installer/deb/sgx-aesm-service/
.PHONY: deb_libsgx_qe3_logic
deb_libsgx_qe3_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_qe3_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-qe3-logic/libsgx-qe3-logic*deb ./linux/installer/deb/sgx-aesm-service/
.PHONY: deb_libsgx_pce_logic
deb_libsgx_pce_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_pce_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-pce-logic/libsgx-pce-logic*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_dcap_default_qpl
deb_libsgx_dcap_default_qpl: 
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_dcap_default_qpl_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_dcap_pccs
deb_libsgx_dcap_pccs: 
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_dcap_pccs_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/sgx-dcap-pccs/sgx-dcap-pccs*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_sgx_aesm_service
deb_sgx_aesm_service: psw
	./linux/installer/deb/sgx-aesm-service/build.sh

.PHONY: deb_libsgx_epid
deb_libsgx_epid: psw
	./linux/installer/deb/libsgx-epid/build.sh

.PHONY: deb_libsgx_launch
deb_libsgx_launch: psw
	./linux/installer/deb/libsgx-launch/build.sh

.PHONY: deb_libsgx_quote_ex
deb_libsgx_quote_ex: psw
	./linux/installer/deb/libsgx-quote-ex/build.sh

.PHONY: deb_libsgx_uae_service
deb_libsgx_uae_service: psw
	./linux/installer/deb/libsgx-uae-service/build.sh

.PHONY: deb_libsgx_enclave_common
deb_libsgx_enclave_common: psw
	./linux/installer/deb/libsgx-enclave-common/build.sh

.PHONY: deb_libsgx_urts
deb_libsgx_urts: psw
	./linux/installer/deb/libsgx-urts/build.sh

.PHONY: deb_psw_pkg
deb_psw_pkg: deb_libsgx_qe3_logic deb_libsgx_pce_logic deb_sgx_aesm_service deb_libsgx_epid deb_libsgx_launch deb_libsgx_quote_ex deb_libsgx_uae_service deb_libsgx_enclave_common deb_libsgx_urts deb_libsgx_ae_qe3 deb_libsgx_dcap_default_qpl deb_libsgx_dcap_pccs

.PHONY: deb_local_repo
deb_local_repo: deb_psw_pkg
	./linux/installer/common/local_repo_builder/local_repo_builder.sh debian build

.PHONY: rpm_libsgx_ae_qe3
rpm_libsgx_ae_qe3:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_ae_qe3_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-qe3/libsgx-ae-qe3*.rpm ./linux/installer/rpm/sgx-aesm-service/
.PHONY: rpm_libsgx_pce_logic
rpm_libsgx_pce_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_pce_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-pce-logic/libsgx-pce-logic*.rpm ./linux/installer/rpm/sgx-aesm-service/
.PHONY: rpm_libsgx_qe3_logic
rpm_libsgx_qe3_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_qe3_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-qe3-logic/libsgx-qe3-logic*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_sgx_aesm_service
rpm_sgx_aesm_service: psw
	./linux/installer/rpm/sgx-aesm-service/build.sh

.PHONY: rpm_libsgx_epid
rpm_libsgx_epid: psw
	./linux/installer/rpm/libsgx-epid/build.sh

.PHONY: rpm_libsgx_launch
rpm_libsgx_launch: psw
	./linux/installer/rpm/libsgx-launch/build.sh

.PHONY: rpm_libsgx_quote_ex
rpm_libsgx_quote_ex: psw
	./linux/installer/rpm/libsgx-quote-ex/build.sh

.PHONY: rpm_libsgx_uae_service
rpm_libsgx_uae_service: psw
	./linux/installer/rpm/libsgx-uae-service/build.sh

.PHONY: rpm_libsgx_enclave_common
rpm_libsgx_enclave_common: psw
	./linux/installer/rpm/libsgx-enclave-common/build.sh

.PHONY: rpm_libsgx_urts
rpm_libsgx_urts: psw
	./linux/installer/rpm/libsgx-urts/build.sh

.PHONY: rpm_sdk_pkg
rpm_sdk_pkg: sdk
	./linux/installer/rpm/sdk/build.sh

.PHONY: rpm_psw_pkg
rpm_psw_pkg: rpm_libsgx_pce_logic rpm_libsgx_qe3_logic rpm_sgx_aesm_service rpm_libsgx_epid rpm_libsgx_launch rpm_libsgx_quote_ex rpm_libsgx_uae_service rpm_libsgx_enclave_common rpm_libsgx_urts rpm_libsgx_ae_qe3

.PHONY: rpm_local_repo
rpm_local_repo: rpm_psw_pkg
	./linux/installer/common/local_repo_builder/local_repo_builder.sh rpm build

clean:
	@$(MAKE) -C sdk/                                clean
	@$(MAKE) -C psw/                                clean
	@$(RM)   -r $(ROOT_DIR)/build
	@$(RM)   -r linux/installer/bin/sgx_linux*.bin
	./linux/installer/deb/sgx-aesm-service/clean.sh
	./linux/installer/deb/libsgx-epid/clean.sh
	./linux/installer/deb/libsgx-launch/clean.sh
	./linux/installer/deb/libsgx-quote-ex/clean.sh
	./linux/installer/deb/libsgx-uae-service/clean.sh
	./linux/installer/deb/libsgx-enclave-common/clean.sh
	./linux/installer/deb/libsgx-urts/clean.sh
	./linux/installer/common/local_repo_builder/local_repo_builder.sh debian clean
	./linux/installer/rpm/sgx-aesm-service/clean.sh
	./linux/installer/rpm/libsgx-epid/clean.sh
	./linux/installer/rpm/libsgx-launch/clean.sh
	./linux/installer/rpm/libsgx-quote-ex/clean.sh
	./linux/installer/rpm/libsgx-uae-service/clean.sh
	./linux/installer/rpm/libsgx-enclave-common/clean.sh
	./linux/installer/rpm/libsgx-urts/clean.sh
	./linux/installer/rpm/sdk/clean.sh
	./linux/installer/common/local_repo_builder/local_repo_builder.sh rpm clean

rebuild:
	$(MAKE) clean
	$(MAKE) all
