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

DCAP_VER?= 1.3
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

sdk: 
	$(MAKE) -C sdk/ USE_OPT_LIBS=$(USE_OPT_LIBS)

# Generate SE SDK Install package
sdk_install_pkg: sdk
	./linux/installer/bin/build-installpkg.sh sdk

psw_install_pkg: psw
	./linux/installer/bin/build-installpkg.sh psw

deb_sgx_urts_pkg: psw
	./linux/installer/deb/libsgx-urts/build.sh

deb_sgx_enclave_common_pkg: psw
	./linux/installer/deb/libsgx-enclave-common/build.sh

deb_sgx_enclave_common_dev_pkg:
	./linux/installer/deb/libsgx-enclave-common-dev/build.sh

deb_pkg: deb_sgx_urts_pkg deb_sgx_enclave_common_pkg deb_sgx_enclave_common_dev_pkg
	@$(RM) -f ./linux/installer/deb/*.deb ./linux/installer/deb/*.ddeb
	cp `find ./linux/installer/deb/ -name "*.deb" -o -name "*.ddeb"` ./linux/installer/deb/

rpm_sdk_pkg: sdk
	./linux/installer/rpm/sdk/build.sh

rpm_psw_pkg: psw
	./linux/installer/rpm/psw/build.sh

rpm_psw_dev_pkg:
	./linux/installer/rpm/psw-dev/build.sh

rpm_pkg: rpm_sdk_pkg rpm_psw_pkg rpm_psw_dev_pkg
	@$(RM) -f ./linux/installer/rpm/*.rpm
	cp `find ./linux/installer/rpm/ -name "*.rpm"` ./linux/installer/rpm/

clean:
	@$(MAKE) -C sdk/                                clean
	@$(MAKE) -C psw/                                clean
	@$(RM)   -r $(ROOT_DIR)/build
	@$(RM)   -r linux/installer/bin/sgx_linux*.bin
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common-dbgsym_*
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common_*.tar.*
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common_*_amd64.*
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common_*.dsc
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common-dev/libsgx-enclave-common-dev*.deb
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common-dev/libsgx-enclave-common_*.tar.*
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common-dev/libsgx-enclave-common_*_amd64.*
	@$(RM)   -r linux/installer/deb/libsgx-enclave-common-dev/libsgx-enclave-common_*.dsc
	@$(RM)   -r linux/installer/deb/libsgx-urts/libsgx-enclave-common_*.tar.*
	@$(RM)   -r linux/installer/deb/libsgx-urts/libsgx-enclave-common_*_amd64.*
	@$(RM)   -r linux/installer/deb/libsgx-urts/libsgx-urts_*.deb
	@$(RM)   -r linux/installer/deb/*.deb
	@$(RM)   -r linux/installer/deb/*.ddeb
	@$(RM)   -r linux/installer/rpm/sdk/sgxsdk*.rpm
	@$(RM)   -r linux/installer/rpm/psw/sgxpsw*.rpm
	@$(RM)   -r linux/installer/rpm/psw-dev/sgxpsw-dev*.rpm
	@$(RM)   -r linux/installer/rpm/*.rpm
	@$(RM)   -rf linux/installer/common/psw/output
	@$(RM)   -rf linux/installer/common/psw/gen_source.py
	@$(RM)   -rf linux/installer/common/libsgx-enclave-common/output
	@$(RM)   -rf linux/installer/common/libsgx-enclave-common/gen_source.py
	@$(RM)   -rf linux/installer/common/libsgx-enclave-common-dev/output
	@$(RM)   -rf linux/installer/common/libsgx-enclave-common-dev/gen_source.py
	@$(RM)   -rf linux/installer/common/libsgx-urts/output
	@$(RM)   -rf linux/installer/common/libsgx-urts/gen_source.py
	@$(RM)   -rf linux/installer/common/sdk/output
	@$(RM)   -rf linux/installer/common/sdk/pkgconfig/x64
	@$(RM)   -rf linux/installer/common/sdk/pkgconfig/x86
	@$(RM)   -rf linux/installer/common/sdk/gen_source.py

rebuild:
	$(MAKE) clean
	$(MAKE) all
