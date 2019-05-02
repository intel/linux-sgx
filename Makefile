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
DCAP_VER?= 1.1
DCAP_DOWNLOAD_BASE ?= https://github.com/intel/SGXDataCenterAttestationPrimitives/archive

include buildenv.mk
.PHONY: all dcap_source psw sdk clean rebuild sdk_install_pkg psw_install_pkg
.NOTPARALLEL: dcap_source sdk psw

all: dcap_source sdk psw

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

psw: dcap_source sdk
	$(MAKE) -C psw/ USE_OPT_LIBS=$(USE_OPT_LIBS)

sdk: dcap_source
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
