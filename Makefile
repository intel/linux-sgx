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

include buildenv.mk
.PHONY: all tips preparation psw sdk_no_mitigation sdk clean rebuild tdx servtd_attest servtd_attest_preparation ipp sdk_install_pkg_no_mitigation sdk_install_pkg  sdk_install_pkg_from_source psw_install_pkg

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


preparation:
# As SDK build needs to clone and patch openmp, we cannot support the mode that download the source from github as zip.
# Only enable the download from git
	git submodule update --init --recursive
	cd external/dcap_source/external/jwt-cpp && git apply ../0001-Add-a-macro-to-disable-time-support-in-jwt-for-SGX.patch >/dev/null 2>&1 || \
	git apply ../0001-Add-a-macro-to-disable-time-support-in-jwt-for-SGX.patch -R --check
	./external/dcap_source/QuoteVerification/prepare_sgxssl.sh nobuild
	cd external/openmp/openmp_code && git apply ../0001-Enable-OpenMP-in-SGX.patch >/dev/null 2>&1 ||  git apply ../0001-Enable-OpenMP-in-SGX.patch --check -R
	cd external/protobuf/protobuf_code && git apply ../sgx_protobuf.patch >/dev/null 2>&1 ||  git apply ../sgx_protobuf.patch --check -R
	cd external/protobuf/protobuf_code && git submodule update --init --recursive && cd third_party/abseil-cpp && git apply ../../../sgx_abseil.patch>/dev/null 2>&1 || git apply ../../../sgx_abseil.patch --check -R
	./external/sgx-emm/create_symlink.sh
	cd external/mbedtls/mbedtls_code && git apply ../sgx_mbedtls.patch >/dev/null 2>&1 || git apply ../sgx_mbedtls.patch --check -R
	cd external/cbor && cp -r libcbor sgx_libcbor
	cd external/cbor/libcbor && git apply ../raw_cbor.patch >/dev/null 2>&1 || git apply ../raw_cbor.patch --check -R
	cd external/cbor/sgx_libcbor && git apply ../sgx_cbor.patch >/dev/null 2>&1 || git apply ../sgx_cbor.patch --check -R
	cd external/ippcp_internal/ipp-crypto && git apply ../0001-IPP-crypto-for-SGX.patch > /dev/null 2>&1 || git apply ../0001-IPP-crypto-for-SGX.patch --check -R
	cd external/ippcp_internal/ipp-crypto && mkdir -p build
	./download_prebuilt.sh
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh

psw:
	$(MAKE) -C psw/ USE_OPT_LIBS=$(USE_OPT_LIBS)

sdk_no_mitigation:
	$(MAKE) -C sdk/ USE_OPT_LIBS=$(USE_OPT_LIBS)
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl

sdk:
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE) MITIGATION-CVE-2020-0551=LOAD
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE) MITIGATION-CVE-2020-0551=CF
	$(MAKE) -C sdk/ clean
	$(MAKE) -C sdk/ MODE=$(MODE)
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=LOAD clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=LOAD
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=CF clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=CF
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl

tdx:
	$(MAKE) -C external/dcap_source/QuoteGeneration pce_logic
	$(MAKE) -C external/dcap_source/QuoteGeneration tdx_logic
	$(MAKE) -C external/dcap_source/QuoteGeneration tdx_qgs
	$(MAKE) -C external/dcap_source/QuoteGeneration tdx_attest
 
servtd_attest:
	$(MAKE) -C sdk/ servtd_attest SERVTD_ATTEST=1
	$(MAKE) -C external/dcap_source/QuoteGeneration servtd_attest

servtd_attest_preparation:
# Only enable the download from git
	git submodule update --init --recursive external/dcap_source external/sgx-emm/emm_src
	./external/sgx-emm/create_symlink.sh
	./external/dcap_source/QuoteVerification/prepare_sgxssl.sh nobuild

ipp:
	$(MAKE) -C external/ippcp_internal/ clean
	$(MAKE) -C external/ippcp_internal/ MITIGATION-CVE-2020-0551=LOAD
	$(MAKE) -C external/ippcp_internal/ clean
	$(MAKE) -C external/ippcp_internal/ MITIGATION-CVE-2020-0551=CF
	$(MAKE) -C external/ippcp_internal/ clean
	$(MAKE) -C external/ippcp_internal/

# Generate SE SDK Install package
sdk_install_pkg_no_mitigation: sdk_no_mitigation
	./linux/installer/bin/build-installpkg.sh sdk

sdk_install_pkg: sdk
	./linux/installer/bin/build-installpkg.sh sdk cve-2020-0551

sdk_install_pkg_from_source:
	$(MAKE) ipp
	$(MAKE) sdk
	./linux/installer/bin/build-installpkg.sh sdk cve-2020-0551

psw_install_pkg: psw
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_id_enclave.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(CP) external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so $(BUILD_DIR)
	$(CP) external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_id_enclave.signed.so $(BUILD_DIR)
	./linux/installer/bin/build-installpkg.sh psw

.PHONY: deb_libsgx_ae_qe3
deb_libsgx_ae_qe3:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qe3.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ae_qe3_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-qe3/libsgx-ae-qe3*.deb ./linux/installer/deb/sgx-aesm-service/
.PHONY: deb_libsgx_ae_id_enclave
deb_libsgx_ae_id_enclave:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_id_enclave.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ae_id_enclave_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-id-enclave/libsgx-ae-id-enclave*.deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_ae_tdqe deb_libsgx_tdx_logic deb_tdx_qgs deb_tdx_attest
ifeq ($(DISTR_ID)$(DISTR_VER),ubuntu18.04)
deb_libsgx_ae_tdqe:
	echo "Skip tdqe in ubuntu 18.04"
deb_libsgx_tdx_logic:
	echo "Skip tdx_logic in ubuntu 18.04"
deb_tdx_qgs:
	echo "Skip tdx_qgs in ubuntu 18.04"
deb_tdx_attest:
	echo "Skip tdx_attest in ubuntu 18.04"
else
deb_libsgx_ae_tdqe:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_tdqe.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ae_tdqe_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-tdqe/libsgx-ae-tdqe*.deb ./linux/installer/deb/sgx-aesm-service/

deb_libsgx_tdx_logic:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_tdx_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-tdx-logic/libsgx-tdx-logic*deb ./linux/installer/deb/sgx-aesm-service/

deb_tdx_qgs:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_tdx_qgs_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/tdx-qgs/tdx-qgs*deb ./linux/installer/deb/sgx-aesm-service/

deb_tdx_attest:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_tdx_attest_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libtdx-attest/libtdx-attest*deb ./linux/installer/deb/sgx-aesm-service/
endif

.PHONY: deb_libsgx_qe3_logic
deb_libsgx_qe3_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_qe3_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-qe3-logic/libsgx-qe3-logic*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_pce_logic
deb_libsgx_pce_logic: psw
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_pce_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/build/linux/libsgx_pce_logic.so* $(BUILD_DIR)
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-pce-logic/libsgx-pce-logic*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_sgx_aesm_service
deb_sgx_aesm_service: psw deb_libsgx_pce_logic
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

.PHONY: deb_libsgx_headers_pkg
deb_libsgx_headers_pkg:
	./linux/installer/deb/libsgx-headers/build.sh

ifeq ($(CC_BELOW_5_2), 1)
.PHONY: deb_psw_pkg
deb_psw_pkg: deb_libsgx_headers_pkg \
             deb_libsgx_qe3_logic \
             deb_libsgx_pce_logic \
             deb_sgx_aesm_service \
             deb_libsgx_epid \
             deb_libsgx_launch \
             deb_libsgx_quote_ex \
             deb_libsgx_uae_service \
             deb_libsgx_enclave_common \
             deb_libsgx_urts \
             deb_libsgx_ae_qe3 \
             deb_libsgx_ae_tdqe \
             deb_libsgx_ae_id_enclave \
             deb_libsgx_tdx_logic \
             deb_tdx_qgs deb_tdx_attest
else
.PHONY: deb_libsgx_dcap_default_qpl
deb_libsgx_dcap_default_qpl:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_dcap_default_qpl_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_dcap_ql
deb_libsgx_dcap_ql: deb_libsgx_pce_logic
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_dcap_ql_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-ql/libsgx-dcap-ql*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_sgx_dcap_quote_verify
deb_sgx_dcap_quote_verify:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_dcap_quote_verify_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-quote-verify/libsgx-dcap-quote-verify*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_libsgx_ae_qve
deb_libsgx_ae_qve:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qve.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ae_qve_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-qve/libsgx-ae-qve*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_sgx_pck_id_retrieval_tool_pkg
deb_sgx_pck_id_retrieval_tool_pkg:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_pck_id_retrieval_tool_pkg
	$(CP) external/dcap_source/tools/PCKRetrievalTool/installer/deb/sgx-pck-id-retrieval-tool/sgx-pck-id-retrieval-tool*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_sgx_ra_service_pkg
deb_sgx_ra_service_pkg:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_sgx_ra_service_pkg
	$(CP) external/dcap_source/tools/SGXPlatformRegistration/build/installer/sgx-ra-service*deb ./linux/installer/deb/sgx-aesm-service/
	$(CP) external/dcap_source/tools/SGXPlatformRegistration/build/installer/libsgx-ra-*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_tee_appraisal_tool
deb_tee_appraisal_tool:
	$(MAKE) -C external/dcap_source/QuoteGeneration deb_tee_appraisal_tool_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/deb/tee-appraisal-tool/tee-appraisal-tool*deb ./linux/installer/deb/sgx-aesm-service/

.PHONY: deb_psw_pkg
deb_psw_pkg: deb_libsgx_headers_pkg \
             deb_libsgx_qe3_logic \
             deb_libsgx_pce_logic \
             deb_sgx_aesm_service \
             deb_libsgx_epid \
             deb_libsgx_launch \
             deb_libsgx_quote_ex \
             deb_libsgx_uae_service \
             deb_libsgx_enclave_common \
             deb_libsgx_urts \
             deb_libsgx_ae_qe3 \
             deb_libsgx_ae_id_enclave \
             deb_libsgx_dcap_default_qpl \
             deb_libsgx_dcap_ql \
             deb_libsgx_ae_qve \
             deb_sgx_dcap_quote_verify \
             deb_sgx_pck_id_retrieval_tool_pkg \
             deb_sgx_ra_service_pkg \
             deb_libsgx_ae_tdqe \
             deb_libsgx_tdx_logic \
             deb_tdx_qgs \
             deb_tdx_attest \
             deb_tee_appraisal_tool
endif

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

.PHONY: rpm_libsgx_ae_tdqe
rpm_libsgx_ae_tdqe:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_tdqe.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_ae_tdqe_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-tdqe/libsgx-ae-tdqe*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_libsgx_ae_id_enclave
rpm_libsgx_ae_id_enclave:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_id_enclave.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_ae_id_enclave_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-id-enclave/libsgx-ae-id-enclave*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_libsgx_tdx_logic
rpm_libsgx_tdx_logic:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_tdx_logic_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-tdx-logic/libsgx-tdx-logic*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_tdx_qgs
rpm_tdx_qgs:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_tdx_qgs_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/tdx-qgs/tdx-qgs*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_tdx_attest
rpm_tdx_attest:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_tdx_attest_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libtdx-attest/libtdx-attest*.rpm ./linux/installer/rpm/sgx-aesm-service/

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

.PHONY: rpm_libsgx_headers_pkg
rpm_libsgx_headers_pkg:
	./linux/installer/rpm/libsgx-headers/build.sh

ifeq ($(CC_BELOW_5_2), 1)
.PHONY: rpm_psw_pkg
rpm_psw_pkg: rpm_libsgx_headers_pkg \
             rpm_libsgx_pce_logic \
             rpm_libsgx_qe3_logic \
             rpm_sgx_aesm_service \
             rpm_libsgx_epid \
             rpm_libsgx_launch \
             rpm_libsgx_quote_ex \
             rpm_libsgx_uae_service \
             rpm_libsgx_enclave_common \
             rpm_libsgx_urts \
             rpm_libsgx_ae_qe3 \
             rpm_libsgx_ae_tdqe \
             rpm_libsgx_ae_id_enclave \
             rpm_libsgx_tdx_logic \
             rpm_tdx_qgs \
             rpm_tdx_attest
else
.PHONY: rpm_libsgx_dcap_default_qpl
rpm_libsgx_dcap_default_qpl:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_dcap_default_qpl_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl*.rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_libsgx_dcap_ql
rpm_libsgx_dcap_ql:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_dcap_ql_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-ql/libsgx-dcap-ql*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_libsgx_ae_qve
rpm_libsgx_ae_qve:
ifeq ("$(wildcard ./external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/libsgx_qve.signed.so)", "")
	./external/dcap_source/QuoteGeneration/download_prebuilt.sh
endif
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_ae_qve_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-qve/libsgx-ae-qve*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_sgx_dcap_quote_verify
rpm_sgx_dcap_quote_verify:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_dcap_quote_verify_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-quote-verify/libsgx-dcap-quote-verify*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_sgx_pck_id_retrieval_tool_pkg
rpm_sgx_pck_id_retrieval_tool_pkg:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_pck_id_retrieval_tool_pkg
	$(CP) external/dcap_source/tools/PCKRetrievalTool/installer/rpm/sgx-pck-id-retrieval-tool/sgx-pck-id-retrieval-tool*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_sgx_ra_service_pkg
rpm_sgx_ra_service_pkg:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_sgx_ra_service_pkg
	$(CP) external/dcap_source/tools/SGXPlatformRegistration/build/installer/sgx-ra-service*rpm ./linux/installer/rpm/sgx-aesm-service/
	$(CP) external/dcap_source/tools/SGXPlatformRegistration/build/installer/libsgx-ra-*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_tee_appraisal_tool
rpm_tee_appraisal_tool:
	$(MAKE) -C external/dcap_source/QuoteGeneration rpm_tee_appraisal_tool_pkg
	$(CP) external/dcap_source/QuoteGeneration/installer/linux/rpm/tee-appraisal-tool/tee-appraisal-tool*rpm ./linux/installer/rpm/sgx-aesm-service/

.PHONY: rpm_psw_pkg
rpm_psw_pkg: rpm_libsgx_headers_pkg \
             rpm_libsgx_pce_logic \
             rpm_libsgx_qe3_logic \
             rpm_sgx_aesm_service \
             rpm_libsgx_epid \
             rpm_libsgx_launch \
             rpm_libsgx_quote_ex \
             rpm_libsgx_uae_service \
             rpm_libsgx_enclave_common \
             rpm_libsgx_urts \
             rpm_libsgx_ae_qe3 \
             rpm_libsgx_ae_id_enclave \
             rpm_libsgx_dcap_default_qpl \
             rpm_libsgx_dcap_ql \
             rpm_libsgx_ae_qve \
             rpm_sgx_dcap_quote_verify \
             rpm_sgx_pck_id_retrieval_tool_pkg \
             rpm_sgx_ra_service_pkg \
             rpm_libsgx_ae_tdqe \
             rpm_libsgx_tdx_logic \
             rpm_tdx_qgs \
             rpm_tdx_attest \
             rpm_tee_appraisal_tool
endif

.PHONY: rpm_local_repo
rpm_local_repo: rpm_psw_pkg
	./linux/installer/common/local_repo_builder/local_repo_builder.sh rpm build

clean:
	@$(MAKE) -C sdk/                                    clean
	@$(MAKE) -C psw/                                    clean
	@$(RM)   -r $(ROOT_DIR)/build
	@$(RM)   -r linux/installer/bin/install-sgx-*.bin*.withLicense
	@$(RM)   -r linux/installer/bin/sgx_linux*.bin
	./linux/installer/deb/sgx-aesm-service/clean.sh
	./linux/installer/deb/libsgx-epid/clean.sh
	./linux/installer/deb/libsgx-launch/clean.sh
	./linux/installer/deb/libsgx-quote-ex/clean.sh
	./linux/installer/deb/libsgx-uae-service/clean.sh
	./linux/installer/deb/libsgx-enclave-common/clean.sh
	./linux/installer/deb/libsgx-urts/clean.sh
	./linux/installer/deb/libsgx-headers/clean.sh
	./linux/installer/common/local_repo_builder/local_repo_builder.sh debian clean
	./linux/installer/rpm/sgx-aesm-service/clean.sh
	./linux/installer/rpm/libsgx-epid/clean.sh
	./linux/installer/rpm/libsgx-launch/clean.sh
	./linux/installer/rpm/libsgx-quote-ex/clean.sh
	./linux/installer/rpm/libsgx-uae-service/clean.sh
	./linux/installer/rpm/libsgx-enclave-common/clean.sh
	./linux/installer/rpm/libsgx-urts/clean.sh
	./linux/installer/rpm/libsgx-headers/clean.sh
	./linux/installer/rpm/sdk/clean.sh
	./linux/installer/common/local_repo_builder/local_repo_builder.sh rpm clean
	$(MAKE) -C external/ippcp_internal/ clean
ifeq ("$(shell test -f external/dcap_source/QuoteVerification/dcap_tvl/Makefile && echo TVL Makefile exists)", "TVL Makefile exists")
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=LOAD clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl MITIGATION-CVE-2020-0551=CF clean
	$(MAKE) -C external/dcap_source/QuoteVerification/dcap_tvl clean
endif
ifeq ("$(shell test -f external/dcap_source/QuoteVerification/Makefile && echo Makefile exists)", "Makefile exists")
	@$(MAKE) -C external/dcap_source/QuoteVerification  clean
	@$(MAKE) -C external/dcap_source/QuoteGeneration    clean
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-qve/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-qe3/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-id-enclave/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-ae-tdqe/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-tdx-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libtdx-attest/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/tdx-qgs/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-default-qpl/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-ql/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-pce-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-qe3-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/libsgx-dcap-quote-verify/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/deb/tee-appraisal-tool/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-qve/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-qe3/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-id-enclave/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-ae-tdqe/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-tdx-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libtdx-attest/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/tdx-qgs/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-default-qpl/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-ql/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-pce-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-qe3-logic/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/libsgx-dcap-quote-verify/clean.sh
	./external/dcap_source/QuoteGeneration/installer/linux/rpm/tee-appraisal-tool/clean.sh
endif

rebuild:
	$(MAKE) clean
	$(MAKE) all

.PHONY: distclean
distclean:
	$(MAKE) clean
	# Cleanup
	$(RM) -r 'Intel redistributable binary.txt' Master_EULA_for_Intel_Sw_Development_Products.pdf redist.txt
	$(RM) -rf external/ippcp_internal/inc/*.h external/ippcp_internal/lib/ external/ippcp_internal/license
	$(RM) -rf external/toolset psw/ae/data/prebuilt/lib*.so psw/ae/data/prebuilt/README.md
	$(RM) -rf external/dcap_source/QuoteGeneration/psw/ae/data/prebuilt/
	$(RM) -rf external/dcap_source/QuoteGeneration/'Intel redistributable binary.txt'
	$(RM) -rf external/dcap_source/QuoteVerification/sgxssl/
	git submodule deinit  --all -f
