#!/usr/bin/env bash
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


set -e

psw_dcap="psw-dcap"

cur_dir=$(dirname "$0")
root_dir="${cur_dir}/../../../../"
dcap_dir="${root_dir}/external/dcap_source"
common_dir="${root_dir}/linux/installer/common"
common_psw_dcap_dir="${common_dir}/${psw_dcap}"

psw_version=$(awk '/STRFILEVER/ {print substr($3, 2, length($3) - 2);}' \
            ${root_dir}/common/inc/internal/se_version.h)
rpm_build_dir=${psw_dcap}-${psw_version}

source ${common_psw_dcap_dir}/installConfig

pre_build() {
    rm -fr ${cur_dir}/${rpm_build_dir}
    mkdir -p ${cur_dir}/${rpm_build_dir}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
}

update_spec() {
    local min_version="4.12"
    local rpm_version=$(rpmbuild --version 2> /dev/null | awk '{print $NF}')
    local cur_version=$(echo -e "${rpm_version}\n${min_version}" | sort -V | head -n 1)
    local dcap_version=$(awk '/STRFILEVER/ {print substr($3, 2, length($3) - 2);}' \
                       ${dcap_dir}/QuoteGeneration/common/inc/internal/se_version.h)

    sed -e "s:@psw_version@:${psw_version}:"                                                      \
        -e "s:@dcap_version@:${dcap_version}:"                                                    \
        -e "s:@aesm_service_path@:${SGX_INSTALL_PATH}/${AESM_SERVICE_PACKAGE}:"                   \
        -e "s:@ra_service_path@:${SGX_INSTALL_PATH}/${RA_SERVICE_PACKAGE}:"                       \
        -e "s:@dcap_pccs_path@:${SGX_INSTALL_PATH}/${DCAP_PCCS_PACKAGE}:"                         \
        -e "s:@pck_id_retrieval_tool_path@:${SGX_INSTALL_PATH}/${PCK_ID_RETRIEVAL_TOOL_PACKAGE}:" \
        ${cur_dir}/${psw_dcap}.spec.tmpl > ${cur_dir}/${rpm_build_dir}/SPECS/${psw_dcap}.spec

    if [ "${min_version}" != "${cur_version}" ]; then
        sed -i "s/^Recommends:/Requires:  /" ${cur_dir}/${rpm_build_dir}/SPECS/${psw_dcap}.spec
    fi
}

create_upstream_tarball() {
    tar -zcvf ${cur_dir}/${rpm_build_dir}/SOURCES/${psw_dcap}-${psw_version}.tar.gz \
        --exclude=$(realpath --relative-to=${root_dir} ${cur_dir})                  \
	--directory=${root_dir} $(ls ${root_dir})
}

build_package() {
    pushd ${cur_dir}/${rpm_build_dir} &> /dev/null
    rpmbuild --define="_topdir `pwd`" -ba SPECS/${psw_dcap}.spec
    popd &> /dev/null
}

post_build() {
    cp -f ${cur_dir}/${rpm_build_dir}/RPMS/**/*.rpm ${cur_dir}
    cp -f ${cur_dir}/${rpm_build_dir}/SRPMS/*.rpm ${cur_dir}
    cp -f ${cur_dir}/${rpm_build_dir}/SOURCES/*.tar.gz ${cur_dir}
    cp -f ${cur_dir}/${rpm_build_dir}/SPECS/${psw_dcap}.spec ${cur_dir}/${psw_dcap}.spec.in
    rm -fr ${cur_dir}/${rpm_build_dir}
}

main() {
    pre_build
    update_spec
    create_upstream_tarball
    build_package
    post_build
}

main $@
