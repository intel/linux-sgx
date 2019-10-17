#!/usr/bin/env bash
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


set -e

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="${SCRIPT_DIR}/../../../../"
LINUX_INSTALLER_DIR="${ROOT_DIR}/linux/installer"
LINUX_INSTALLER_COMMON_DIR="${LINUX_INSTALLER_DIR}/common"
LINUX_INSTALLER_COMMON_ECL_DIR="${LINUX_INSTALLER_COMMON_DIR}/libsgx-enclave-common"
LINUX_OS_ID=$(grep "^ID=" /usr/lib/os-release 2> /dev/null | awk -F'=' '{print $2}')

source ${LINUX_INSTALLER_COMMON_ECL_DIR}/installConfig.x64
SGX_PKG_PATH=${ECL_PKG_PATH}
if [ "${LINUX_OS_ID}" = "clear-linux-os" ]; then
    SGX_PKG_PATH=/usr/share
fi

SGX_VERSION=$(awk '/STRFILEVER/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
PSW_PKG_NAME=sgxpsw
RPM_BUILD_FOLDER=${PSW_PKG_NAME}-${SGX_VERSION}

main() {
    pre_build
    update_spec
    create_upstream_tarball
    build_rpm_package
    post_build
}

pre_build() {
    rm -fR ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}
    mkdir -p ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp -f ${SCRIPT_DIR}/${PSW_PKG_NAME}.spec ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}/SPECS
}

post_build() {
    for FILE in $(find ${SCRIPT_DIR}/${RPM_BUILD_FOLDER} -name "*.rpm" 2> /dev/null); do
        cp "${FILE}" ${SCRIPT_DIR}
    done
    rm -fR ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}
}

update_spec() {
    pushd ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}
    sed -i "s#@version@#${SGX_VERSION}#" SPECS/${PSW_PKG_NAME}.spec
    sed -i "s#@install_path@#${SGX_PKG_PATH}/${PSW_PKG_NAME}#" SPECS/${PSW_PKG_NAME}.spec
    popd
}

create_upstream_tarball() {
    ${LINUX_INSTALLER_COMMON_ECL_DIR}/createTarball.sh
    tar -xvf ${LINUX_INSTALLER_COMMON_ECL_DIR}/output/${TARBALL_NAME} -C ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}/SOURCES
    pushd ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}/SOURCES
    # change the install path to /usr/share instead of /opt/intel
    # change the package name to sgxpsw
    sed -i "s#\(ECL_PKG_NAME=\).*#\1${PSW_PKG_NAME}#" scripts/installConfig
    sed -i "s#\(ECL_PKG_PATH=\).*#\1${SGX_PKG_PATH}#" scripts/installConfig
    tar -zcvf ${RPM_BUILD_FOLDER}$(echo ${TARBALL_NAME}|awk -F'.' '{print "."$(NF-1)"."$(NF)}') *
    popd
}

build_rpm_package() {
    pushd ${SCRIPT_DIR}/${RPM_BUILD_FOLDER}
    rpmbuild --define="_topdir `pwd`" -ba SPECS/${PSW_PKG_NAME}.spec
    popd
}

main $@
