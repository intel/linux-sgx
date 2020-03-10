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
LINUX_BUILD_DIR=$(readlink -m "${ROOT_DIR}/build/linux")
LINUX_INSTALLER_DIR="${ROOT_DIR}/linux/installer"
LINUX_INSTALLER_COMMON_DIR="${LINUX_INSTALLER_DIR}/common"
LINUX_INSTALLER_COMMON_AESM_SERVICE_DIR="${LINUX_INSTALLER_COMMON_DIR}/sgx-aesm-service"

source ${LINUX_INSTALLER_COMMON_AESM_SERVICE_DIR}/installConfig
DEB_FOLDER=${AESM_SERVICE_PACKAGE_NAME}-${AESM_SERVICE_VERSION}

SGX_VERSION=$(awk '/STRFILEVER/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
DEB_BUILD_FOLDER=${AESM_SERVICE_PACKAGE_NAME}-${SGX_VERSION}

PACKAGE_NAMES[0]=${AESM_SERVICE_PACKAGE_NAME}
PACKAGE_NAMES[1]=${AE_EPID_PACKAGE_NAME}
PACKAGE_NAMES[2]=${AE_LE_PACKAGE_NAME}
PACKAGE_NAMES[3]=${AE_PCE_PACKAGE_NAME}
PACKAGE_NAMES[4]=${AESM_ECDSA_PACKAGE_NAME}
PACKAGE_NAMES[5]=${AESM_EPID_PACKAGE_NAME}
PACKAGE_NAMES[6]=${AESM_LAUNCH_PACKAGE_NAME}
PACKAGE_NAMES[7]=${AESM_PCE_PACKAGE_NAME}
PACKAGE_NAMES[8]=${AESM_QUOTE_EX_PACKAGE_NAME}

main() {
    pre_build
    create_upstream_tarball
    unpack_upstream_tarball
    generate_install
    generate_copyright
    update_version
    update_install_path
    rename_tarball
    build_deb_package
    post_build
}

pre_build() {
    rm -fR ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    cp -fR ${SCRIPT_DIR}/${DEB_FOLDER} ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
}

post_build() {
    rm -fR ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
}

create_upstream_tarball() {
    ${LINUX_INSTALLER_COMMON_AESM_SERVICE_DIR}/createTarball.sh
    cp ${LINUX_INSTALLER_COMMON_AESM_SERVICE_DIR}/output/${TARBALL_NAME} ${SCRIPT_DIR}
}

unpack_upstream_tarball() {
    pushd ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    cp ../${TARBALL_NAME} .
    tar xvf ${TARBALL_NAME}
    rm -f ${TARBALL_NAME}
    popd
}

generate_install() {
    for PACKAGE_NAME in "${PACKAGE_NAMES[@]}"; do
       echo "debian/tmp/${PACKAGE_NAME}/* ." > ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}/debian/${PACKAGE_NAME}.install
    done
}

generate_copyright() {
    pushd ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    rm -f debian/copyright
    find package/licenses/ -type f -print0 | xargs -0 -n1 cat >> debian/copyright
    popd
}

get_os_code() {
    OS_CODE=$(lsb_release -cs 2> /dev/null)
    if [ -z ${OS_CODE} ]; then
        OS_CODE=$(grep "VERSION_CODENAME" /etc/os-release 2> /dev/null | cut -d= -f2)
    fi
    echo ${OS_CODE}
}

update_version() {
    pushd ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    INS_VERSION=$(echo $(dpkg-parsechangelog |grep "Version" | cut -d: -f2))
    DEB_VERSION=$(echo ${INS_VERSION} | cut -d- -f2)

    FULL_VERSION=${SGX_VERSION}-$(get_os_code)${DEB_VERSION}
    sed -i "s/${INS_VERSION}/${FULL_VERSION}/" debian/changelog
    sed -i "s/@dep_version@/${FULL_VERSION}/g" debian/control
    popd
}

update_install_path() {
    pushd ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    sed -i "s#@pkg_path@#${AESM_SERVICE_PACKAGE_PATH}/${AESM_SERVICE_PACKAGE_NAME}#" debian/postinst
    sed -i "s#@pkg_path@#${AESM_SERVICE_PACKAGE_PATH}/${AESM_SERVICE_PACKAGE_NAME}#" debian/prerm
    popd
}

rename_tarball() {
    TARBALL_NAME_NEW_VERSION=$(echo ${TARBALL_NAME} | sed "s/${AESM_SERVICE_VERSION}/${SGX_VERSION}/")
    mv ${SCRIPT_DIR}/${TARBALL_NAME} ${SCRIPT_DIR}/${TARBALL_NAME_NEW_VERSION}
}

build_deb_package() {
    pushd ${SCRIPT_DIR}/${DEB_BUILD_FOLDER}
    SOURCE_DATE_EPOCH="$(date +%s)" LINUX_BUILD_DIR="${LINUX_BUILD_DIR}" dpkg-buildpackage -us -uc
    popd
}

main $@
