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

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR="${SCRIPT_DIR}/../../../../"
LINUX_INSTALLER_DIR="${ROOT_DIR}/linux/installer"
LINUX_INSTALLER_COMMON_DIR="${LINUX_INSTALLER_DIR}/common"

INSTALL_PATH=${SCRIPT_DIR}/output

# Cleanup
rm -fr ${INSTALL_PATH}

# Get the configuration for this package
source ${SCRIPT_DIR}/installConfig

# Fetch the gen_source script
cp ${LINUX_INSTALLER_COMMON_DIR}/gen_source/gen_source.py ${SCRIPT_DIR}

# Copy the files according to the BOM
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-ae-epid.txt --installdir=pkgroot/libsgx-ae-epid
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-ae-le.txt --cleanup=false --installdir=pkgroot/libsgx-ae-le
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-ae-pce.txt --cleanup=false --installdir=pkgroot/libsgx-ae-pce
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-aesm-ecdsa-plugin.txt --cleanup=false --installdir=pkgroot/libsgx-aesm-ecdsa-plugin
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-aesm-epid-plugin.txt --cleanup=false --installdir=pkgroot/libsgx-aesm-epid-plugin
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-aesm-launch-plugin.txt --cleanup=false --installdir=pkgroot/libsgx-aesm-launch-plugin
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-aesm-pce-plugin.txt --cleanup=false --installdir=pkgroot/libsgx-aesm-pce-plugin
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/libsgx-aesm-quote-ex-plugin.txt --cleanup=false --installdir=pkgroot/libsgx-aesm-quote-ex-plugin
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sgx-aesm-service.txt --cleanup=false --installdir=pkgroot/sgx-aesm-service
python ${SCRIPT_DIR}/gen_source.py --bom=BOMs/sgx-aesm-service-package.txt --cleanup=false
python ${SCRIPT_DIR}/gen_source.py --bom=../licenses/BOM_license.txt --cleanup=false

# Create the tarball
QE_VERSION=$(awk '/QE_VERSION/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
PVE_VERSION=$(awk '/PVE_VERSION/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
LE_VERSION=$(awk '/LE_VERSION/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
PCE_VERSION=$(awk '/PCE_VERSION/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
URTS_VERSION=$(awk '/URTS_VERSION/ {print $3}' ${ROOT_DIR}/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
QE3_VERSION=$(awk '/QE3_VERSION/ {print $3}' ${ROOT_DIR}/external/dcap_source/QuoteGeneration/common/inc/internal/se_version.h|sed 's/^\"\(.*\)\"$/\1/')
pushd ${INSTALL_PATH} &> /dev/null
sed -i "s/QE_VER=.*/QE_VER=${QE_VERSION}/" Makefile
sed -i "s/PVE_VER=.*/PVE_VER=${PVE_VERSION}/" Makefile
sed -i "s/LE_VER=.*/LE_VER=${LE_VERSION}/" Makefile
sed -i "s/PCE_VER=.*/PCE_VER=${PCE_VERSION}/" Makefile
sed -i "s/URTS_VER=.*/URTS_VER=${URTS_VERSION}/" Makefile
sed -i "s/QE3_VER=.*/QE3_VER=${QE3_VERSION}/" Makefile
tar -zcvf ${TARBALL_NAME} *
popd &> /dev/null
