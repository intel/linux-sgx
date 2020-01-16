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


CURRENT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) > /dev/null 2>&1 && pwd)
SOURCE_PKG_DIR="${CURRENT_DIR}/.."
LOCAL_REPO_DIR="${SOURCE_PKG_DIR}/sgx_debian_local_repo"
REPO_CONFIG_DIR="${CURRENT_DIR}/conf"

local_repo_clean()
{
    rm -rf ${LOCAL_REPO_DIR}
}

local_repo_build()
{
    local_repo_clean
    code_name=$(lsb_release -cs)
    deb_pkgs=$(find ${SOURCE_PKG_DIR} -type f \( -name "*.deb" -o -name "*.ddeb" \))
    if [[ ${deb_pkgs} != "" ]]
    then
        reprepro --confdir ${REPO_CONFIG_DIR} --outdir ${LOCAL_REPO_DIR} --dbdir ${LOCAL_REPO_DIR}/db --ignore=extension includedeb ${code_name} ${deb_pkgs} 2>/dev/null
    fi
}

