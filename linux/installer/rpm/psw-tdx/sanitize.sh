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

tarball="linux-sgx"
psw_tdx="psw-tdx"

cur_dir=$(dirname "$0")
root_dir="${cur_dir}/../../../../"
common_dir="${root_dir}/linux/installer/common"
common_psw_tdx_dir="${common_dir}/${psw_tdx}"
tarball_dir="${cur_dir}/${tarball}"

make -C ${root_dir} preparation

# Prepare ipp-crypto source
pushd ${root_dir}/external/ippcp_internal/
cd ipp-crypto && git apply ../0001-IPP-crypto-for-SGX_psw_dcap.patch >/dev/null 2>&1 ||  git apply ../0001-IPP-crypto-for-SGX_psw_dcap.patch --check -R
popd

python ${common_dir}/gen_source/copy_source.py                          \
      --bom-file ${common_psw_tdx_dir}/BOM_source/psw-tdx-tarball.txt \
      --src-path ${root_dir}                                            \
      --dst-path ${tarball_dir}                                         \
      --cleanup

tar -zcvf ${tarball}.tar.gz -C ${cur_dir} ${tarball}
rm -fr ${tarball_dir}
