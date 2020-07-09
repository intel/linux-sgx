#!/usr/bin/env bash
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

# The script is to automatically prepare the reproducible code, build docker image and launch the build
# in the docker container.
#
# Usage:
#     ./build_and_launch_docker.sh [ [ -d | --code-dir dir ] [ -t | --reproduce-type type ] | [ -h | --help ] ]
#
# Options:
#     -d, --code-dir:
#         Specify the directory you want to download the repo. If this option is
#         not specified, will use the same directory as the script location.
#
#     -t, --reproduce-type:
#         Specify the reproducibility type. Provided options: all|sdk|ae|ipp|binutils.
#         If one type is provided, the corresponding code will be prepared. And the correponding
#         build steps will also be launched in the container automatically.
#         If no type is provided, all the code will be prepared. And the build steps will
#         be triggered in the container. Then you can choose to build what you want in the container.
#
#     -h, --help:
#         Show this usage message.#
#

set -e

script_dir="$( cd "$( dirname "$0" )" >> /dev/null 2>&1 && pwd )"
code_dir="$script_dir/code_dir"
sgx_repo="$code_dir/sgx"
binutils_repo="$code_dir/binutils"
type="all"
type_flag=0
mount_dir="/linux-sgx"

usage()
{
    echo "
    The script is to automatically prepare the reproducible code, build docker image and launch the build
    in the docker container.

    Usage:
        $0 [ [ -d | --code-dir dir ] [ -t | --reproduce-type type ] | [ -h | --help ] ]

    Options:
        -d, --code-dir:
            Specify the directory you want to download the repo. If this option is
            not specified, will use the same directory as the script location.

        -t, --reproduce-type:
            Specify the reproducibility type. Provided options: all|sdk|ae|ipp|binutils.
            If one type is provided, the corresponding code will be prepared. And the correponding
            build steps will also be executed in the container automatically.
            If no type is provided, all the code will be prepared. And the build steps will not
            be triggered in the container. Then you can choose to build what you want in the container.

        -h, --help:
            Show this usage message."
}

parse_cmd()
{
    while [ "$1" != "" ]; do
        case $1 in
            -d | --code-dir ) shift
                code_dir="$1"
                ;;
            -t | --reproduce-type ) shift
                type="$1"
                type_flag=1
                if [ "$type" != "all" ] && [ "$type" != "sdk" ] && [ "$type" != "ae" ] && [ "$type" != "ipp" ]  && [ "$type" != "binutils" ]; then
                    usage
                    exit 1
                fi
                ;;
            -h | --help )
                usage
                exit
                ;;
            * )
                usage
                exit 1
        esac
        shift
    done
    mkdir -p "$code_dir" | exit
    code_dir="$(realpath $code_dir)"
    sgx_repo="$code_dir/sgx"
    binutils_repo="$code_dir/binutils"
}

prepare_sgx_src()
{
    if [ -d $sgx_repo ]; then
        echo "Removing existing SGX code repo in $sgx_repo"
        rm -rf $sgx_repo
    fi

    git clone https://github.com/intel/linux-sgx.git $sgx_repo
    cd $sgx_repo && ./download_prebuilt.sh && cd -
}

prepare_dcap_src()
{
    if [ ! -f $sgx_repo/Makefile ]; then
        echo "Please download the source repo firstly."
        exit -1
    fi
    cd ${sgx_repo} && make dcap_source && cd -
    $sgx_repo/external/dcap_source/QuoteVerification/prepare_sgxssl.sh nobuild
}

prepare_openmp_src()
{
    openmp_dir="$sgx_repo/external/openmp/"
    if [ ! -d $openmp_dir/openmp_code/final ]; then
        cd $openmp_dir && git clone -b svn-tags/RELEASE_801 https://github.com/llvm-mirror/openmp.git --depth 1 openmp_code && cd -
    fi
    if [ ! -f $openmp_dir/openmp_code/final/runtime/src/sgx_stub.h ]; then
        cd $openmp_dir/openmp_code && git apply ../0001-Enable-OpenMP-in-SGX.patch && cd -
    fi
}

prepare_ipp_src()
{
    pushd .
    ipp_dir="$sgx_repo/external/ippcp_internal"
    if [ ! -d $ipp_dir/ipp-crypto ]; then
        git clone -b ipp-crypto_2019_update5  https://github.com/intel/ipp-crypto.git --depth 1 $ipp_dir/ipp-crypto
    fi

    patch_log="$( cd $ipp_dir/ipp-crypto && git log --oneline --grep='Add mitigation support to assembly code' | cut -d' ' -f 3)"

    if [  "$patch_log" != "mitigation" ]; then
        cd $ipp_dir/ipp-crypto && git am ../0001-Add-mitigation-support-to-assembly-code.patch
    fi
    popd
}

prepare_binutils_src()
{
    if [ -d $binutils_repo ]; then
        echo "Removing existing repo $binutils_repo"
        rm -rf $binutils_repo
    fi

    git clone https://github.com/bminor/binutils-gdb.git $binutils_repo
    #git clone https://sourceware.org/git/binutils-gdb.git $binutils_repo
    cd $binutils_repo && git checkout a09f656b267b9a684f038fba7cadfe98e2f18892 && cd -
}


prepare_sdk_installer()
{
    # Used for 'ae' type repreducibility.
    sdk_installer=sgx_linux_x64_sdk_2.10.100.2.bin
    sdk_url=https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/$sdk_installer
    cd $code_dir && wget $sdk_url && chmod +x $sdk_installer && cd -
}

generate_cmd_script()
{
    rm -rf $code_dir/cmd.sh

    cat > $code_dir/cmd.sh << EOF
#!/usr/bin/env bash

. ~/.bash_profile
nix-shell ~/shell.nix --run "$mount_dir/start_build.sh $type"

EOF

    chmod +x $code_dir/cmd.sh
}

######################################################
# Step 1: Parse command line, prepare code and scripts
######################################################
parse_cmd $@

case $type in
    "binutils")
        prepare_binutils_src
        ;;
    "all")
        prepare_binutils_src
        prepare_sgx_src
        prepare_dcap_src
        prepare_openmp_src
        prepare_ipp_src
        ;;
    "sdk")
        prepare_sgx_src
        prepare_dcap_src
        prepare_openmp_src
        ;;
    "ae")
        prepare_sgx_src
        prepare_dcap_src
        prepare_sdk_installer
        ;;
    "ipp")
        prepare_sgx_src
        prepare_ipp_src
        ;;
    *)
        echo "Unsupported reproducibility type."
        exit 1
esac

cp $script_dir/start_build.sh.tmp $code_dir/start_build.sh
chmod +x $code_dir/start_build.sh
generate_cmd_script

######################################################
# Step 2: Build docker image and launch the container
######################################################
# Check if the image already exists. If not, build the docker image
set +e && docker image inspect sgx.build.env:latest > /dev/null 2>&1 && set -e
if [ $? != 0 ]; then
    docker build -t sgx.build.env --build-arg https_proxy=$https_proxy \
              --build-arg http_proxy=$http_proxy -f $script_dir/Dockerfile .
fi

if [ $type_flag = 0 ]; then
    docker run -v $code_dir:$mount_dir -it --network none --rm sgx.build.env
else
    docker run -v $code_dir:$mount_dir -it --network none --rm sgx.build.env /bin/bash -c $mount_dir/cmd.sh
fi



