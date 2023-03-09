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

# The script is to automatically prepare the reproducible code, build docker image and launch the build
# in the docker container.
#
# Usage:
#     ./build_and_launch_docker.sh [ [ -d | --code-dir dir ] [ -t | --reproduce-type type ] | [ -i | --sdk-installer installer ] | [ -s | --sgx-src-dir src_dir ] [ -h | --help ] ]
#
# Options:
#     -d, --code-dir:
#         Specify the directory you want to download the repo. If this option is
#         not specified, will use the same directory as the script location.
#
#     -t, --reproduce-type:
#         Specify the reproducibility type. Provided options: all|sdk|ae|ipp.
#         If one type is provided, the corresponding code will be prepared. And the correponding
#         build steps will also be launched in the container automatically.
#         If no type is provided, all the code will be prepared. And the build steps will
#         be triggered in the container. Then you can choose to build what you want in the container.
#
#    -i, --sdk-installer:
#         Specify the SDK installer used for AE reproducibility. If this option is not specified,
#         script will download the default SDK installer.
#
#    -s, --sgx-src-dir:
#         Specify the local sgx source path if you have pulled the sgx source code via `$git clone`
#         or by other ways.
#         If this option is specified, script will not clone sgx source but start the build based on
#         the code base specified by this option.
#
#     -h, --help:
#         Show this usage message.
#
#

set -e

script_dir="$( cd "$( dirname "$0" )" >> /dev/null 2>&1 && pwd )"
code_dir="$script_dir/code_dir"
sgx_repo="$code_dir/sgx"
type="all"
type_flag=0
mount_dir="/linux-sgx"

sdk_installer=""
sgx_src=""

default_sdk_installer=sgx_linux_x64_sdk_reproducible_2.19.100.1.bin
default_sdk_installer_url=https://download.01.org/intel-sgx/sgx-linux/2.19/distro/nix_reproducibility/$default_sdk_installer


usage()
{
    echo "
    The script is to automatically prepare the reproducible code, build docker image and launch the build
    in the docker container.

    Usage:
        $0 [ [ -d | --code-dir dir ] [ -t | --reproduce-type type ] | [ -i | --sdk-installer installer ] | [ -s | --sgx-src-dir src_dir ] [ -h | --help ] ]

    Options:
        -d, --code-dir:
            Specify the directory you want to prepare the code and share to the reproducible container.
            If this option is not specified, will use the same directory as the script location.
        -t, --reproduce-type:
            Specify the reproducibility type. Provided options: all|sdk|ae|ipp.
            If one type is provided, the corresponding code will be prepared. And the correponding
            build steps will also be executed in the container automatically.
            If no type is provided, all the code will be prepared. And the build steps will not
            be triggered in the container. Then you can choose to build what you want in the container.
        -i, --sdk-installer:
            Specify the SDK installer used for AE reproducibility.
            If this option is not provided, script will choose the default SDK installer to build AEs.
            Only valid when the reproduce type is 'ae'.
        -s, --sgx-src-dir:
            Specify the local sgx source path if you have pulled the sgx source code via \`\$git clone\`
            or by other ways.
            If this option is specified, script will not clone sgx source but start the build based on
            the code base specified by this option.
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
                if [ "$type" != "all" ] && [ "$type" != "sdk" ] && [ "$type" != "ae" ] && [ "$type" != "ipp" ]; then
                    usage
                    exit 1
                fi
                ;;
            -h | --help )
                usage
                exit
                ;;
             -i | --sdk-installer ) shift
                sdk_installer="$1"
                if [ ! -f "$sdk_installer" ]; then
                    echo "The $sdk_installer doesn't exist."
                    usage
                    exit 1
                fi
                sdk_installer="$(realpath $sdk_installer)"
                ;;
            -s | --sgx-src-dir) shift
                sgx_src="$1"
                if [ ! -d "$sgx_src" ]; then
                    echo "The $sgx_src doesn't exist."
                    usage
                    exit 1
                fi
                sgx_src="$(realpath $sgx_src)"
                ;;
            * )
                usage
                exit 1
        esac
        shift
    done
    if [ "$type" != "ae" ] && [ $type_flag == 1 ] && [ "$sdk_installer" != "" ]; then
        echo -e "\n   ERROR: Option '--sdk-installer' is valid only if '--reproduce-type' is 'ae'."
        usage
        exit 1
    fi
    mkdir -p "$code_dir" | exit
    code_dir="$(realpath $code_dir)"
    sgx_repo="$code_dir/sgx"
}

prepare_sgx_src()
{
    pushd .
    if [ -d $sgx_repo ]; then
        echo "Removing existing SGX code repo in $sgx_repo"
        rm -rf $sgx_repo
    fi

    # If user prepares the sgx code repo in the host machine, copy the code to $sgx_repo
    # Otherwise, pull the sgx source code.
    if [ "$sgx_src" != "" ]; then
        mkdir -p "$sgx_repo" && cp -a "$sgx_src/." "$sgx_repo"
    else
        git clone -b sgx_2.19_reproducible https://github.com/intel/linux-sgx.git $sgx_repo
    fi

    cd "$sgx_repo" && make preparation
    popd

}

prepare_ipp_src()
{
    pushd .
    ipp_dir="$sgx_repo/external/ippcp_internal"
    
    # Apply the patch
    cd $ipp_dir/ipp-crypto
    git apply ../0001-IPP-crypto-for-SGX.patch > /dev/null 2>&1 ||  git apply ../0001-IPP-crypto-for-SGX.patch --check -R
    popd
}


prepare_sdk_installer()
{
    # Used for 'ae' type repreducibility.
    # If user prepares the sdk installer, we copy it to the right place
    # Otherwise, we download one from 01.org
    if [ "$sdk_installer" != "" ]; then
        chmod +x "$sdk_installer" && cp "$sdk_installer" "$code_dir"
    else
        cd $code_dir && wget $default_sdk_installer_url && chmod +x $default_sdk_installer && cd -
    fi
}

generate_cmd_script()
{
    rm -f $code_dir/cmd.sh

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
    "all")
        prepare_sgx_src
        prepare_ipp_src
        ;;
    "sdk")
        prepare_sgx_src
        ;;
    "ae")
        prepare_sgx_src
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

# Allow 'w' permission for other users to the code_dir in case the uid in the container
# is different from the host uid.
chmod -R o+w $code_dir

if [ $type_flag = 0 ]; then
    docker run -v $code_dir:$mount_dir -it --network none --rm sgx.build.env
else
    docker run -v $code_dir:$mount_dir -it --network none --rm sgx.build.env /bin/bash -c $mount_dir/cmd.sh
fi



