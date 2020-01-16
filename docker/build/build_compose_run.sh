#!/bin/sh
#
# Copyright (C) 2020 Intel Corporation. All rights reserved.
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

set -e
docker build  --target aesm --build-arg https_proxy=$https_proxy \
              --build-arg http_proxy=$http_proxy -t sgx_aesm -f ./Dockerfile ../../

docker build --target sample --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t sgx_sample -f ./Dockerfile ../../

# Create a temporary directory on the host that is mounted
# into both the AESM and sample containers at /var/run/aesmd
# so that the AESM socket is visible to the sample container
# in the expected location. It is critical that /tmp/aesmd is
# world writable as the UIDs may shift in the container.

mkdir -p -m 777 /tmp/aesmd
chmod -R -f 777 /tmp/aesmd || sudo chmod -R -f 777 /tmp/aesmd || true
docker-compose --verbose up
