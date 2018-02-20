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


FROM ubuntu:18.04 as builder

RUN apt-get update --fix-missing
RUN apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev 
RUN apt-get install -y git libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake lsb-release

# We assume this docker file is invoked with root at the top of linux-sgx repo, see shell scripts for example.
WORKDIR /linux-sgx
COPY . .

RUN ./download_prebuilt.sh

RUN make sdk_install_pkg

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make psw_install_pkg


FROM ubuntu:18.04 as aesm 
RUN apt-get update && \ 
    apt-get install -y libssl1.1 libcurl4 libprotobuf10 module-init-tools make
 
WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
USER aesmd
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


FROM ubuntu:18.04 as sample
RUN apt-get update && \
    apt-get install -y g++ \
                       libcurl4-openssl-dev \
                       libprotobuf-dev \
                       libssl-dev \
                       make \
                       module-init-tools
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

CMD ./app

