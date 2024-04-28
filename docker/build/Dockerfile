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


FROM ubuntu:22.04 as builder

RUN apt-get update && apt-get install  -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    debhelper \
    git \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    lsb-release \
    ocaml \
    ocamlbuild \
    protobuf-compiler \
    python-is-python3 \
    reprepro \
    wget \
    perl \
    unzip \
    pkgconf \
    libboost-dev \
    libboost-system-dev \
    libboost-thread-dev \
    lsb-release \
    libsystemd0
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# We assume this docker file is invoked with root at the top of linux-sgx repo, see shell scripts for example.
WORKDIR /linux-sgx
COPY . .

RUN make sdk_install_pkg_no_mitigation

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

ENV SGX_SDK=/opt/intel/sgxsdk
WORKDIR /linux-sgx
RUN make psw_install_pkg

ENV BUILD_PLATFORM="docker"
RUN make deb_local_repo

FROM ubuntu:22.04 as aesm
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon

FROM ubuntu:22.04 as aesm_deb
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

WORKDIR /deb_local_repo

COPY --from=builder /linux-sgx/linux/installer/deb/sgx_debian_local_repo/ ./
RUN echo "deb [trusted=yes arch=amd64] file:///deb_local_repo jammy main">>/etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y libsgx-aesm-launch-plugin libsgx-aesm-quote-ex-plugin

WORKDIR /opt/intel/sgx-aesm-service/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon


FROM ubuntu:22.04 as sample
RUN apt-get update && apt-get install -y \
    g++ \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser
USER sgxuser

CMD ./app


FROM ubuntu:22.04 as sample_deb
RUN apt-get update && apt-get install -y \
    g++ \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

WORKDIR /deb_local_repo

COPY --from=builder /linux-sgx/linux/installer/deb/sgx_debian_local_repo/ ./
RUN echo "deb [trusted=yes arch=amd64] file:///deb_local_repo jammy main">>/etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y libsgx-urts

WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser
USER sgxuser

CMD ./app
