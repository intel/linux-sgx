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


FROM ubuntu:22.04 as sgxbase
RUN apt-get update && apt-get install -y \
    gnupg \
    wget

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update 

FROM sgxbase as sgx_sample_builder
# App build time dependencies
RUN apt-get install -y build-essential

WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.22.100.3.bin
RUN chmod +x sgx_linux_x64_sdk_2.22.100.3.bin
RUN echo 'yes' | ./sgx_linux_x64_sdk_2.22.100.3.bin
WORKDIR /opt/intel/sgxsdk/SampleCode/SampleEnclave
RUN SGX_DEBUG=0 SGX_MODE=HW SGX_PRERELEASE=1 make

FROM sgxbase as sample
RUN apt-get install -y \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev

# No AESM daemon, only AESM client side API support for launch.
# For applications requiring attestation, add libsgx-quote-ex
RUN apt-get install -y --no-install-recommends libsgx-launch libsgx-urts

COPY --from=sgx_sample_builder /opt/intel/sgxsdk/SampleCode/SampleEnclave/app .
COPY --from=sgx_sample_builder /opt/intel/sgxsdk/SampleCode/SampleEnclave/enclave.signed.so .

RUN adduser -q --disabled-password --gecos "" --no-create-home sgxuser
USER sgxuser
CMD ./app

FROM sgxbase as aesm 
RUN apt-get install -y \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    make

# More aesm plugins, e.g libsgx-aesm-quote-ex-plugin, are needed if application requires attestation. See installation guide.
RUN apt-get install -y libsgx-aesm-launch-plugin

WORKDIR /opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon

