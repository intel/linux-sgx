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


FROM quay.io/centos/centos:stream8 as qgs-builder

RUN dnf -y groupinstall 'Development Tools'
RUN dnf -y install --enablerepo=powertools ocaml ocaml-ocamlbuild wget python2 \
        openssl-devel libcurl-devel protobuf-devel cmake createrepo yum-utils \
        dos2unix pkgconf boost-devel protobuf-c-compiler protobuf-c-devel \
        protobuf-lite-devel

# We assume this docker file is invoked with root at the top of linux-sgx repo, see shell scripts for example.
WORKDIR /linux-sgx
COPY . .
RUN alternatives --set python /usr/bin/python2
RUN make sdk_install_pkg_no_mitigation

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make rpm_local_repo


FROM quay.io/centos/centos:stream8 as qgs

WORKDIR /installer

COPY --from=qgs-builder /linux-sgx/linux/installer/rpm/sgx_rpm_local_repo/ .
RUN dnf config-manager --add-repo file:///installer
RUN dnf -y install --setopt=install_weak_deps=False --nogpgcheck tdx-qgs \
    libsgx-dcap-default-qpl
RUN mkdir -p /var/run/tdx-qgs/
RUN sed -i "s/localhost:8081/host.docker.internal:8081/" /etc/sgx_default_qcnl.conf && \
    sed -i 's/"use_secure_cert": true/"use_secure_cert": false/' /etc/sgx_default_qcnl.conf && \
    sed -i "s/port = 4050//" /etc/qgs.conf


WORKDIR /opt/intel/tdx-qgs
CMD ./qgs --no-daemon
