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

%define _unpackaged_files_terminate_build 0
%define _install_path @install_path@
%define _helper_command @helper_command@

Name:           sgxsdk
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) SGX SDK
Group:          Development/Libraries

License:        BSD License
URL:            https://github.com/intel/linux-sgx
Source0:        %{name}-%{version}.tar.gz

%if 0%{?rhel} > 0 || 0%{?fedora} > 0 || 0%{?centos} > 0
Requires:       python 
%endif

%if 0%{?suse_version} > 0
Requires:       devel_basis python 
%endif

Requires:       sgxpsw-debuginfo == %{version}-%{release}

%description
Intel(R) SGX SDK

%debug_package

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
rm -f %{_specdir}/listfiles
for f in $(find %{?buildroot} -type f -o -type l); do lf=$(echo $f | sed -e "s#%{?buildroot}##"); [[ $lf = %{_install_path}* ]] || echo $lf >> %{_specdir}/listfiles; done
%{_helper_command}

%files -f %{_specdir}/listfiles
%{_install_path}

%changelog
