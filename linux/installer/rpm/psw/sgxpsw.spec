Name:           sgxpsw
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) SGX platform software(Intel(R) SGX PSW) 
Group:          Development/Libraries

License:        BSD License
URL:            https://github.com/intel/linux-sgx
Source0:        %{name}-%{version}.tar.gz

%if 0%{?rhel} > 0 || 0%{?fedora} > 0 || 0%{?centos} > 0
Requires:       openssl-devel libcurl-devel protobuf-devel
%endif

%if 0%{?suse_version} > 0
Requires:       libopenssl-devel libcurl-devel protobuf-devel
%endif

%description
Intel(R) SGX platform software(Intel(R) SGX PSW)

%debug_package

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
rm -f %{_specdir}/listfiles
for f in $(find %{?buildroot} -type f -o -type l); do echo $f | sed -e "s#%{?buildroot}##" >> %{_specdir}/listfiles; done

%files -f %{_specdir}/listfiles

%post
if [ -x /opt/intel/sgxpsw/scripts/install.sh ]; then /opt/intel/sgxpsw/scripts/install.sh; fi

%postun
if [ -x /opt/intel/sgxpsw/cleanup.sh ]; then /opt/intel/sgxpsw/cleanup.sh; fi


%changelog
