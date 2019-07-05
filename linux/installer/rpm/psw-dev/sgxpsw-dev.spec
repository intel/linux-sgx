Name:           sgxpsw-dev
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) SGX platform software(Intel(R) SGX PSW) for developers
Group:          Development/Libraries

License:        BSD License
URL:            https://github.com/intel/linux-sgx
Source0:        %{name}-%{version}.tar.gz

Requires:       sgxpsw == %{version}-%{release}

%description
Intel(R) SGX platform software(Intel(R) SGX PSW) for developers

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
rm -f %{_specdir}/listfiles
for f in $(find %{?buildroot} -type f -o -type l); do echo $f | sed -e "s#%{?buildroot}##" >> %{_specdir}/listfiles; done

%files -f %{_specdir}/listfiles

%changelog
