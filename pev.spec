Name:           pev
Version:        0.81
Release:        1
License:        GPL2
URL:            http://pev.sf.net/
Requires:       readline
BuildRequires:  openssl-devel
Source0:        https://github.com/merces/pev/archive/v%{version}.tar.gz
Summary:        The PE file analysis toolkit

%description
pev the PE file analysis toolkit. It is fast, multiplatform, feature-rich, free and open source

%prep
%setup -n pev

%build
make

%install
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
/usr/bin/*
/usr/lib/*
