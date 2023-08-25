# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023 IBM Corp.
Name:		secvarctl
Version:        1.0
Release:        1%{?dist}
Summary:        PowerPC secure variable control
BuildArch:      ppc64le ppcl64 x86_64

Group:          None
License:        Apache 2.0
URL:            https://github.com/open-power/secvarctl
Source0:        https://github.com/open-power/secvarctl/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires: cmake openssl-devel
Requires: openssl

%description
%{name} facilitates manipulation of PowerPC authenticated variables from
userspace via sysfs.  The primary use case is management of secure boot
variables.

%global debug_package %{nil}

%prep
%setup -q
%cmake

%build
%cmake_build

%install
%cmake_install
  
%files
%defattr(-,root,root)
%license LICENSE
%doc README.md
%{_mandir}/man1/%{name}.1.gz
%attr(0755,root,root) %{_bindir}/%{name}

