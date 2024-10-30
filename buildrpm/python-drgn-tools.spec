# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
Name:           python-drgn-tools
Version:        1.1.1
Release:        1%{?dist}
Summary:        Helper scripts for drgn, containing the corelens utility

License:        UPL
URL:            https://github.com/oracle-samples/drgn-tools
Source0:        drgn-tools-%{version}.tar.bz2

BuildArch:      noarch

BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-pip
BuildRequires:  python%{python3_pkgversion}-wheel

%global python_wheelname drgn_tools-%{version}-py3-none-any.whl

%global _description %{expand:
drgn-tools extends the drgn debugger with scripts & helpers developed by the
Oracle Linux Sustaining team. It provides a program called "corelens" which
allows users to extract diagnostic information from a kernel core dump, or from
a running kernel image (via /proc/kcore).}
%description %{_description}

%package -n     drgn-tools
Summary:        %{summary}
# The drgn dependency can be fulfilled by drgn with, or without, CTF support.
# However, drgn-tools is tied to specific drgn releases.
Requires:       drgn >= 0.0.25, drgn < 0.0.30
%description -n drgn-tools %{_description}

%prep
%autosetup -n drgn-tools-%{version}
echo '__version__ = "%{version}"' > drgn_tools/_version.py
rm -rf drgn_tools/v2/

%build
export DRGN_TOOLS_V2_OMIT=1
%py3_build_wheel


%install
%py3_install_wheel %{python_wheelname}
gzip man/corelens.1
install -m644 -D man/corelens.1.gz %{buildroot}%{_mandir}/man1/corelens.1.gz

# The DRGN script is an interactive CLI which is convenient for developers,
# but should not be part of general users' PATH. If necessary, it can be invoked
# manually with "python3 -m drgn_tools.cli"
rm %{buildroot}/usr/bin/DRGN

%files -n drgn-tools
%license LICENSE.txt
%{python3_sitelib}/drgn_tools-*.dist-info/
%{python3_sitelib}/drgn_tools/*
/usr/bin/corelens
%{_mandir}/man1/corelens.1.gz

%changelog
* Wed Oct 30 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 1.1.1-1
- Fix crash for NULL mutex owner in corelens "lock" module [Orabug: 37186686]
- Fix crash for NULL hc.uuid in dm helper [Orabug: 37170994]
- Handle circular freelists in slabinfo [Orabug: 37170864]
- Fix missing drgn dependency for OL8 [Orabug: 37126783]
- Add support for drgn 0.0.29

* Tue Aug 27 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 1.1.0-1
- Update to 1.1.0

* Mon Apr 22 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 0.9.1-1
- Update to 0.9.1

* Fri Apr 12 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 0.9.0-1
- Update to 0.9.0

* Thu Feb 01 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 0.8.0-1
- Update to 0.8.0

* Wed Dec 20 2023 Stephen Brennan <stephen.s.brennan@oracle.com> - 0.6.0-1
- Initial packaging
