# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
%if 0%{?rhel} == 8 || 0%{?rhel} == 9
%global with_python311 1
%global with_python312 1
%else
%global with_python311 0
%global with_python312 0
%endif

%if %{with_python311}
%global __python311 /usr/bin/python3.11
%global python311_sitelib /usr/lib/python3.11/site-packages
%endif

%if %{with_python312}
%global __python312 /usr/bin/python3.12
%global python312_sitelib /usr/lib/python3.12/site-packages
%endif


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
%if %{with_python311}
BuildRequires:  python3.11-devel
BuildRequires:  python3.11-setuptools
BuildRequires:  python3.11-pip
BuildRequires:  python3.11-wheel
%endif
%if %{with_python312}
BuildRequires:  python3.12-devel
BuildRequires:  python3.12-setuptools
BuildRequires:  python3.12-pip
BuildRequires:  python3.12-wheel
%endif

%global platform_python %{__python3}

%global _description %{expand:
drgn-tools extends the drgn debugger with scripts & helpers developed by the
Oracle Linux Sustaining team. It provides a program called "corelens" which
allows users to extract diagnostic information from a kernel core dump, or from
a running kernel image (via /proc/kcore).}
%description %{_description}

# The drgn dependency can be fulfilled by drgn with, or without, CTF support.
# However, drgn-tools is tied to specific drgn releases.
%global drgn_min 0.0.25
%global drgn_max 0.0.31

%package -n     drgn-tools
Summary:        %{summary}
Requires:       drgn >= %{drgn_min}, drgn < %{drgn_max}
%description -n drgn-tools %{_description}

%if %{with_python311}
%package -n     python3.11-drgn-tools
Summary:        %{summary}
Requires:       python3.11-drgn >= %{drgn_min}, python3.11-drgn < %{drgn_max}
%description -n python3.11-drgn-tools %{_description}
%endif

%if %{with_python312}
%package -n     python3.12-drgn-tools
Summary:        %{summary}
Requires:       python3.12-drgn >= %{drgn_min}, python3.12-drgn < %{drgn_max}
%description -n python3.12-drgn-tools %{_description}
%endif

%prep
%autosetup -n drgn-tools-%{version}
echo '__version__ = "%{version}"' > drgn_tools/_version.py
rm -rf drgn_tools/v2/

%build
export DRGN_TOOLS_V2_OMIT=1
%py3_build


%install
export DRGN_TOOLS_V2_OMIT=1
# Install alternative Python versions first, so that the corelens script points
# to the last one which is installed: the platform python.
%if %{with_python311}
%global __python3 %{__python311}
%py3_install
%endif
%if %{with_python312}
%global __python3 %{__python312}
%py3_install
%endif
%global __python3 %{platform_python}

%py3_install
gzip man/corelens.1
install -m644 -D man/corelens.1.gz %{buildroot}%{_mandir}/man1/corelens.1.gz

# The DRGN script is an interactive CLI which is convenient for developers,
# but should not be part of general users' PATH. If necessary, it can be invoked
# manually with "python3 -m drgn_tools.cli"
rm %{buildroot}/usr/bin/DRGN

%files -n drgn-tools
%license LICENSE.txt
%{python3_sitelib}/drgn_tools-*.egg-info/
%{python3_sitelib}/drgn_tools/*
/usr/bin/corelens
%{_mandir}/man1/corelens.1.gz

%if %{with_python311}
%files -n python3.11-drgn-tools
%license LICENSE.txt
%{python311_sitelib}/drgn_tools-*.egg-info/
%{python311_sitelib}/drgn_tools/*
%endif

%if %{with_python312}
%files -n python3.12-drgn-tools
%license LICENSE.txt
%{python312_sitelib}/drgn_tools-*.egg-info/
%{python312_sitelib}/drgn_tools/*
%endif

%changelog
* Wed Oct 30 2024 Stephen Brennan <stephen.s.brennan@oracle.com> - 1.1.1-1
- Fix crash for NULL mutex owner in corelens "lock" module [Orabug: 37186686]
- Fix crash for NULL hc.uuid in dm helper [Orabug: 37170994]
- Handle circular freelists in slabinfo [Orabug: 37170864]
- Fix missing drgn dependency for OL8 [Orabug: 37126783]
- Add support for drgn 0.0.29
- Add support to build for Python 3.11 and Python 3.12 [Orabug: 37229451]

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
