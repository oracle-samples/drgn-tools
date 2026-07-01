# Copyright (c) 2024-2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/

# Build settings by OL version:
# - with_python3: produce drgn-tools RPM for system python
# - with_python3xx: produce python3.xx-drgn-tools RPM for python stream
# - with_alternatives: use alternatives to enable swapping default corelens
%if 0%{?rhel} == 7
%global with_python3      1
%global with_python311    0
%global with_python312    0
%global with_python314    0
%global with_alternatives 0
%endif
%if 0%{?rhel} == 8
%global with_python3      1
%global with_python311    1
%global with_python312    1
%global with_python314    0
%global with_alternatives 1
%endif
%if 0%{?rhel} == 9
%global with_python3      1
%global with_python311    1
%global with_python312    1
%global with_python314    1
%global with_alternatives 1
%endif
%if 0%{?rhel} == 10
%global with_python3      1
%global with_python311    0
%global with_python312    0
%global with_python314    1
%global with_alternatives 1
%endif

%if %{with_python3}
%global dt_python3_cmd %{_bindir}/python3-corelens
%endif
%if %{with_python311}
%global __python311 /usr/bin/python3.11
%global python311_sitelib /usr/lib/python3.11/site-packages
%global dt_python311_cmd %{_bindir}/python3.11-corelens
%endif
%if %{with_python312}
%global __python312 /usr/bin/python3.12
%global python312_sitelib /usr/lib/python3.12/site-packages
%global dt_python312_cmd %{_bindir}/python3.12-corelens
%endif
%if %{with_python314}
%global __python314 /usr/bin/python3.14
%global python314_sitelib /usr/lib/python3.14/site-packages
%global dt_python314_cmd %{_bindir}/python3.14-corelens
%endif

%if %{with_alternatives}
%global dt_alt_name corelens
%global dt_alt_link %{_bindir}/corelens
%if %{with_python3}
%global dt_alt_priority_py3 %(%{__python3} -c 'import sys; print("{}{:02d}".format(*sys.version_info))')
%endif
%if %{with_python311}
%global dt_alt_priority_py311 311
%endif
%if %{with_python312}
%global dt_alt_priority_py312 312
%endif
%if %{with_python314}
%global dt_alt_priority_py314 314
%endif
%endif


Name:           python-drgn-tools
Version:        2.3.0
Release:        1%{?dist}
Summary:        Helper scripts for drgn, containing the corelens utility

License:        UPL
URL:            https://github.com/oracle-samples/drgn-tools
Source0:        drgn-tools-%{version}.tar.bz2

BuildArch:      noarch

%if %{with_python3}
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-pip
BuildRequires:  python%{python3_pkgversion}-wheel
%endif
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
%if %{with_python314}
BuildRequires:  python3.14-devel
BuildRequires:  python3.14-setuptools
BuildRequires:  python3.14-pip
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
%global drgn_min 0.0.32
%global drgn_max 0.3.0

%if %{with_python3}
%package -n     drgn-tools
Summary:        %{summary}
Requires:       drgn >= %{drgn_min}, drgn < %{drgn_max}
%description -n drgn-tools %{_description}
%if %{with_alternatives}
Requires(post): %{_sbindir}/alternatives
Requires(postun): %{_sbindir}/alternatives
%endif
%endif

%if %{with_python311}
%package -n     python3.11-drgn-tools
Summary:        %{summary}
Requires:       python3.11-drgn >= %{drgn_min}, python3.11-drgn < %{drgn_max}
%description -n python3.11-drgn-tools %{_description}
%if %{with_alternatives}
Requires(post): %{_sbindir}/alternatives
Requires(postun): %{_sbindir}/alternatives
%endif
%endif

%if %{with_python312}
%package -n     python3.12-drgn-tools
Summary:        %{summary}
Requires:       python3.12-drgn >= %{drgn_min}, python3.12-drgn < %{drgn_max}
%description -n python3.12-drgn-tools %{_description}
%if %{with_alternatives}
Requires(post): %{_sbindir}/alternatives
Requires(postun): %{_sbindir}/alternatives
%endif
%endif

%if %{with_python314}
%package -n     python3.14-drgn-tools
Summary:        %{summary}
Requires:       python3.14-drgn >= %{drgn_min}, python3.14-drgn < %{drgn_max}
%description -n python3.14-drgn-tools %{_description}
%if %{with_alternatives}
Requires(post): %{_sbindir}/alternatives
Requires(postun): %{_sbindir}/alternatives
%endif
%endif

%prep
%autosetup -n drgn-tools-%{version}
echo '__version__ = "%{version}+%{release}"' > drgn_tools/_version.py

%build

%install
%if %{with_python311}
%global __python3 %{__python311}
%py3_build
%py3_install
mv %{buildroot}/%{_bindir}/corelens %{buildroot}/%{dt_python311_cmd}
%endif
%if %{with_python312}
%global __python3 %{__python312}
%py3_build
%py3_install
mv %{buildroot}/%{_bindir}/corelens %{buildroot}/%{dt_python312_cmd}
%endif
%if %{with_python314}
%global __python3 %{__python314}
%py3_build
%py3_install
mv %{buildroot}/%{_bindir}/corelens %{buildroot}/%{dt_python314_cmd}
%endif
%global __python3 %{platform_python}

%if %{with_python3}
%py3_build
%py3_install
# When packaging the main drgn-tools with alternatives, we must rename corelens
# to "python3-corelens" and provide an empty file to satisfy the ghost
# directive.
%if %{with_alternatives}
mv %{buildroot}/%{_bindir}/corelens %{buildroot}/%{dt_python3_cmd}
touch %{buildroot}/%{dt_alt_link}
%endif
gzip man/corelens.1
install -m644 -D man/corelens.1.gz %{buildroot}%{_mandir}/man1/corelens.1.gz
install -m644 -D extras/corelens.py %{buildroot}%{python3_sitelib}/sos/report/plugins/corelens.py
%endif

# The DRGN script is an interactive CLI which is convenient for developers,
# but should not be part of general users' PATH. If necessary, it can be invoked
# manually with "python3 -m drgn_tools.cli"
rm -f %{buildroot}/usr/bin/DRGN

%if %{with_alternatives}
%if %{with_python3}
# If upgrading from a prior non-alternatives version, the corelens script will
# be present at /usr/bin/corelens and alternatives will fail to install the
# symlink:
#
#     failed to link /usr/bin/corelens -> /etc/alternatives/corelens /usr/bin/corelens exists and it is not a symlink
#
# The responsibility must be for the main drgn-tools RPM to remove the prior
# script, because it owns the file.
#
# Note that as a result, it is possible for a user to install an
# alternatives-enabled python3.xx-drgn-tools alongside a non-alternatives
# drgn-tools RPM. This can occur if they fail to upgrade their system (or at
# least drgn-tools) prior to installing the newest python3.xx-drgn-tools.
# However, in all cases, this can be resolved by simply upgrading drgn-tools.
%post -n drgn-tools
if [ -e "%{dt_alt_link}" ] && [ ! -L "%{dt_alt_link}" ]; then
    rm -f "%{dt_alt_link}"
fi
%{_sbindir}/alternatives --install %{dt_alt_link} %{dt_alt_name} %{dt_python3_cmd} %{dt_alt_priority_py3}
%postun -n drgn-tools
if [ $1 -eq 0 ]; then
    %{_sbindir}/alternatives --remove %{dt_alt_name} %{dt_python3_cmd}
fi
%endif
%if %{with_python311}
%post -n python3.11-drgn-tools
%{_sbindir}/alternatives --install %{dt_alt_link} %{dt_alt_name} %{dt_python311_cmd} %{dt_alt_priority_py311}
%postun -n python3.11-drgn-tools
if [ $1 -eq 0 ]; then
    %{_sbindir}/alternatives --remove %{dt_alt_name} %{dt_python311_cmd}
fi
%endif
%if %{with_python312}
%post -n python3.12-drgn-tools
%{_sbindir}/alternatives --install %{dt_alt_link} %{dt_alt_name} %{dt_python312_cmd} %{dt_alt_priority_py312}
%postun -n python3.12-drgn-tools
if [ $1 -eq 0 ]; then
    %{_sbindir}/alternatives --remove %{dt_alt_name} %{dt_python312_cmd}
fi
%endif
%if %{with_python314}
%post -n python3.14-drgn-tools
%{_sbindir}/alternatives --install %{dt_alt_link} %{dt_alt_name} %{dt_python314_cmd} %{dt_alt_priority_py314}
%postun -n python3.14-drgn-tools
if [ $1 -eq 0 ]; then
    %{_sbindir}/alternatives --remove %{dt_alt_name} %{dt_python314_cmd}
fi
%endif
%endif

%if %{with_python3}
%files -n drgn-tools
%license LICENSE.txt
%{python3_sitelib}/drgn_tools-*.egg-info/
%{python3_sitelib}/drgn_tools/*
%if %{with_alternatives}
%ghost %{dt_alt_link}
%{dt_python3_cmd}
%else
%{_bindir}/corelens
%endif
%{_mandir}/man1/corelens.1.gz
%{python3_sitelib}/sos/report/plugins/corelens.py
%{python3_sitelib}/sos/report/plugins/__pycache__/corelens.*
%endif

%if %{with_python311}
%files -n python3.11-drgn-tools
%license LICENSE.txt
%{python311_sitelib}/drgn_tools-*.egg-info/
%{python311_sitelib}/drgn_tools/*
%{dt_python311_cmd}
%endif

%if %{with_python312}
%files -n python3.12-drgn-tools
%license LICENSE.txt
%{python312_sitelib}/drgn_tools-*.egg-info/
%{python312_sitelib}/drgn_tools/*
%{dt_python312_cmd}
%endif

%if %{with_python314}
%files -n python3.14-drgn-tools
%license LICENSE.txt
%{python314_sitelib}/drgn_tools-*.egg-info/
%{python314_sitelib}/drgn_tools/*
%{dt_python314_cmd}
%endif

%changelog
* Fri Jun 26 2026 Stephen Brennan <stephen.s.brennan@oracle.com> - 2.3.0-1
- Add support for drgn 0.1.0 and drgn 0.2.0 (Stephen Brennan)
- New corelens module: slabdump (Stephen Brennan)
- Improve testing frameworks and unit tests (Stephen Brennan)
- runq: dump task scheduling delay and RT throttling status (Junxiao Bi)
- blockinfo: Add disk driver (Junxiao Bi)
- kvm: Fix "not a valid MemSlotFlag" error [Orabug: 39025976] (Siddhi Katage)
- lock: Add support for completion variables [Orabug: 38803445] (Imran Khan)
- rds: Add verbose diagnostics and fix connection CPU info on older UEK5/UEK6 kernels (Anand Khoje, Pradyumn Rahar, Stephen Brennan)
- inflightio: Add NVMe management queue support (Junxiao Bi)
- scsi: Add "--target" option [Orabug: 39271381] (Rajan Shanmugavelu)
- scsi: Add verbose host info for qla2xxx LFPC and megraid_sas HBA hosts [Orabug: 39122042] (Rajan Shanmugavelu)
- slabinfo: fix failures with per-cpu sheaves [Orabug: 39518020] (Imran Khan)
- smp: fix smp module for uek7 and later kernels [Orabug: 39429804] (Imran Khan)
- Add corelens command to drgn and crash [Orabug: 39523319] (Stephen Brennan)
- Fix incorrect CPU count in corelens sys module [Orabug: 38829413] (Stephen Brennan)
- runq: do not filter curr from output [Orabug: 38933146] (Stephen Brennan)
- nvme: disambiguate nvme_ns and nvme_ns_head [Orabug: 38995392] (Stephen Brennan)
- Improve detection of ksplice cold-patches and proprietary modules (Stephen Brennan)
- corelens: add overrides to specify vmcoreinfo and architecture (Stephen Brennan)
- Fix FaultError in slab_object_to_memcgidx [Orabug: 39653070] (Stephen Brennan)
- Add Python 3.14 to RPM packaging (Stephen Brennan)
- Use alternatives to switch default corelens command (Stephen Brennan)

* Fri Jan 30 2026 Stephen Brennan <stephen.s.brennan@oracle.com> - 2.2.1-1
- Print number of pending I/O requests for all virtio devices [Orabug: 38665851] (Siddhi Katage)
- pstack: multiple fixes (Stephen Brennan)
- fsnotify: fix FaultError on RHCK7 (Stephen Brennan)
- memstate: fix miscounted hugepages (Stephen Brennan)
- debuginfo: handle multiple calls to drgn_prog_set() (Stephen Brennan)
- meminfo: handle "could not find symbol with name 'swapper_spaces'" (Stephen Brennan)

* Tue Nov 04 2025 Stephen Brennan <stephen.s.brennan@oracle.com> - 2.2.0-1
- Rework drgn-tools debuginfo loading to be based on drgn's Module API (Stephen Brennan)
- Create "oracle" drgn plugin which encapsulates drgn-tools debuginfo logic (Stephen Brennan)
- New corelens module: "pstack" for printing userspace stack traces (Stephen Brennan)
- Corelens module: equivalent to oled memstate [Orabug: 37357348] (Yassine Larhrissi)
- Corelens fails accessing rds_ib_devices [Orabug: 37502613] (Stephen Brennan)
- Print ioeventfd, iobus, vmstat and vcpustat information in kvm corelens module. [Orabug: 37713468] (Siddhi Katage)
- crash in corelens rds module [Orabug: 38225228] (Stephen Brennan)
- test_dump_page_cache_pages_pinning_cgroups produces too much output [Orabug: 37974100] (Stephen Brennan)
- Test failure for module_build_id() in Linux 6.14 [Orabug: 37973187] (Stephen Brennan)
- False negatives in module debuginfo detection [Orabug: 37894875] (Stephen Brennan)
- Make md helper not crash with uninitialized percpu refcount [Orabug: 37968889] (Junxiao Bi)
- UEK8, drgn-tools-2.1.0-1.el9.noarch : Error with corelens binary when run with /proc/kcore or vmcore [Orabug: 37894852] (Stephen Brennan)
- drgn-tools-2.1.0-1.el9: python traceback when ctrl-c done with corelens command [Orabug: 37894865] (Stephen Brennan)
- Mountinfo fails on a (nearly) empty struct mount [Orabug: 37911508] (Stephen Brennan)
- lockup: detect the blocker for process hang in RCU grace period [Orabug: 37899681] (Richard Li)
- Add vectorinfo module to drgn_tools [Orabug: 38383772] (Srivathsa Dara)
- corelens: dump panic bt [Orabug: 38074929] (Richard Li)
- Enhance rds helper to extract rdma resources and RDS QP state [Orabug: 38221449] (Anand Khoje)
- Add sosreport module for collecting corelens reports (Anil Palakunnathu Kunnengeri)

* Thu Apr 17 2025 Stephen Brennan <stephen.s.brennan@oracle.com> - 2.1.0-1
- Add helper and module for unsubmitted pending work (Imran Khan)
- Add -V option to display version, and include the version in corelens reports (Stephen Brennan) [Orabug: 37503503]
- targetcli: add portal info (Richard Li) [Orabug: 37444641]
- Add --mmslot option to kvm module (Siddhi Katage) [Orabug: 37357370]
- Fix crash in show_unexpired_delayed_works with CTF (Stephen Brennan) [Orabug: 37695749]
- Add support for drgn 0.0.31 (Stephen Brennan)

* Fri Jan 10 2025 Stephen Brennan <stephen.s.brennan@oracle.com> - 2.0.0-1
- Installing drgn-tools does not pull in drgn as a dependency (Stephen Brennan) [Orabug: 37126732]
- Circular freelist causes infinite loop in corelens "slabinfo" module (Stephen Brennan) [Orabug: 37170860]
- hc.uuid null pointer in dm helper (Richard Li) [Orabug: 37176287]
- Crash for NULL mutex owner in corelens "lock" module (Stephen Brennan) [Orabug: 37186679]
- Enable all v2 corelens modules (Stephen Brennan) [Orabug: 37186712]
- drgn-tools: add a lockup helper (Richard Li) [Orabug: 37187006]
- runq: add prio and runtime (Richard Li) [Orabug: 37187104]
- Add support to corelens-ls module to recursively print direntries of sub-directories (Srivathsa Dara) [Orabug: 37188670]
- corelens: add sysctl to corelens module (Richard Li) [Orabug: 37191878]
- targetcli: helper to reconstruct and dump targetcli structure on iscsi target (Richard Li) [Orabug: 37285210]
- Drgn-tools compatibility with UEK next (Stephen Brennan) [Orabug: 37296325]
- targetcli: helper to dump iscsi and vhost sections info from targetcli (Richard Li) [Orabug: 37301968]
- Streamline drgn-tools testing & CI (Stephen Brennan) [Orabug: 37307170]
- Add memcgroup related helpers to drgn-tools (Imran Khan) [Orabug: 37322867]
- Corelens module: vhost (Richard Li) [Orabug: 37357372]
- couple small enhancment for dm/block helpers (Junxiao Bi) [Orabug: 37361260]
- drgn-tools: add an iscsi helper (Richard Li) [Orabug: 37362180]
- corelens: add support for multiple kmods in skip_unless_have_kmod (Richard Li) [Orabug: 37389765]
- corelens inflight io helpers crash due to a missing data filed with uek7 (Junxiao Bi) [Orabug: 37393601]
- Support drgn 0.0.30 (Stephen Brennan) [Orabug: 37413889]

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
