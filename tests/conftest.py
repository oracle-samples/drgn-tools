# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import List
from typing import Optional

import drgn
import pytest


VMCORE: Optional[Path] = None
VMCORE_NAME: Optional[str] = None
DEBUGINFO: List[Path] = []
CTF = False
CTF_FILE: Optional[str] = None

CORE_DIR = Path.cwd() / "vmcores"


@pytest.fixture(scope="session")
def prog() -> drgn.Program:
    p = drgn.Program()
    if VMCORE:
        p.set_core_dump(VMCORE)
    elif os.geteuid() == 0:
        p.set_kernel()
    else:
        from drgn.internal.sudohelper import open_via_sudo

        p.set_core_dump(open_via_sudo("/proc/kcore", os.O_RDONLY))
    if CTF:
        try:
            from drgn.helpers.linux.ctf import load_ctf

            # CTF_FILE may be None here, in which case the default CTF file
            # location is used (similar to below, where default DWARF debuginfo
            # is loaded if we don't have a path).
            load_ctf(p, path=CTF_FILE)
            p.cache["using_ctf"] = True
        except ModuleNotFoundError:
            raise Exception("CTF is not supported, cannot run CTF test")
    elif DEBUGINFO:
        p.load_debug_info(DEBUGINFO)
    else:
        p.load_default_debug_info()
    return p


@pytest.fixture(scope="session")
def prog_type() -> str:
    if VMCORE:
        return "core"
    else:
        return "live"


@pytest.fixture(scope="session")
def debuginfo_type() -> str:
    if CTF:
        return "ctf"
    else:
        return "dwarf"


@pytest.fixture(scope="session", autouse=True)
def log_global_env_facts(prog, record_testsuite_property):
    if VMCORE:
        record_testsuite_property("target", VMCORE_NAME)
    else:
        record_testsuite_property("target", "live")
    release = prog["UTS_RELEASE"].string_().decode("utf-8")
    record_testsuite_property("release", release)


def pytest_addoption(parser):
    parser.addoption(
        "--vmcore",
        action="store",
        metavar="VMCORE",
        default=None,
        help="Run tests for VMCORE",
    )
    parser.addoption(
        "--vmcore-dir",
        action="store",
        metavar="DIR",
        default=None,
        help="Search for vmcores in DIR",
    )
    parser.addoption(
        "--ctf",
        action="store_true",
        default=False,
        help="Use CTF data instead of DWARF",
    )


def pytest_configure(config):
    global VMCORE
    global VMCORE_NAME
    global CORE_DIR
    global CTF
    global CTF_FILE

    # The default for tests is to run in every environment: vmcore and live
    # kernel. But using markers, we can restrict tests:
    #
    # @pytest.mark.skip_live: Do not run on live VMs
    # @pytest.mark.vmcore("block_*"): only run on vmcores whose name matches the
    #   pattern (in this case, block*). Still runs on live VMs -- you can use
    #   skip_live as well if you want to prevent testing on a live VM.
    # @ptest.mark.skip_vmcore("foo_*"): skip on vmcores whose name matches the
    #   pattern.
    # The latter two options (only_vmcore, skip_vmcore) are mutually exclusive
    # and will result in an error.
    #
    # Some examples:
    #   - No marker: run on all vmcores and all live VMs
    #   - skip_live: runs on all vmcores, but not live VMs
    #   - vmcore("*uek6"): run only on vmcores whose name ends in UEK6.
    #     Still runs on all live VMs.
    #   - skip_vmcore("*"): run on live VMs, but not vmcores
    config.addinivalue_line("markers", "skip_live: requires live system")
    config.addinivalue_line(
        "markers", "vmcore(name): requires named core dump"
    )
    config.addinivalue_line(
        "markers", "skip_vmcore(name): skip when debugging this core dump"
    )

    core_dir = config.getoption("vmcore_dir")
    if core_dir:
        CORE_DIR = Path(core_dir)
    vmcore = config.getoption("vmcore")
    CTF = config.getoption("ctf")
    debuginfo_kind = "CTF" if CTF else "DWARF"
    if vmcore:
        # With vmcore tests, we need to manually find the debuginfo alongside
        # the vmcore in the same directory. For heavyvm or litevm tests, the
        # debuginfo is installed to the default locations, so we don't need any
        # logic for them.
        VMCORE_NAME = vmcore
        vmcore_dir = CORE_DIR / vmcore
        vmcore_file = vmcore_dir / "vmcore"
        VMCORE = vmcore_file
        if not vmcore_file.is_file():
            pytest.exit(
                reason=f"error: vmcore {vmcore} does not exist",
                returncode=1,
            )
        if CTF:
            ctf_file = vmcore_dir / "vmlinux.ctfa"
            if not ctf_file.is_file():
                pytest.exit(
                    reason=f"error: CTF for vmcore {vmcore} does not exist",
                    returncode=1,
                )
            CTF_FILE = str(ctf_file)
        else:
            vmlinux_file = vmcore_dir / "vmlinux"
            if not vmcore_file.is_file() or not vmlinux_file.is_file():
                pytest.exit(
                    reason=f"error: vmlinux for {vmcore} does not exist",
                    returncode=1,
                )
            DEBUGINFO.append(vmlinux_file)
            for module in vmcore_dir.glob("*.ko.debug"):
                DEBUGINFO.append(module)

    config.inicfg["junit_suite_name"] = "Python {}.{}.{} - {} ({})".format(
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
        f"vmcore {vmcore}" if vmcore else f"live {os.uname().release}",
        debuginfo_kind,
    )
    if CTF:
        print("TESTING WITH CTF")


def pytest_runtest_setup(item: pytest.Item):
    skip_live = False
    vmcore_pats = []
    vmcore_skip_pats = []

    for mark in item.iter_markers():
        if mark.name == "skip_live":
            skip_live = True
        if mark.name == "vmcore":
            vmcore_pats.append(mark.args[0])
        if mark.name == "skip_vmcore":
            vmcore_skip_pats.append(mark.args[0])

    if vmcore_pats and vmcore_skip_pats:
        raise ValueError("Can't mark a test both: vmcore() and skip_vmcore()")

    if VMCORE:
        if vmcore_pats:
            if not any(fnmatch(VMCORE_NAME, p) for p in vmcore_pats):
                pytest.skip(
                    f"vmcore {VMCORE_NAME} not included in vmcore() mark"
                )
        elif vmcore_skip_pats:
            if any(fnmatch(VMCORE_NAME, p) for p in vmcore_skip_pats):
                pytest.skip(
                    f"vmcore {VMCORE_NAME} is included in vmcore_skip mark"
                )
    else:
        if skip_live:
            pytest.skip("test marked to skip on live kernels")
