# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
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

CORE_DIR = Path.cwd() / "vmcores"


@pytest.fixture(scope="session")
def prog() -> drgn.Program:
    p = drgn.Program()
    if VMCORE:
        p.set_core_dump(VMCORE)
        p.load_debug_info(DEBUGINFO)
        return p
    else:
        p.set_kernel()
        p.load_default_debug_info()
        return p


@pytest.fixture(scope="session")
def prog_type() -> str:
    if VMCORE:
        return "core"
    else:
        return "live"


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


def pytest_configure(config):
    global VMCORE
    global VMCORE_NAME
    global CORE_DIR

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
    if vmcore:
        VMCORE_NAME = vmcore
        vmcore_dir = CORE_DIR / vmcore
        vmcore_file = vmcore_dir / "vmcore"
        vmlinux_file = vmcore_dir / "vmlinux"
        if not vmcore_file.is_file() or not vmlinux_file.is_file():
            pytest.exit(
                reason=f"error: vmcore {vmcore} does not exist",
                returncode=1,
            )
        VMCORE = vmcore_file
        DEBUGINFO.append(vmlinux_file)
        for module in vmcore_dir.glob("*.ko.debug"):
            DEBUGINFO.append(module)

    config.inicfg["junit_suite_name"] = "Python {}.{}.{} - {}".format(
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
        f"vmcore {vmcore}" if vmcore else "live",
    )


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
