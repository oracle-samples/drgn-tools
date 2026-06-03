# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import sys
import unittest
from fnmatch import fnmatch
from functools import wraps
from pathlib import Path
from typing import List
from typing import Optional
from typing import Tuple

import drgn
from drgn import MainModule
from drgn import ModuleFileStatus

from drgn_tools.debuginfo import has_vmlinux_build_id_mismatch
from drgn_tools.debuginfo import KernelVersion
from drgn_tools.module import module_is_in_tree


VMCORE: Optional[Path] = None
VMCORE_NAME: Optional[str] = None
DEBUGINFO: List[Path] = []
CTF = False
CTF_FILE: Optional[str] = None

CORE_DIR = Path.cwd() / "vmcores"
KVER: Optional[KernelVersion] = None
PROG: Optional[drgn.Program] = None

_CONFIGURED = False
_CONFIG: Optional[Tuple[Optional[str], str, bool]] = None

_SKIP_LIVE_ATTR = "_drgntools_skip_live"
_LIVE_ONLY_ATTR = "_drgntools_live_only"
_VMCORE_ATTR = "_drgntools_vmcore"
_SKIP_VMCORE_ATTR = "_drgntools_skip_vmcore"
_KVER_MIN_ATTR = "_drgntools_kver_min"


def _append_marker(obj, attr: str, value):
    values = list(getattr(obj, attr, ()))
    values.append(value)
    setattr(obj, attr, values)
    return obj


def skip_live(obj):
    """Skip a test when running against a live kernel."""
    setattr(obj, _SKIP_LIVE_ATTR, True)
    return obj


def skip_unless_live(obj):
    """Skip a test when running against a live kernel."""
    setattr(obj, _LIVE_ONLY_ATTR, True)
    return obj


def skip_vmcore(name: str):
    """Skip a vmcore test when the vmcore name matches a pattern."""

    def decorator(obj):
        return _append_marker(obj, _SKIP_VMCORE_ATTR, name)

    return decorator


def skip_unless_vmcore(name: str):
    """Run a vmcore test only when the vmcore name matches a pattern."""

    def decorator(obj):
        return _append_marker(obj, _VMCORE_ATTR, name)

    return decorator


def skip_kernel_versions_below(ver: str):
    """Skip a test unless the target kernel version is at least ver."""

    def decorator(obj):
        return _append_marker(obj, _KVER_MIN_ATTR, ver)

    return decorator


def xfail(func):
    """Mark a test as an expected failure without failing on unexpected pass."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except unittest.SkipTest:
            raise
        except Exception as err:
            raise unittest.SkipTest(f"expected failure: {err}")

    return wrapper


def configure(
    vmcore: Optional[str] = None,
    vmcore_dir: Optional[Path] = None,
    ctf: bool = False,
) -> None:
    global VMCORE
    global VMCORE_NAME
    global DEBUGINFO
    global CORE_DIR
    global CTF
    global CTF_FILE
    global PROG
    global KVER
    global _CONFIGURED
    global _CONFIG

    core_dir = Path(vmcore_dir) if vmcore_dir else Path.cwd() / "vmcores"
    config = (vmcore, str(core_dir), ctf)
    if _CONFIGURED:
        if _CONFIG != config:
            raise RuntimeError(
                "test session is already configured differently"
            )
        return

    VMCORE = None
    VMCORE_NAME = None
    DEBUGINFO = []
    CORE_DIR = core_dir
    CTF = ctf
    CTF_FILE = None

    if vmcore:
        VMCORE_NAME = vmcore
        vmcore_root = CORE_DIR / vmcore
        vmcore_file = vmcore_root / "vmcore"
        VMCORE = vmcore_file
        if not vmcore_file.is_file():
            sys.exit(f"error: vmcore {vmcore} does not exist")
        if CTF:
            ctf_file = vmcore_root / "vmlinux.ctfa"
            if not ctf_file.is_file():
                sys.exit(f"error: CTF for vmcore {vmcore} does not exist")
            CTF_FILE = str(ctf_file)
        else:
            vmlinux_file = vmcore_root / "vmlinux"
            if not vmcore_file.is_file() or not vmlinux_file.is_file():
                sys.exit(f"error: vmlinux for {vmcore} does not exist")
            DEBUGINFO.append(vmlinux_file)
            for drgnmod in vmcore_root.glob("*.ko.debug"):
                DEBUGINFO.append(drgnmod)

    PROG = drgn.Program()
    if VMCORE:
        PROG.set_core_dump(VMCORE)
    elif os.geteuid() == 0:
        PROG.set_kernel()
    else:
        from drgn.internal.sudohelper import open_via_sudo

        PROG.set_core_dump(open_via_sudo("/proc/kcore", os.O_RDONLY))

    KVER = KernelVersion.parse(PROG["UTS_RELEASE"].string_().decode())

    print(
        "BEGIN {} {} TEST: {} (Python {}.{}, drgn {})".format(
            "CTF" if CTF else "DWARF",
            "VMCORE" if VMCORE else "LIVE",
            f"{vmcore} {KVER.original}" if VMCORE else KVER.original,
            sys.version_info[0],
            sys.version_info[1],
            getattr(drgn, "__version__", "unknown"),
        )
    )
    kmod = os.environ.get("DRGNTOOLS_TEST_KMOD")
    extra_debuginfo = [kmod] if kmod else []
    if CTF:
        try:
            from drgn.helpers.linux.ctf import load_ctf

            load_ctf(PROG, path=CTF_FILE)
            PROG.cache["using_ctf"] = True
            if kmod:
                import _drgn

                _drgn._linux_helper_load_module_ctf(
                    PROG, "drgntools_test", kmod
                )
            for module in PROG.modules():
                if isinstance(module, MainModule) or module_is_in_tree(module):
                    module.debug_file_status = ModuleFileStatus.DONT_NEED
        except ModuleNotFoundError:
            raise Exception("CTF is not supported, cannot run CTF test")
    elif DEBUGINFO:
        PROG.load_debug_info(DEBUGINFO + extra_debuginfo)
    else:
        if extra_debuginfo:
            PROG.load_debug_info(extra_debuginfo)
        if has_vmlinux_build_id_mismatch(KVER):
            PROG.create_loaded_modules()
            PROG.main_module().build_id = None
        PROG.load_default_debug_info()

    _CONFIG = config
    _CONFIGURED = True


def suite_name() -> str:
    target = (
        f"vmcore {VMCORE_NAME}" if VMCORE else f"live {os.uname().release}"
    )
    return "Python {}.{}.{} - {} ({})".format(
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
        target,
        "CTF" if CTF else "DWARF",
    )


def suite_properties():
    release = ""
    if PROG is not None:
        release = PROG["UTS_RELEASE"].string_().decode("utf-8")
    return {
        "target": VMCORE_NAME if VMCORE else "live",
        "release": release,
    }


class DrgnToolsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _CONFIGURED:
            configure()

    @property
    def prog(self) -> drgn.Program:
        assert PROG is not None
        return PROG

    @property
    def kver(self) -> KernelVersion:
        assert KVER is not None
        return KVER

    @property
    def prog_type(self) -> str:
        if VMCORE:
            return "core"
        return "live"

    @property
    def debuginfo_type(self) -> str:
        if CTF:
            return "ctf"
        return "dwarf"

    def setUp(self):
        self._apply_environment_skips()

    def _collect_marker_values(self, attr: str):
        values = []  # type: ignore[var-annotated]
        for cls in reversed(type(self).mro()):
            values.extend(getattr(cls, attr, ()))
        method = getattr(self, self._testMethodName)
        values.extend(getattr(method, attr, ()))
        return values

    def _has_marker(self, attr: str) -> bool:
        for cls in type(self).mro():
            if getattr(cls, attr, False):
                return True
        method = getattr(self, self._testMethodName)
        return bool(getattr(method, attr, False))

    def _apply_environment_skips(self):
        assert KVER is not None

        skip_live_mark = self._has_marker(_SKIP_LIVE_ATTR)
        live_only_mark = self._has_marker(_LIVE_ONLY_ATTR)
        vmcore_pats = self._collect_marker_values(_VMCORE_ATTR)
        vmcore_skip_pats = self._collect_marker_values(_SKIP_VMCORE_ATTR)
        kver_minimum = (0,)

        for value in self._collect_marker_values(_KVER_MIN_ATTR):
            version_tuple = tuple(map(int, value.split(".")))
            kver_minimum = max(kver_minimum, version_tuple)

        if vmcore_pats and vmcore_skip_pats:
            raise ValueError(
                "Can't mark a test both: vmcore() and skip_vmcore()"
            )

        if KVER.version_tuple < kver_minimum:
            self.skipTest(
                f"Skipped test (requires minimum kernel version: {kver_minimum})"
            )

        if VMCORE:
            if live_only_mark:
                self.skipTest("test marked to run only on live kernels")
            elif vmcore_pats:
                if not any(fnmatch(VMCORE_NAME, p) for p in vmcore_pats):
                    self.skipTest(
                        f"vmcore {VMCORE_NAME} not included in vmcore() mark"
                    )
            elif vmcore_skip_pats:
                if any(fnmatch(VMCORE_NAME, p) for p in vmcore_skip_pats):
                    self.skipTest(
                        f"vmcore {VMCORE_NAME} is included in vmcore_skip mark"
                    )
        elif skip_live_mark:
            self.skipTest("test marked to skip on live kernels")
