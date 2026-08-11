# Copyright (c) 2024, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Run tests in parallel against vmcores
"""
import argparse
import fnmatch
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from typing import List
from typing import NamedTuple
from typing import Optional

from drgn_tools.debuginfo import CtfCompatibility
from drgn_tools.debuginfo import KernelVersion
from testing.chroot import BindMount
from testing.chroot import run_in_rootfs
from testing.config import Architecture
from testing.config import Debuginfo
from testing.config import OLVersion
from testing.config import PythonVer
from testing.config import Rootfs
from testing.config import TestDirectories
from testing.util import combine_junit_xml


class TestParam(NamedTuple):
    core_name: str
    rootfs: Optional[Rootfs]
    mode: Debuginfo
    python: PythonVer


class TestResult(NamedTuple):
    param: TestParam
    success: bool
    junitxml: ET.ElementTree


def _test_in_host(
    layout: TestDirectories,
    param: TestParam,
    test_cmd: List[str],
) -> TestResult:
    testlog = layout.vmcore_log_path(
        param.core_name, param.mode.value, "hostfs", param.python.value
    )
    xml = testlog.parent / testlog.name.replace(".log", ".xml")
    with testlog.open("wt") as f:
        print(f"Begin testing {param.core_name}")
        test_cmd.extend(
            [
                f"--vmcore-dir={str(layout.vmcore_dir)}",
                f"--junitxml={str(xml)}",
            ]
        )
        start = time.time()
        res = subprocess.run(test_cmd, stdout=f, stderr=f)
        if res.returncode != 0:
            print(f"=== FAILURE: {param.core_name} ===")
            f.seek(0)
            sys.stdout.write(f.read())
        runtime = time.time() - start
        print(f"Completed testing {param.core_name} in {runtime:.1f}")
        run_data = ET.parse(xml)
    return TestResult(param, res.returncode == 0, run_data)


def _test_in_rootfs(
    layout: TestDirectories,
    param: TestParam,
    test_cmd: List[str],
) -> TestResult:
    r: Rootfs = param.rootfs  # type: ignore[assignment]  # rootfs is present
    testlog = layout.vmcore_log_path(
        param.core_name,
        param.mode.value,
        r.name,
        param.python.value,
    )
    xml = testlog.parent / testlog.name.replace(".log", ".xml")
    print(f"Begin testing {param.core_name} in {r}")
    code_dir = Path(__file__).parent.parent.parent
    mounts = [
        BindMount(layout.vmcore_dir, "/vmcores", True),
        BindMount(layout.logs_dir, "/output", False),
        BindMount(code_dir, "/code", True),
    ]
    test_cmd.extend(
        [
            "--vmcore-dir=/vmcores",
            f"--junitxml=/output/{xml.name}",
        ]
    )
    start = time.time()
    rootfs = layout.rootfs_path(r)
    with testlog.open("w") as f:
        res = run_in_rootfs(
            rootfs,
            test_cmd,
            mounts,
            cwd="/code",
            stdout=f,
            stderr=f,
        )
    runtime = time.time() - start
    if res.returncode != 0:
        print(f"=== FAILURE: {param.core_name} ===")
        sys.stdout.buffer.write(testlog.read_bytes())
    print(f"Completed testing {param.core_name} in {runtime:.1f}")
    run_data = ET.parse(xml)
    return TestResult(param, res.returncode == 0, run_data)


def _skip_ctf(
    mode: Debuginfo, uname: str, host_ol: int, rootfs: Optional[Rootfs]
) -> bool:
    # Skip CTF mode based on the CTF compatibility where the tests are run. If
    # it's within the rootfs, use that ol version instead.
    if rootfs:
        host_ol = rootfs.ol_ver.value
    if mode == Debuginfo.CTF:
        kver = KernelVersion.parse(uname)
        compat = CtfCompatibility.get(kver, host_ol)
        # Skip test when CTF is fully unsupported, or when it would require a
        # /proc/kallsyms.
        return compat in (
            CtfCompatibility.NO,
            CtfCompatibility.LIMITED_PROC,
        )
    return False  # don't skip when non-CTF


def host_ol_ver() -> int:
    rel = {}
    with open("/etc/os-release") as f:
        for line in f:
            line = line.strip()
            if line:
                key, qval = line.split("=", 1)
                # Remove double quotes. Doesn't handle escape sequences, oh well.
                rel[key] = qval[1:-1]
    if "VERSION" in rel and "Oracle" in rel.get("NAME", ""):
        ol_ver = int(rel["VERSION"].split(".", 1)[0])
        print(f"Detected host OL version: {ol_ver}")
    else:
        ol_ver = 9
        print("Assuming OL 9")
    return ol_ver


def test(
    layout: TestDirectories,
    vmcore_list: List[str],
    modes: List[Debuginfo],
    python: PythonVer,
    parallel: int = 1,
    ol_ver: Optional[OLVersion] = None,
    test_args: Optional[List[str]] = None,
) -> None:
    def should_run_vmcore(name: str) -> bool:
        if not vmcore_list:
            return True
        for pat in vmcore_list:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    failed = []
    passed = []
    skipped = []
    xml = None
    host_ol = host_ol_ver()
    if ol_ver is None:
        test_fn = _test_in_host
        rootfs = None
    else:
        test_fn = _test_in_rootfs
        rootfs = Rootfs(ol_ver, Architecture.host_arch())

    if python is None:
        python = sys.executable if ol_ver is None else "python3"

    if test_args is None:
        test_args = []

    with ExitStack() as es:
        pool = es.enter_context(ThreadPoolExecutor(max_workers=parallel))
        futures = []
        for path in layout.vmcore_dir.iterdir():
            core_name = path.name
            if not should_run_vmcore(core_name):
                continue
            for mode in modes:
                param = TestParam(core_name, rootfs, mode, python)
                uname = (path / "UTS_RELEASE").read_text().strip()
                if _skip_ctf(mode, uname, host_ol, rootfs):
                    skipped.append(param)
                    continue
                cmd = [
                    python.value,
                    "-m",
                    "testing.unittest_runner",
                    f"--vmcore={core_name}",
                    *test_args,
                ]
                if mode == Debuginfo.CTF:
                    if not (path / "vmlinux.ctfa").is_file():
                        skipped.append(param)
                        continue
                    cmd.append("--ctf")
                futures.append(pool.submit(test_fn, layout, param, cmd))

        for future in futures:
            param, test_passed, run_data = future.result()
            xml = combine_junit_xml(xml, run_data)
            if test_passed:
                passed.append(param)
            else:
                failed.append(param)

    if xml is not None:
        xml.write("vmcore.xml")
    print("Complete test logs: vmcore.xml")
    print("Vmcore Test Summary -- Passed:")
    print("\n".join(f"- {p.core_name} ({p.mode})" for p in passed))
    if skipped:
        print("Vmcore Test Summary -- Skipped (missing CTF):")
        print("\n".join(f"- {p.core_name} ({p.mode})" for p in skipped))
    if failed:
        print("Vmcore Test Summary -- FAILED:")
        print("\n".join(f"- {p.core_name} ({p.mode})" for p in failed))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="manages drgn-tools vmcores",
    )
    parser.add_argument(
        "--core-directory", type=Path, help="where to store vmcores"
    )
    parser.add_argument(
        "--base-directory", type=Path, help="testdata base directory"
    )
    parser.add_argument(
        "--parallel",
        "-j",
        type=int,
        default=1,
        help="Run the tests in parallel with the given number of threads",
    )
    parser.add_argument(
        "--vmcore",
        "-c",
        action="append",
        default=[],
        help="only run tests on the given vmcore(s). you can use this "
        "multiple times to specify multiple vmcore names. You can also "
        "use fnmmatch patterns to specify several cores at once.",
    )
    parser.add_argument(
        "--no-ctf",
        dest="ctf",
        action="store_false",
        help="Do not run tests with CTF",
    )
    parser.add_argument(
        "--no-dwarf",
        dest="dwarf",
        action="store_false",
        help="Do not run tests with DWARF",
    )
    parser.add_argument(
        "--ol",
        choices=[OLVersion.OL8, OLVersion.OL9, OLVersion.OL10],
        type=lambda s: OLVersion(int(s)),
        default=None,
        help="Run the tests within the Oracle Linux (already built) rootfs",
    )
    parser.add_argument(
        "--python",
        default=PythonVer.SYSTEM,
        type=PythonVer,
        help="Run the tests with the given python binary name",
    )
    parser.add_argument(
        "args",
        nargs="*",
        help="Arguments to pass through to unittest_runner, e.g. to specify"
        " which test files to run.",
    )
    args = parser.parse_args()
    layout = TestDirectories.create(args.base_directory, args.core_directory)
    layout.logs_dir.mkdir(exist_ok=True, parents=True)
    modes = []
    if args.ctf:
        modes.append(Debuginfo.CTF)
    if args.dwarf:
        modes.append(Debuginfo.DWARF)
    test(
        layout,
        args.vmcore,
        modes,
        args.python,
        parallel=args.parallel,
        ol_ver=args.ol,
        test_args=args.args,
    )


if __name__ == "__main__":
    main()
