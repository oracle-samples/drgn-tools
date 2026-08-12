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
from drgn_tools.table import Table
from drgn_tools.vmcore import Dump
from drgn_tools.vmcore import DUMP_DH_COMPRESSED
from testing.chroot import BindMount
from testing.chroot import run_in_rootfs
from testing.config import APPSTREAM_PYTHONS
from testing.config import Architecture
from testing.config import Debuginfo
from testing.config import OLVersion
from testing.config import PythonVer
from testing.config import Rootfs
from testing.config import TestDirectories
from testing.rootfs import have_ol7_rootfs
from testing.util import combine_junit_xml


class TestParam(NamedTuple):
    core_name: str
    rootfs: Optional[Rootfs]
    mode: Debuginfo
    python: PythonVer
    args: List[str]


class TestResult(NamedTuple):
    param: TestParam
    success: bool
    junitxml: ET.ElementTree


def _test_in_host(layout: TestDirectories, param: TestParam) -> TestResult:
    testlog = layout.vmcore_log_path(
        param.core_name, param.mode.value, "hostfs", param.python.value
    )
    xml = testlog.parent / testlog.name.replace(".log", ".xml")
    with testlog.open("wt") as f:
        print(f"Begin testing {param.core_name}")
        test_cmd = [
            sys.executable,
            "-m",
            "testing.unittest_runner",
            f"--vmcore-dir={str(layout.vmcore_dir)}",
            f"--vmcore={param.core_name}",
            f"--junitxml={str(xml)}",
            *param.args,
        ]
        if param.mode == Debuginfo.CTF:
            test_cmd.append("--ctf")
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


def _test_in_rootfs(layout: TestDirectories, param: TestParam) -> TestResult:
    r: Rootfs = param.rootfs  # type: ignore[assignment]  # rootfs is present
    testlog = layout.vmcore_log_path(
        param.core_name,
        param.mode.value,
        r.name,
        param.python.value,
    )
    xml = testlog.parent / testlog.name.replace(".log", ".xml")
    print(
        f"Begin testing {param.core_name} in {r.name} with {param.python.value}"
    )
    code_dir = Path(__file__).parent.parent.parent
    mounts = [
        BindMount(layout.vmcore_dir, "/vmcores", True),
        BindMount(layout.logs_dir, "/output", False),
        BindMount(code_dir, "/code", True),
    ]
    test_cmd = [
        param.python.value,
        "-m",
        "testing.unittest_runner",
        f"--vmcore={param.core_name}",
        "--vmcore-dir=/vmcores",
        f"--junitxml=/output/{xml.name}",
        *param.args,
    ]
    if param.mode == Debuginfo.CTF:
        test_cmd.append("--ctf")
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


def _skip_ol7_zstd(ol_ver: int, path: Path) -> bool:
    # OL7 libkdumpfile / drgn do not support ZSTD. Detect these cores and skip
    # them on OL7 or prior.
    if ol_ver > 7:
        return False
    vmcore = Dump(path)
    return bool(vmcore.get_compression() & DUMP_DH_COMPRESSED.ZSTD)


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


def get_all_tests(
    layout: TestDirectories,
    vmcore_list: List[str],
    modes: List[Debuginfo],
    py_vers: List[PythonVer],
    ol_vers: List[OLVersion],
    args: List[str],
) -> List[TestParam]:
    def should_run_vmcore(name: str) -> bool:
        if not vmcore_list:
            return True
        for pat in vmcore_list:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    params = []
    host_ol = host_ol_ver()
    for path in layout.vmcore_dir.iterdir():
        core_name = path.name
        if not should_run_vmcore(core_name):
            continue
        uname = (path / "UTS_RELEASE").read_text().strip()

        for dbinfo in modes:
            if (
                dbinfo == Debuginfo.CTF
                and not (path / "vmlinux.ctfa").is_file()
            ):
                continue
            if not ol_vers:
                if py_vers != [PythonVer.SYSTEM]:
                    sys.exit(
                        "error: when running in hostfs, only system python may be used"
                    )
                if _skip_ctf(dbinfo, uname, host_ol, None):
                    continue
                if _skip_ol7_zstd(host_ol, path / "vmcore"):
                    continue
                params.append(
                    TestParam(core_name, None, dbinfo, PythonVer.SYSTEM, args)
                )
                continue
            for ol_ver in ol_vers:
                rootfs = Rootfs(ol_ver, Architecture.host_arch())
                if _skip_ctf(dbinfo, uname, host_ol, rootfs):
                    continue
                if _skip_ol7_zstd(ol_ver.value, path / "vmcore"):
                    continue
                supported_pythons = (PythonVer.SYSTEM,) + APPSTREAM_PYTHONS[
                    ol_ver
                ]
                for py_ver in py_vers:
                    if py_ver not in supported_pythons:
                        continue
                    params.append(
                        TestParam(core_name, rootfs, dbinfo, py_ver, args)
                    )

    return params


def print_params(params_list: List[TestParam], comment: str):
    t = Table(["CORE", "ROOTFS", "DBINFO", "PYVER"])
    for param in params_list:
        t.row(
            param.core_name,
            param.rootfs.name if param.rootfs else "host",
            param.mode.value,
            param.python.value,
        )
    t.write()
    print(f"{comment} {len(params_list)} suites")


def test(
    layout: TestDirectories,
    params: List[TestParam],
    parallel: int = 1,
) -> None:
    failed = []
    passed = []
    xml = None

    start = time.time()
    with ExitStack() as es:
        pool = es.enter_context(ThreadPoolExecutor(max_workers=parallel))
        futures = []
        for param in params:
            if param.rootfs is None:
                futures.append(pool.submit(_test_in_host, layout, param))
            else:
                futures.append(pool.submit(_test_in_rootfs, layout, param))

        for future in futures:
            param, test_passed, run_data = future.result()
            xml = combine_junit_xml(xml, run_data)
            if test_passed:
                passed.append(param)
            else:
                failed.append(param)

    runtime = time.time() - start

    if xml is not None:
        xml.write("vmcore.xml")
    print("Complete test logs: vmcore.xml")
    print("Vmcore Test Summary -- Passed:")
    print_params(passed, "Passed:")
    if failed:
        print("Vmcore Test Summary -- FAILED:")
        print_params(failed, "Failed:")
    print(f"Ran {len(params)} suites (-j{parallel}) in {runtime:.1f}s")
    sys.exit(int(bool(failed)))


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
        choices=list(OLVersion),
        type=lambda s: OLVersion(int(s)),
        default=None,
        help="Run the tests within the Oracle Linux (already built) rootfs",
    )
    parser.add_argument(
        "--all-ol-versions",
        action="store_true",
        help="Run the tests in all OL rootfs versions (overrides --ol)",
    )
    parser.add_argument(
        "--python",
        default=PythonVer.SYSTEM,
        type=PythonVer,
        help="Run the tests with the given python binary name",
    )
    parser.add_argument(
        "--all-python-versions",
        action="store_true",
        help="Run the tests against all python versions available in the rootfs",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Just print the tests we would run and exit",
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
    dbinfo = []
    if args.ctf:
        dbinfo.append(Debuginfo.CTF)
    if args.dwarf:
        dbinfo.append(Debuginfo.DWARF)

    ol_vers = []
    if args.all_ol_versions:
        ol_vers = [v for v in OLVersion if v.value > 7]
        # For most people, --all-ol-versions means 8-10. But if you have an OL7
        # rootfs then good for you, I guess.
        if have_ol7_rootfs(layout):
            ol_vers.append(OLVersion.OL7)
    elif args.ol:
        ol_vers = [args.ol]

    py_vers = []
    if args.all_python_versions:
        py_vers = list(PythonVer)
    else:
        py_vers = [args.python]

    params_list = get_all_tests(
        layout, args.vmcore, dbinfo, py_vers, ol_vers, args.args
    )
    if args.no_test:
        print_params(params_list, "Would run")
    else:
        test(layout, params_list, parallel=args.parallel)


if __name__ == "__main__":
    main()
