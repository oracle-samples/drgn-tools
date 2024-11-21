# Copyright (c) 2024, Oracle and/or its affiliates.
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
from tempfile import NamedTemporaryFile
from typing import List
from typing import Tuple

from drgn_tools.debuginfo import CtfCompatibility
from drgn_tools.debuginfo import KernelVersion
from testing.util import combine_junit_xml
from testing.vmcore.manage import CORE_DIR


def _test_job(
    core_name: str, cmd: List[str], xml: str
) -> Tuple[str, bool, ET.ElementTree]:
    # Runs the test silently, but prints the stdout/stderr on failure.
    with NamedTemporaryFile("w+t") as f:
        print(f"Begin testing {core_name}")
        start = time.time()
        res = subprocess.run(cmd, stdout=f, stderr=f)
        if res.returncode != 0:
            print(f"=== FAILURE: {core_name} ===")
            f.seek(0)
            sys.stdout.write(f.read())
        runtime = time.time() - start
        print(f"Completed testing {core_name} in {runtime:.1f}")
        run_data = ET.parse(xml)
    return (core_name, res.returncode == 0, run_data)


def _skip_ctf(ctf: bool, uname: str) -> bool:
    if ctf:
        host_ol = 9  # OL8 or 9 work here, tests aren't supported for OL7
        kver = KernelVersion.parse(uname)
        compat = CtfCompatibility.get(kver, host_ol)
        # Skip test when CTF is fully unsupported, or when it would require a
        # /proc/kallsyms.
        return compat in (
            CtfCompatibility.NO,
            CtfCompatibility.LIMITED_PROC,
        )
    return False  # don't skip when non-CTF


def test(
    vmcore_list: List[str],
    ctf: bool = False,
    parallel: int = 1,
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

    with ExitStack() as es:
        pool = es.enter_context(ThreadPoolExecutor(max_workers=parallel))
        futures = []
        for path in CORE_DIR.iterdir():
            core_name = path.name
            if not should_run_vmcore(core_name):
                continue
            uname = (path / "UTS_RELEASE").read_text().strip()
            if _skip_ctf(ctf, uname):
                skipped.append(core_name)
                continue
            xml_run = es.enter_context(
                NamedTemporaryFile("w", suffix=".xml", delete=False)
            )
            xml_run.close()  # not deleted until context is ended
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                f"--vmcore={core_name}",
                f"--vmcore-dir={str(CORE_DIR)}",
                f"--junitxml={xml_run.name}",
                "-o",
                "junit_logging=all",
            ]
            if ctf:
                if not (path / "vmlinux.ctfa").is_file():
                    skipped.append(core_name)
                    continue
                cmd.append("--ctf")
            futures.append(
                pool.submit(_test_job, core_name, cmd, xml_run.name)
            )

        for future in futures:
            core_name, test_passed, run_data = future.result()
            xml = combine_junit_xml(xml, run_data)
            if test_passed:
                passed.append(core_name)
            else:
                failed.append(core_name)

    if xml is not None:
        xml.write("vmcore.xml")
    print("Complete test logs: vmcore.xml")
    print("Vmcore Test Summary -- Passed:")
    print("\n".join(f"- {n}" for n in passed))
    if skipped:
        print("Vmcore Test Summary -- Skipped (missing CTF):")
        print("\n".join(f"- {n}" for n in skipped))
    if failed:
        print("Vmcore Test Summary -- FAILED:")
        print("\n".join(f"- {n}" for n in failed))
        sys.exit(1)


def main():
    global CORE_DIR
    parser = argparse.ArgumentParser(
        description="manages drgn-tools vmcores",
    )
    parser.add_argument(
        "--core-directory", type=Path, help="where to store vmcores"
    )
    parser.add_argument(
        "--vmcore",
        action="append",
        default=[],
        help="only run tests on the given vmcore(s). you can use this "
        "multiple times to specify multiple vmcore names. You can also "
        "use fnmmatch patterns to specify several cores at once.",
    )
    parser.add_argument(
        "--ctf",
        action="store_true",
        help="Use CTF debuginfo for tests rather than DWARF (skips vmcores "
        "without a vmlinux.ctfa file)",
    )
    parser.add_argument(
        "--parallel",
        "-j",
        type=int,
        default=1,
        help="Run the tests in parallel with the given number of threads",
    )
    args = parser.parse_args()
    if args.core_directory:
        CORE_DIR = args.core_directory.absolute()
    test(
        args.vmcore,
        ctf=args.ctf,
        parallel=args.parallel,
    )


if __name__ == "__main__":
    main()
