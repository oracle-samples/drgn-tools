# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Simple test runner for built RPMs

Once the drgn and drgn-tools RPMs are built, these automatic tests can be run.
Be sure to first install "pytest<7.1 pytest-cov" to the system or user.
"""
import argparse
import fnmatch
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import List


CORE_DIR = Path.cwd() / "testdata/vmcores"


def vmcore_test(vmcore: str, ctf: bool = False, coverage: bool = False) -> str:
    ctf_path = CORE_DIR / vmcore / "vmlinux.ctfa"
    if ctf and not ctf_path.exists():
        return "skip (CTF not available)"

    return do_test(
        vmcore,
        [
            "--vmcore",
            vmcore,
            f"--vmcore-dir={str(CORE_DIR)}",
        ],
        ctf=ctf,
        coverage=coverage,
    )


def do_test(
    ident: str, args: List[str], ctf: bool = False, coverage: bool = False
) -> str:
    kind = "CTF" if ctf else "DWARF"
    print("=" * 30 + f" TESTING {ident} W/ {kind} " + "=" * 30)

    cmd = [
        "python3",
        "-m",
        "pytest",
    ]
    if coverage:
        cmd += [
            "--cov=drgn_tools",
            "--cov-append",
        ]
    if ctf:
        cmd.append("--ctf")

    cmd += args
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        return "fail"
    else:
        return "pass"


def live_test(ctf: bool = False, coverage: bool = False) -> str:
    release = os.uname().release
    kind = "CTF" if ctf else "DWARF"
    if ctf:
        path = f"/lib/modules/{release}/kernel/vmlinux.ctfa"
    else:
        path = f"/usr/lib/debug/lib/modules/{release}/vmlinux"
    if not os.path.exists(path):
        return f"skip ({kind} not available)"
    return do_test("LIVE", [], ctf=ctf, coverage=coverage)


def main() -> None:
    global CORE_DIR

    parser = argparse.ArgumentParser(description="simple test runner")
    parser.add_argument(
        "--no-ctf",
        dest="ctf",
        action="store_false",
        help="do not run CTF tests",
    )
    parser.add_argument(
        "--no-dwarf",
        dest="dwarf",
        action="store_false",
        help="do not run DWARF tests",
    )
    parser.add_argument(
        "--no-live",
        dest="live",
        action="store_false",
        help="do not run live kernel test",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="run code coverage (requires pytest-cov)",
    )
    parser.add_argument(
        "--xml",
        action="store_true",
        help="collect output in XML (requires junitparser)",
    )
    parser.add_argument(
        "--core-dir",
        type=Path,
        default=CORE_DIR,
        help="core directory (default: ./testdata/vmcores)",
    )
    parser.add_argument(
        "cores",
        nargs="*",
        help="vmcore(s) to run - fnmatch pattern accepted",
    )
    args = parser.parse_args()
    CORE_DIR = args.core_dir
    cores = [
        p.name
        for p in CORE_DIR.iterdir()
        if p.is_dir() and (p / "vmcore").is_file()
    ]

    def should_run_vmcore(name: str) -> bool:
        if not args.cores:
            return True
        for pat in args.cores:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    cores = list(filter(should_run_vmcore, cores))

    print(cores)

    if args.coverage:
        cov = Path.cwd() / ".coverage"
        if cov.is_file():
            cov.unlink()

    fail = False
    results = defaultdict(list)
    for core in cores:
        if args.dwarf:
            res = vmcore_test(core, coverage=args.coverage)
            results[res].append(f"{core} (DWARF)")
            if "fail" in res or "error" in res:
                fail = True

        if args.ctf:
            res = vmcore_test(core, ctf=True, coverage=args.coverage)
            results[res].append(f"{core} (CTF)")
            if "fail" in res or "error" in res:
                fail = True

    if args.live:
        res = live_test(coverage=args.coverage)
        results[res].append("live (DWARF)")
        if "fail" in res or "error" in res:
            fail = True

        res = live_test(ctf=True, coverage=args.coverage)
        results[res].append("live (CTF)")
        if "fail" in res or "error" in res:
            fail = True

    for status, vmcores in results.items():
        print(f"==> {status}")
        for vmcore in vmcores:
            print(f"    {vmcore}")

    if fail:
        print("FAILED")
        sys.exit(1)
    else:
        print("PASSED! Congratulations :)")


if __name__ == "__main__":
    main()
