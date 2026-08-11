# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""VM test runner."""
import argparse
import fnmatch
import shutil
import sys
from pathlib import Path
from typing import List

from testing.config import Debuginfo
from testing.config import KernelCategory
from testing.config import KernelKind
from testing.config import PythonVer
from testing.config import REPO_ROOT
from testing.config import TARGETS
from testing.config import TestDirectories
from testing.rootfs import ensure_rootfs
from testing.util import ci_section
from testing.vm.artifacts import ensure_kernel
from testing.vm.boot import run_in_vm
from testing.vm.kmod import ensure_kmod
from testing.vm.logging import default_verbose
from testing.vm.logging import VmLogger


def _select_targets(pattern: str = "*") -> List[KernelCategory]:
    return [t for t in TARGETS if fnmatch.fnmatch(t.name, pattern)]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="testing.vm runner")
    parser.add_argument(
        "--kernel",
        "-k",
        default="*",
        help="Match against target slug (example: ol9-uek8-*)",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help="Base directory for cached and generated test artifacts",
    )
    parser.add_argument(
        "--skip-rootfs-build",
        action="store_true",
        help="Do not build rootfs (requires it to already exist)",
    )
    parser.add_argument(
        "--skip-rpm-fetch",
        action="store_true",
        help=(
            "Do not download repodata or RPMs "
            "(requires cached metadata/RPMs)"
        ),
    )
    parser.add_argument(
        "--skip-kmod-build",
        action="store_true",
        help="Do not build kernel module (requires existing .ko output)",
    )
    parser.add_argument(
        "--skip-all",
        "-n",
        action="store_true",
        help=(
            "Activate all --skip-* options "
            "(requires everything already built)"
        ),
    )
    parser.add_argument(
        "--no-ctf",
        dest="ctf",
        action="store_false",
        help="Skip CTF mode",
    )
    parser.add_argument(
        "--no-dwarf",
        dest="dwarf",
        action="store_false",
        help="Skip DWARF mode",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Connect stdout/stdin of the VM to the terminal",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=default_verbose(),
        help="Print output from builds & increase kernel log level",
    )
    parser.add_argument(
        "--delete-after-test",
        action="store_true",
        help="Delete downloaded & extracted RPMs after tests for target",
    )
    parser.add_argument(
        "--python",
        type=PythonVer,
        default=PythonVer.SYSTEM,
        help="Python version for running tests (default: system python)",
    )
    parser.add_argument(
        "test_args",
        nargs="*",
        help="Arguments to test through to unittest_runner",
    )

    args = parser.parse_args()
    if not args.dwarf and not args.ctf:
        raise SystemExit(
            "Both --no-dwarf and --no-ctf were set, nothing to run"
        )
    if args.skip_all:
        args.skip_rootfs_build = True
        args.skip_rpm_fetch = True
        args.skip_kmod_build = True
    return args


def main() -> None:
    args = _parse_args()
    layout = TestDirectories.create(args.base_dir)
    log = VmLogger(args.verbose, args.interactive)

    base_command = [
        args.python.value,
        "-m",
        "testing.unittest_runner",
        *args.test_args,
    ]
    targets = _select_targets(args.kernel)
    if not targets:
        raise SystemExit(f"No targets matched --kernel {args.kernel!r}")

    modes = []
    if args.dwarf:
        modes.append(Debuginfo.DWARF)
    if args.ctf:
        modes.append(Debuginfo.CTF)

    failures: List[str] = []

    for target in targets:
        try:
            with ci_section(
                f"{target.name}_setup",
                f"Set up rootfs, kernel RPMs, and kmod for {target.name}",
            ):
                log.begin_target(target.name)
                ensure_rootfs(
                    target.rootfs,
                    layout,
                    log,
                    skip_build=args.skip_rootfs_build,
                )
                kernel = ensure_kernel(
                    target,
                    layout,
                    log,
                    skip_fetch=args.skip_rpm_fetch,
                )
                ensure_kmod(
                    kernel,
                    REPO_ROOT,
                    layout,
                    log,
                    skip_build=args.skip_kmod_build,
                )

            for mode in modes:
                with ci_section(
                    f"{target.name}_{mode.value}",
                    f"Run {mode.value.upper()} tests for {target.name}",
                ):
                    ctf = mode == Debuginfo.CTF
                    if kernel.category.kind == KernelKind.RHCK and ctf:
                        log.skip_test(
                            target.name, mode.value, "CTF unsupported"
                        )
                        continue
                    log.begin_test(target.name, mode.value, target.shared_fs)
                    log_path = layout.vm_log_path(kernel.category, mode.value)
                    log_path.parent.mkdir(exist_ok=True, parents=True)
                    if ctf:
                        command = base_command + ["--ctf"]
                    else:
                        command = base_command[:]
                    try:
                        run_in_vm(
                            kernel,
                            layout,
                            REPO_ROOT,
                            command,
                            None if args.interactive else log_path,
                            log,
                        )
                    except RuntimeError as e:
                        failures.append(f"{target.name} {mode.value}: {e}")
                        log.fail_test(target.name, mode.value)
                    else:
                        log.pass_test(target.name, mode.value)

            if args.delete_after_test:
                log.message("Deleting RPM cache and extraction directory")
                shutil.rmtree(layout.target_path(target))
        except BaseException as e:
            failures.append(f"{target.name}: {e}")
            if isinstance(e, (SystemExit, KeyboardInterrupt)):
                print("\ninterrupted")
                break

    if failures:
        print("VM test failures:")
        for failure in failures:
            print(f"- {failure}")
        sys.exit(1)


if __name__ == "__main__":
    main()
