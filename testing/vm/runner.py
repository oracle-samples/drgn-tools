# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""New VM test runner orchestration."""
import argparse
import fnmatch
import sys
from pathlib import Path
from typing import List

from testing.util import BASE_DIR
from testing.util import ci_section
from testing.vm.artifacts import ensure_kernel
from testing.vm.artifacts import resolve_kernel
from testing.vm.boot import run_in_vm
from testing.vm.config import KernelCategory
from testing.vm.config import SHARED_FS_AUTO
from testing.vm.config import SHARED_FS_CHOICES
from testing.vm.config import TARGETS
from testing.vm.config import VmLayout
from testing.vm.kmod import ensure_kmod
from testing.vm.logging import default_verbose
from testing.vm.logging import VmLogger
from testing.vm.rootfs import ensure_rootfs


def _select_targets(pattern: str = "*") -> List[KernelCategory]:
    return [t for t in TARGETS if fnmatch.fnmatch(t.name, pattern)]


def _default_command() -> List[str]:
    return ["python3", "-m", "pytest", "tests"]


def _is_pytest_command(command: List[str]) -> bool:
    if not command:
        return False
    if "pytest" in command:
        return True
    for i, arg in enumerate(command[:-1]):
        if arg == "-m" and command[i + 1] == "pytest":
            return True
    return False


def _command_for_mode(
    base_command: List[str],
    ctf: bool,
) -> List[str]:
    command = list(base_command)
    is_pytest = _is_pytest_command(command)

    if not is_pytest:
        return command

    if ctf and "--ctf" not in command:
        command.append("--ctf")

    return command


def _shared_fs_for_target(target: KernelCategory, shared_fs: str) -> str:
    if shared_fs == SHARED_FS_AUTO:
        return target.shared_fs
    return shared_fs


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
        default=BASE_DIR,
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
        "--shared-fs",
        choices=SHARED_FS_CHOICES,
        default=SHARED_FS_AUTO,
        help=(
            "Host/guest shared filesystem. auto uses 9p for UEK6 and "
            "virtiofs for newer UEKs"
        ),
    )
    parser.add_argument(
        "command",
        nargs="*",
        help="Command to run in guest (default: python3 -m pytest tests)",
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
    layout = VmLayout(args.base_dir)
    log = VmLogger(args.verbose, args.interactive)

    base_command = args.command if args.command else _default_command()
    is_pytest = _is_pytest_command(base_command)
    targets = _select_targets(args.kernel)
    if not targets:
        raise SystemExit(f"No targets matched --kernel {args.kernel!r}")

    repo_root = Path.cwd().absolute()
    modes = []
    if not is_pytest:
        args.interactive = True
        modes.append(("interactive", False))
    else:
        if args.dwarf:
            modes.append(("dwarf", False))
        if args.ctf:
            modes.append(("ctf", True))

    failures: List[str] = []

    for target in targets:
        try:
            shared_fs = _shared_fs_for_target(target, args.shared_fs)
            with ci_section(
                f"{target.name}_setup",
                f"Set up rootfs, kernel RPMs, and kmod for {target.name}",
            ):
                log.begin_target(target.name)
                rootfs = ensure_rootfs(
                    target,
                    layout,
                    log,
                    skip_build=args.skip_rootfs_build,
                )
                kernel = resolve_kernel(
                    target,
                    layout,
                    log,
                    skip_fetch=args.skip_rpm_fetch,
                )
                ensure_kernel(
                    kernel,
                    layout,
                    log,
                    skip_fetch=args.skip_rpm_fetch,
                )
                kmod_path = ensure_kmod(
                    rootfs,
                    kernel,
                    repo_root,
                    layout,
                    log,
                    skip_build=args.skip_kmod_build,
                )

            for mode_name, ctf in modes:
                with ci_section(
                    f"{target.name}_{mode_name}",
                    f"Run {mode_name.upper()} tests for {target.name}",
                ):
                    log.begin_test(target.name, mode_name, shared_fs)
                    log_path = layout.log_path(target.name, mode_name)
                    run_command = _command_for_mode(
                        base_command,
                        ctf,
                    )
                    try:
                        run_in_vm(
                            kernel,
                            rootfs,
                            layout,
                            repo_root,
                            run_command,
                            None if args.interactive else log_path,
                            log,
                            kmod_path=kmod_path,
                            shared_fs=shared_fs,
                        )
                    except RuntimeError as e:
                        failures.append(f"{target.name} {mode_name}: {e}")
                        log.fail_test(target.name, mode_name)
                    else:
                        log.pass_test(target.name, mode_name)
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
